
import os
import random
import sqlite3
from datetime import date, datetime, timedelta
from functools import wraps
from urllib.parse import quote_plus

from flask import Flask, flash, g, redirect, render_template, request, session, url_for
from werkzeug.security import check_password_hash, generate_password_hash
from werkzeug.utils import secure_filename

try:
    from twilio.rest import Client
except ImportError:
    Client = None

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(BASE_DIR, 'app.db')
DAILY_VIDEO_LIMIT = 10
VIDEO_REWARD = 1.50
MIN_WITHDRAWAL = 20
REFERRAL_BONUS_PER_SIGNUP = 1.0
WITHDRAWAL_STATUSES = ('pending', 'approved', 'rejected')
PROFILE_PHOTO_DIR = os.path.join(BASE_DIR, 'static', 'profile_photos')
ALLOWED_PHOTO_EXTENSIONS = {'png', 'jpg', 'jpeg', 'webp', 'gif'}
VIDEO_UPLOAD_DIR = os.path.join(BASE_DIR, 'static', 'uploaded_videos')
ALLOWED_VIDEO_EXTENSIONS = {'mp4', 'webm', 'ogg'}
MAX_VIDEO_UPLOAD_MB = int(os.getenv('MAX_VIDEO_UPLOAD_MB', '200'))
MAX_VIDEO_UPLOAD_BYTES = MAX_VIDEO_UPLOAD_MB * 1024 * 1024
ADMIN_DEFAULT_USERNAME = os.getenv('ADMIN_USERNAME', 'admin')
ADMIN_DEFAULT_PASSWORD = os.getenv('ADMIN_PASSWORD', 'admin12345')
ADMIN_DEFAULT_PHONE = os.getenv('ADMIN_PHONE', '+992000000000')
ROLE_USER = 'user'
ROLE_SUBADMIN = 'subadmin'
ROLE_ADMIN = 'admin'
USER_ROLES = (ROLE_ADMIN, ROLE_SUBADMIN, ROLE_USER)
TAJIK_BANKS = [
    'ГСБ РТ "Амонатбонк"',
    'ОАО "Ориёнбанк"',
    'ЗАО "Банк Эсхата"',
    'ЗАО "Спитамен Банк"',
    'ЗАО "Душанбе Сити Банк"',
    'ЗАО "Алиф Банк"',
    'ОАО "Тавхидбанк"',
    'Другой банк Таджикистана',
]

DEFAULT_VIDEOS = [
    ('Рекламное видео 1', 'https://samplelib.com/lib/preview/mp4/sample-5s.mp4'),
    ('Рекламное видео 2', 'https://samplelib.com/lib/preview/mp4/sample-5mb.mp4'),
    ('Рекламное видео 3', 'https://samplelib.com/lib/preview/mp4/sample-10s.mp4'),
    ('Рекламное видео 4', 'https://samplelib.com/lib/preview/mp4/sample-15s.mp4'),
    ('Рекламное видео 5', 'https://samplelib.com/lib/preview/mp4/sample-20s.mp4'),
    ('Рекламное видео 6', 'https://samplelib.com/lib/preview/mp4/sample-30s.mp4'),
    ('Рекламное видео 7', 'https://samplelib.com/lib/preview/mp4/sample-5s.mp4'),
    ('Рекламное видео 8', 'https://samplelib.com/lib/preview/mp4/sample-10s.mp4'),
    ('Рекламное видео 9', 'https://samplelib.com/lib/preview/mp4/sample-15s.mp4'),
    ('Рекламное видео 10', 'https://samplelib.com/lib/preview/mp4/sample-20s.mp4'),
]

app = Flask(__name__)
app.secret_key = os.getenv('FLASK_SECRET_KEY', 'change-me-in-production')


def get_db() -> sqlite3.Connection:
    if 'db' not in g:
        g.db = sqlite3.connect(DB_PATH)
        g.db.row_factory = sqlite3.Row
    return g.db


@app.teardown_appcontext
def close_db(_error: Exception | None) -> None:
    db = g.pop('db', None)
    if db is not None:
        db.close()


def ensure_users_referral_columns(db: sqlite3.Connection) -> None:
    columns = {row['name'] for row in db.execute('PRAGMA table_info(users)').fetchall()}
    if 'referred_by' not in columns:
        db.execute('ALTER TABLE users ADD COLUMN referred_by INTEGER')
    if 'referral_code' not in columns:
        db.execute('ALTER TABLE users ADD COLUMN referral_code TEXT')
    if 'referral_bonus' not in columns:
        db.execute('ALTER TABLE users ADD COLUMN referral_bonus REAL NOT NULL DEFAULT 0')
    if 'profile_photo_url' not in columns:
        db.execute('ALTER TABLE users ADD COLUMN profile_photo_url TEXT')
    if 'is_admin' not in columns:
        db.execute('ALTER TABLE users ADD COLUMN is_admin INTEGER NOT NULL DEFAULT 0')
    if 'role' not in columns:
        db.execute(f"ALTER TABLE users ADD COLUMN role TEXT NOT NULL DEFAULT '{ROLE_USER}'")

    db.execute('UPDATE users SET referral_bonus = 0 WHERE referral_bonus IS NULL')
    db.execute("UPDATE users SET profile_photo_url = '' WHERE profile_photo_url IS NULL")
    db.execute('UPDATE users SET is_admin = 0 WHERE is_admin IS NULL')
    db.execute(f"UPDATE users SET role = '{ROLE_ADMIN}' WHERE is_admin = 1 AND (role IS NULL OR TRIM(role) = '')")
    db.execute(f"UPDATE users SET role = '{ROLE_USER}' WHERE role IS NULL OR TRIM(role) = ''")
    db.execute(
        f"UPDATE users SET role = '{ROLE_USER}' WHERE role NOT IN ({','.join(['?'] * len(USER_ROLES))})",
        USER_ROLES,
    )
    db.execute(f"UPDATE users SET is_admin = 1 WHERE role = '{ROLE_ADMIN}'")
    db.execute(f"UPDATE users SET is_admin = 0 WHERE role <> '{ROLE_ADMIN}'")
    db.execute('CREATE UNIQUE INDEX IF NOT EXISTS idx_users_referral_code ON users(referral_code)')


def ensure_videos_columns(db: sqlite3.Connection) -> None:
    columns = {row['name'] for row in db.execute('PRAGMA table_info(videos)').fetchall()}
    if 'advertiser_name' not in columns:
        db.execute("ALTER TABLE videos ADD COLUMN advertiser_name TEXT NOT NULL DEFAULT ''")
    if 'available_on' not in columns:
        db.execute('ALTER TABLE videos ADD COLUMN available_on TEXT')
    if 'created_at' not in columns:
        db.execute('ALTER TABLE videos ADD COLUMN created_at TEXT')
    if 'created_by' not in columns:
        db.execute('ALTER TABLE videos ADD COLUMN created_by INTEGER')

    today = date.today().isoformat()
    now_iso = datetime.utcnow().isoformat()
    db.execute("UPDATE videos SET advertiser_name = 'Не указан' WHERE advertiser_name IS NULL OR TRIM(advertiser_name) = ''")
    db.execute('UPDATE videos SET available_on = ? WHERE available_on IS NULL OR TRIM(available_on) = ""', (today,))
    db.execute('UPDATE videos SET created_at = ? WHERE created_at IS NULL OR TRIM(created_at) = ""', (now_iso,))


def cleanup_expired_videos(db: sqlite3.Connection) -> int:
    today = date.today().isoformat()
    expired_rows = db.execute(
        'SELECT id, video_url FROM videos WHERE available_on < ?',
        (today,),
    ).fetchall()
    if not expired_rows:
        return 0

    expired_ids = [row['id'] for row in expired_rows]
    for row in expired_rows:
        remove_uploaded_video_file(row['video_url'])

    placeholders = ','.join(['?'] * len(expired_ids))
    db.execute(f'DELETE FROM user_video_views WHERE video_id IN ({placeholders})', expired_ids)
    deleted = db.execute(f'DELETE FROM videos WHERE id IN ({placeholders})', expired_ids).rowcount
    return int(deleted or 0)


def seed_default_videos_for_day(db: sqlite3.Connection, target_day: str) -> None:
    rows = []
    for idx, (title, url) in enumerate(DEFAULT_VIDEOS[:DAILY_VIDEO_LIMIT], start=1):
        rows.append(
            (
                title,
                url,
                f'Рекламодатель {idx}',
                target_day,
                datetime.utcnow().isoformat(),
                None,
            )
        )
    db.executemany(
        '''
        INSERT INTO videos (title, video_url, advertiser_name, available_on, created_at, created_by)
        VALUES (?, ?, ?, ?, ?, ?)
        ''',
        rows,
    )


def generate_referral_code(db: sqlite3.Connection) -> str:
    alphabet = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789'
    while True:
        code = ''.join(random.choice(alphabet) for _ in range(8))
        exists = db.execute('SELECT 1 FROM users WHERE referral_code = ?', (code,)).fetchone()
        if not exists:
            return code


def ensure_users_have_referral_codes(db: sqlite3.Connection) -> None:
    users_without_code = db.execute(
        "SELECT id FROM users WHERE referral_code IS NULL OR TRIM(referral_code) = ''"
    ).fetchall()
    for row in users_without_code:
        db.execute('UPDATE users SET referral_code = ? WHERE id = ?', (generate_referral_code(db), row['id']))


def ensure_admin_account(db: sqlite3.Connection) -> None:
    existing_admin = db.execute(
        'SELECT id FROM users WHERE role = ? OR is_admin = 1 LIMIT 1',
        (ROLE_ADMIN,),
    ).fetchone()
    if existing_admin:
        return

    username = (ADMIN_DEFAULT_USERNAME or 'admin').strip() or 'admin'
    password = (ADMIN_DEFAULT_PASSWORD or 'admin12345').strip() or 'admin12345'
    phone = (ADMIN_DEFAULT_PHONE or '+992000000000').strip() or '+992000000000'

    existing_user = db.execute('SELECT id FROM users WHERE username = ?', (username,)).fetchone()
    if existing_user:
        db.execute(
            'UPDATE users SET is_admin = 1, role = ?, is_verified = 1 WHERE id = ?',
            (ROLE_ADMIN, existing_user['id']),
        )
        return

    phone_candidate = phone
    suffix = 1
    while db.execute('SELECT 1 FROM users WHERE phone = ?', (phone_candidate,)).fetchone():
        phone_candidate = f'{phone}{suffix}'
        suffix += 1

    db.execute(
        '''
        INSERT INTO users (
            username, phone, password_hash, balance, is_verified, created_at,
            referred_by, referral_code, referral_bonus, profile_photo_url, is_admin, role
        )
        VALUES (?, ?, ?, 0, 1, ?, NULL, ?, 0, '', 1, ?)
        ''',
        (
            username,
            phone_candidate,
            generate_password_hash(password),
            datetime.utcnow().isoformat(),
            generate_referral_code(db),
            ROLE_ADMIN,
        ),
    )


def init_db() -> None:
    db = sqlite3.connect(DB_PATH)
    db.row_factory = sqlite3.Row
    db.executescript(
        '''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            phone TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            balance REAL NOT NULL DEFAULT 0,
            is_verified INTEGER NOT NULL DEFAULT 0,
            sms_code TEXT,
            sms_code_expires_at TEXT,
            created_at TEXT NOT NULL,
            referred_by INTEGER,
            referral_code TEXT UNIQUE,
            referral_bonus REAL NOT NULL DEFAULT 0,
            profile_photo_url TEXT,
            is_admin INTEGER NOT NULL DEFAULT 0,
            role TEXT NOT NULL DEFAULT 'user',
            FOREIGN KEY(referred_by) REFERENCES users(id)
        );

        CREATE TABLE IF NOT EXISTS videos (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            title TEXT NOT NULL,
            video_url TEXT NOT NULL,
            advertiser_name TEXT NOT NULL DEFAULT '',
            available_on TEXT NOT NULL,
            created_at TEXT NOT NULL,
            created_by INTEGER,
            FOREIGN KEY(created_by) REFERENCES users(id)
        );

        CREATE TABLE IF NOT EXISTS user_video_views (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            video_id INTEGER NOT NULL,
            viewed_on TEXT NOT NULL,
            created_at TEXT NOT NULL,
            UNIQUE(user_id, video_id, viewed_on),
            FOREIGN KEY(user_id) REFERENCES users(id),
            FOREIGN KEY(video_id) REFERENCES videos(id)
        );

        CREATE TABLE IF NOT EXISTS withdrawal_requests (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            amount REAL NOT NULL,
            payout_details TEXT NOT NULL,
            status TEXT NOT NULL DEFAULT 'pending',
            created_at TEXT NOT NULL,
            FOREIGN KEY(user_id) REFERENCES users(id)
        );
        '''
    )
    ensure_users_referral_columns(db)
    ensure_videos_columns(db)
    ensure_admin_account(db)
    ensure_users_have_referral_codes(db)

    cleanup_expired_videos(db)
    video_count = db.execute('SELECT COUNT(*) AS c FROM videos').fetchone()['c']
    if video_count == 0:
        seed_default_videos_for_day(db, date.today().isoformat())

    db.commit()
    db.close()


def login_required(view_func):
    @wraps(view_func)
    def wrapped(*args, **kwargs):
        if 'user_id' not in session:
            return redirect(url_for('login'))
        return view_func(*args, **kwargs)

    return wrapped


def send_sms_code(phone: str, code: str) -> bool:
    account_sid = os.getenv('TWILIO_ACCOUNT_SID')
    auth_token = os.getenv('TWILIO_AUTH_TOKEN')
    from_phone = os.getenv('TWILIO_PHONE_NUMBER')

    if account_sid and auth_token and from_phone and Client:
        client = Client(account_sid, auth_token)
        client.messages.create(
            body=f'Ваш код подтверждения: {code}',
            from_=from_phone,
            to=phone,
        )
        return True

    print(f'[ТЕСТ SMS] {phone}: {code}')
    return False


def get_current_user() -> sqlite3.Row | None:
    user_id = session.get('user_id')
    if not user_id:
        return None
    return get_db().execute('SELECT * FROM users WHERE id = ?', (user_id,)).fetchone()


def get_current_admin() -> sqlite3.Row | None:
    admin_user_id = session.get('admin_user_id')
    if not admin_user_id:
        return None
    return get_db().execute(
        'SELECT * FROM users WHERE id = ? AND role IN (?, ?)',
        (admin_user_id, ROLE_ADMIN, ROLE_SUBADMIN),
    ).fetchone()


def admin_required(view_func):
    @wraps(view_func)
    def wrapped(*args, **kwargs):
        if not get_current_admin():
            return redirect(url_for('login'))
        return view_func(*args, **kwargs)

    return wrapped


def get_user_reward(user: sqlite3.Row) -> float:
    bonus = float(user['referral_bonus'] or 0)
    return round(VIDEO_REWARD + bonus, 2)


def get_profile_level(total_views: int) -> str:
    if total_views >= 200:
        return 'Легенда'
    if total_views >= 100:
        return 'Мастер'
    if total_views >= 40:
        return 'Опытный'
    if total_views >= 10:
        return 'Активный'
    return 'Новичок'


def is_allowed_photo(filename: str) -> bool:
    if '.' not in filename:
        return False
    extension = filename.rsplit('.', 1)[1].lower()
    return extension in ALLOWED_PHOTO_EXTENSIONS


def is_allowed_video(filename: str) -> bool:
    if '.' not in filename:
        return False
    extension = filename.rsplit('.', 1)[1].lower()
    return extension in ALLOWED_VIDEO_EXTENSIONS


def get_uploaded_video_path(video_url: str) -> str | None:
    normalized_url = (video_url or '').strip().replace('\\', '/')
    for prefix in ('/static/uploaded_videos/', 'static/uploaded_videos/'):
        if normalized_url.startswith(prefix):
            filename = os.path.basename(normalized_url[len(prefix):])
            if filename:
                return os.path.join(VIDEO_UPLOAD_DIR, filename)
    return None


def remove_uploaded_video_file(video_url: str) -> None:
    file_path = get_uploaded_video_path(video_url)
    if file_path and os.path.isfile(file_path):
        try:
            os.remove(file_path)
        except OSError:
            pass


def get_avatar_url(user: sqlite3.Row) -> str:
    profile_photo_url = (user['profile_photo_url'] or '').strip()
    if profile_photo_url:
        return profile_photo_url
    username = quote_plus(str(user['username']))
    return f'https://ui-avatars.com/api/?name={username}&background=FFD447&color=1F1F1F&size=160'


def ensure_user_referral_code(db: sqlite3.Connection, user: sqlite3.Row) -> sqlite3.Row:
    if user['referral_code'] and str(user['referral_code']).strip():
        return user
    db.execute('UPDATE users SET referral_code = ? WHERE id = ?', (generate_referral_code(db), user['id']))
    db.commit()
    refreshed = db.execute('SELECT * FROM users WHERE id = ?', (user['id'],)).fetchone()
    assert refreshed is not None
    return refreshed


def build_referral_link(referral_code: str) -> str:
    referral_path = url_for('register', ref=referral_code)
    public_base_url = os.getenv('PUBLIC_BASE_URL', '').strip().rstrip('/')
    if public_base_url:
        return f'{public_base_url}{referral_path}'
    return url_for('register', ref=referral_code, _external=True)


@app.context_processor
def inject_header_user():
    return {
        'header_user': get_current_user(),
        'admin_user': get_current_admin(),
    }


@app.before_request
def apply_daily_video_cleanup() -> None:
    if request.endpoint == 'static':
        return
    db = get_db()
    try:
        deleted = cleanup_expired_videos(db)
        if deleted:
            db.commit()
    except sqlite3.OperationalError:
        # Happens before initial DB setup.
        return


def videos_watched_today(user_id: int) -> int:
    today = date.today().isoformat()
    row = get_db().execute(
        'SELECT COUNT(*) AS c FROM user_video_views WHERE user_id = ? AND viewed_on = ?',
        (user_id, today),
    ).fetchone()
    return row['c']


def parse_amount(value: str) -> float | None:
    try:
        return round(float(value.replace(',', '.')), 2)
    except (TypeError, ValueError):
        return None


def parse_day_value(day_value: str) -> str | None:
    value = (day_value or '').strip()
    try:
        return date.fromisoformat(value).isoformat()
    except ValueError:
        return None


@app.route('/')
def index():
    if 'user_id' in session:
        return redirect(url_for('dashboard'))
    return redirect(url_for('login'))


@app.route('/register', methods=['GET', 'POST'])
def register():
    referral_code = request.args.get('ref', '').strip().upper()

    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        phone = request.form.get('phone', '').strip()
        password = request.form.get('password', '')
        referral_code = request.form.get('referral_code', '').strip().upper()

        if not username or not phone or not password:
            flash('Заполните все поля.')
            return render_template('register.html', referral_code=referral_code)

        code = f'{random.randint(100000, 999999)}'
        expires = (datetime.utcnow() + timedelta(minutes=10)).isoformat()

        db = get_db()
        referred_by = None
        if referral_code:
            inviter = db.execute(
                'SELECT id FROM users WHERE referral_code = ?',
                (referral_code,),
            ).fetchone()
            if inviter:
                referred_by = inviter['id']
            else:
                flash('Реферальная ссылка недействительна.')
                return render_template('register.html', referral_code='')

        try:
            new_referral_code = generate_referral_code(db)
            db.execute(
                '''
                INSERT INTO users (
                    username, phone, password_hash, sms_code, sms_code_expires_at, created_at,
                    referred_by, referral_code
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                ''',
                (
                    username,
                    phone,
                    generate_password_hash(password),
                    code,
                    expires,
                    datetime.utcnow().isoformat(),
                    referred_by,
                    new_referral_code,
                ),
            )
            if referred_by:
                db.execute(
                    'UPDATE users SET referral_bonus = referral_bonus + ? WHERE id = ?',
                    (REFERRAL_BONUS_PER_SIGNUP, referred_by),
                )
            db.commit()
        except sqlite3.IntegrityError:
            flash('Имя пользователя или телефон уже заняты.')
            return render_template('register.html', referral_code=referral_code)

        user = db.execute('SELECT id FROM users WHERE phone = ?', (phone,)).fetchone()
        sms_sent = send_sms_code(phone, code)
        if sms_sent:
            flash('Код подтверждения отправлен по SMS.')
        else:
            flash('SMS-провайдер не настроен. Тестовый код в консоли сервера.')
        return redirect(url_for('verify_sms', user_id=user['id']))

    return render_template('register.html', referral_code=referral_code)


@app.route('/verify/<int:user_id>', methods=['GET', 'POST'])
def verify_sms(user_id: int):
    db = get_db()
    user = db.execute('SELECT * FROM users WHERE id = ?', (user_id,)).fetchone()
    if not user:
        flash('Пользователь не найден.')
        return redirect(url_for('register'))

    if request.method == 'POST':
        code = request.form.get('code', '').strip()
        if not code:
            flash('Введите код.')
            return render_template('verify.html', user_id=user_id)

        if user['sms_code'] != code:
            flash('Неверный код.')
            return render_template('verify.html', user_id=user_id)

        expires = datetime.fromisoformat(user['sms_code_expires_at'])
        if datetime.utcnow() > expires:
            flash('Срок действия кода истек. Зарегистрируйтесь снова.')
            return redirect(url_for('register'))

        db.execute(
            'UPDATE users SET is_verified = 1, sms_code = NULL, sms_code_expires_at = NULL WHERE id = ?',
            (user_id,),
        )
        db.commit()
        flash('Аккаунт подтвержден. Теперь можно войти.')
        return redirect(url_for('login'))

    return render_template('verify.html', user_id=user_id)


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '')

        user = get_db().execute('SELECT * FROM users WHERE username = ?', (username,)).fetchone()
        if not user or not check_password_hash(user['password_hash'], password):
            flash('Неверный логин или пароль.')
            return render_template('login.html')

        if user['role'] in (ROLE_ADMIN, ROLE_SUBADMIN):
            session.clear()
            session['admin_user_id'] = user['id']
            return redirect(url_for('admin_users'))

        if not user['is_verified']:
            flash('Сначала подтвердите аккаунт.')
            return redirect(url_for('verify_sms', user_id=user['id']))

        session.pop('admin_user_id', None)
        session['user_id'] = user['id']
        return redirect(url_for('dashboard'))

    return render_template('login.html')


@app.route('/logout')
def logout():
    session.clear()
    flash('Вы вышли из аккаунта.')
    return redirect(url_for('login'))


@app.route('/admin')
def admin_index():
    if get_current_admin():
        return redirect(url_for('admin_users'))
    return redirect(url_for('login'))


@app.route('/admin/login', methods=['GET', 'POST'])
def admin_login():
    return redirect(url_for('login'))


@app.route('/admin/logout')
def admin_logout():
    session.pop('admin_user_id', None)
    flash('Вы вышли из админ-панели.')
    return redirect(url_for('login'))


@app.route('/admin/users', methods=['GET', 'POST'])
@admin_required
def admin_users():
    db = get_db()
    admin_user = get_current_admin()
    assert admin_user is not None

    q = request.args.get('q', '').strip()

    if request.method == 'POST':
        action = request.form.get('action', '').strip()
        q = request.form.get('q', q).strip()
        user_id_raw = request.form.get('user_id', '').strip()

        if not user_id_raw.isdigit():
            flash('Неверный ID пользователя.')
            return redirect(url_for('admin_users', q=q))

        target_user = db.execute(
            'SELECT id, username, is_admin, role FROM users WHERE id = ?',
            (int(user_id_raw),),
        ).fetchone()
        if not target_user:
            flash('Пользователь не найден.')
            return redirect(url_for('admin_users', q=q))

        if action == 'reset_password':
            new_password = request.form.get('new_password', '')
            if len(new_password) < 6:
                flash('Новый пароль должен быть не короче 6 символов.')
                return redirect(url_for('admin_users', q=q))

            db.execute(
                'UPDATE users SET password_hash = ? WHERE id = ?',
                (generate_password_hash(new_password), target_user['id']),
            )
            db.commit()
            flash(f"Пароль пользователя '{target_user['username']}' изменен.")
            return redirect(url_for('admin_users', q=q))

        if action == 'change_role':
            new_role = request.form.get('new_role', '').strip().lower()
            if admin_user['role'] != ROLE_ADMIN:
                flash('Только админ может изменять роли.')
                return redirect(url_for('admin_users', q=q))
            if new_role not in USER_ROLES:
                flash('Неверная роль.')
                return redirect(url_for('admin_users', q=q))
            if target_user['id'] == admin_user['id']:
                flash('Нельзя изменить роль текущего админа через эту форму.')
                return redirect(url_for('admin_users', q=q))
            if target_user['role'] == ROLE_ADMIN and new_role != ROLE_ADMIN:
                admins_count = db.execute(
                    'SELECT COUNT(*) AS c FROM users WHERE role = ?',
                    (ROLE_ADMIN,),
                ).fetchone()['c']
                if admins_count <= 1:
                    flash('Нельзя убрать роль у последнего админа.')
                    return redirect(url_for('admin_users', q=q))

            db.execute(
                'UPDATE users SET role = ?, is_admin = ? WHERE id = ?',
                (new_role, 1 if new_role == ROLE_ADMIN else 0, target_user['id']),
            )
            db.commit()
            flash(f"Роль пользователя '{target_user['username']}' изменена.")
            return redirect(url_for('admin_users', q=q))

        if action == 'delete_user':
            if target_user['id'] == admin_user['id']:
                flash('Нельзя удалить текущего пользователя админ-панели.')
                return redirect(url_for('admin_users', q=q))
            if target_user['role'] == ROLE_ADMIN:
                admins_count = db.execute(
                    'SELECT COUNT(*) AS c FROM users WHERE role = ?',
                    (ROLE_ADMIN,),
                ).fetchone()['c']
                if admins_count <= 1:
                    flash('Нельзя удалить последнего админа.')
                    return redirect(url_for('admin_users', q=q))
            if target_user['role'] in (ROLE_ADMIN, ROLE_SUBADMIN) and admin_user['role'] != ROLE_ADMIN:
                flash('Только админ может удалять админов и подадминов.')
                return redirect(url_for('admin_users', q=q))

            db.execute('UPDATE users SET referred_by = NULL WHERE referred_by = ?', (target_user['id'],))
            db.execute('UPDATE videos SET created_by = NULL WHERE created_by = ?', (target_user['id'],))
            db.execute('DELETE FROM user_video_views WHERE user_id = ?', (target_user['id'],))
            db.execute('DELETE FROM withdrawal_requests WHERE user_id = ?', (target_user['id'],))
            db.execute('DELETE FROM users WHERE id = ?', (target_user['id'],))
            db.commit()
            flash(f"Пользователь '{target_user['username']}' удален.")
            return redirect(url_for('admin_users', q=q))

        flash('Неизвестное действие.')
        return redirect(url_for('admin_users', q=q))

    like = f'%{q}%'

    users = db.execute(
        '''
        SELECT
            u.id,
            u.username,
            u.phone,
            u.balance,
            u.is_verified,
            u.is_admin,
            u.role,
            u.created_at,
            u.referral_code,
            u.referral_bonus,
            inviter.username AS inviter_username,
            inviter.referral_code AS inviter_referral_code
        FROM users AS u
        LEFT JOIN users AS inviter ON inviter.id = u.referred_by
        WHERE (
            ? = ''
            OR u.username LIKE ?
            OR u.phone LIKE ?
            OR IFNULL(inviter.username, '') LIKE ?
            OR IFNULL(inviter.referral_code, '') LIKE ?
        )
        ORDER BY u.id DESC
        ''',
        (q, like, like, like, like),
    ).fetchall()
    total_users = db.execute('SELECT COUNT(*) AS c FROM users').fetchone()['c']

    return render_template(
        'admin_users.html',
        users=users,
        q=q,
        total_users=total_users,
    )


@app.route('/admin/withdrawals', methods=['GET', 'POST'])
@admin_required
def admin_withdrawals():
    q = request.args.get('q', '').strip()
    status_filter = request.args.get('status', 'all').strip().lower()
    if status_filter not in ('all',) + WITHDRAWAL_STATUSES:
        status_filter = 'all'

    db = get_db()

    if request.method == 'POST':
        request_id_raw = request.form.get('request_id', '').strip()
        new_status = request.form.get('status', '').strip()
        q = request.form.get('q', q).strip()
        status_filter = request.form.get('status_filter', status_filter).strip().lower()

        if not request_id_raw.isdigit() or new_status not in WITHDRAWAL_STATUSES:
            flash('Неверные данные для смены статуса.')
            return redirect(url_for('admin_withdrawals', q=q, status=status_filter))

        db.execute(
            'UPDATE withdrawal_requests SET status = ? WHERE id = ?',
            (new_status, int(request_id_raw)),
        )
        db.commit()
        flash('Статус заявки обновлен.')
        return redirect(url_for('admin_withdrawals', q=q, status=status_filter))

    like = f'%{q}%'
    requests_data = db.execute(
        '''
        SELECT
            wr.id,
            wr.user_id,
            wr.amount,
            wr.payout_details,
            wr.status,
            wr.created_at,
            u.username,
            u.phone,
            u.balance
        FROM withdrawal_requests AS wr
        JOIN users AS u ON u.id = wr.user_id
        WHERE (
            ? = ''
            OR u.username LIKE ?
            OR u.phone LIKE ?
            OR wr.payout_details LIKE ?
        )
        AND (? = 'all' OR wr.status = ?)
        ORDER BY wr.id DESC
        ''',
        (q, like, like, like, status_filter, status_filter),
    ).fetchall()

    total_requests = db.execute('SELECT COUNT(*) AS c FROM withdrawal_requests').fetchone()['c']
    pending_count = db.execute(
        "SELECT COUNT(*) AS c FROM withdrawal_requests WHERE status = 'pending'"
    ).fetchone()['c']

    return render_template(
        'admin_withdrawals.html',
        requests_data=requests_data,
        q=q,
        status_filter=status_filter,
        statuses=WITHDRAWAL_STATUSES,
        total_requests=total_requests,
        pending_count=pending_count,
    )


@app.route('/admin/videos', methods=['GET', 'POST'])
@admin_required
def admin_videos():
    db = get_db()
    admin_user = get_current_admin()
    assert admin_user is not None

    today = date.today().isoformat()
    requested_day = request.args.get('day', '').strip()
    selected_day = parse_day_value(requested_day) if requested_day else today
    if selected_day is None:
        selected_day = today
    if selected_day < today:
        selected_day = today

    if request.method == 'POST':
        action = request.form.get('action', '').strip()
        selected_day = parse_day_value(request.form.get('day', '')) or today
        if selected_day < today:
            flash('Нельзя добавить видео на прошедшую дату.')
            return redirect(url_for('admin_videos', day=today))

        if action == 'add_video':
            title = request.form.get('title', '').strip()
            video_url = request.form.get('video_url', '').strip()
            video_file = request.files.get('video_file')
            advertiser_name = request.form.get('advertiser_name', '').strip()

            has_uploaded_file = bool(video_file and video_file.filename)
            if not video_url and not has_uploaded_file:
                flash('Укажите ссылку или загрузите файл видео.')
                return redirect(url_for('admin_videos', day=selected_day))
            if not advertiser_name:
                flash('Укажите имя рекламодателя.')
                return redirect(url_for('admin_videos', day=selected_day))

            day_count = db.execute(
                'SELECT COUNT(*) AS c FROM videos WHERE available_on = ?',
                (selected_day,),
            ).fetchone()['c']
            if day_count >= DAILY_VIDEO_LIMIT:
                flash(f'На {selected_day} уже добавлено {DAILY_VIDEO_LIMIT} видео.')
                return redirect(url_for('admin_videos', day=selected_day))

            if not title:
                title = f'Рекламное видео {day_count + 1}'

            if has_uploaded_file:
                assert video_file is not None
                if not is_allowed_video(video_file.filename):
                    flash('Допустимые файлы: mp4, webm, ogg.')
                    return redirect(url_for('admin_videos', day=selected_day))

                try:
                    video_file.stream.seek(0, os.SEEK_END)
                    file_size = video_file.stream.tell()
                    video_file.stream.seek(0)
                except (AttributeError, OSError):
                    file_size = 0

                if file_size > MAX_VIDEO_UPLOAD_BYTES:
                    flash(f'Файл слишком большой. Максимум {MAX_VIDEO_UPLOAD_MB} МБ.')
                    return redirect(url_for('admin_videos', day=selected_day))

                extension = secure_filename(video_file.filename).rsplit('.', 1)[1].lower()
                unique_suffix = random.randint(1000, 9999)
                filename = f'video_{selected_day}_{int(datetime.utcnow().timestamp())}_{unique_suffix}.{extension}'
                os.makedirs(VIDEO_UPLOAD_DIR, exist_ok=True)
                save_path = os.path.join(VIDEO_UPLOAD_DIR, filename)
                video_file.save(save_path)
                video_url = url_for('static', filename=f'uploaded_videos/{filename}')

            db.execute(
                '''
                INSERT INTO videos (title, video_url, advertiser_name, available_on, created_at, created_by)
                VALUES (?, ?, ?, ?, ?, ?)
                ''',
                (title, video_url, advertiser_name, selected_day, datetime.utcnow().isoformat(), admin_user['id']),
            )
            db.commit()
            flash('Видео добавлено.')
            return redirect(url_for('admin_videos', day=selected_day))

        if action == 'delete_video':
            video_id_raw = request.form.get('video_id', '').strip()
            if not video_id_raw.isdigit():
                flash('Неверный ID видео.')
                return redirect(url_for('admin_videos', day=selected_day))

            video_row = db.execute(
                'SELECT id, video_url FROM videos WHERE id = ? AND available_on = ?',
                (int(video_id_raw), selected_day),
            ).fetchone()
            if not video_row:
                flash('Видео не найдено для выбранной даты.')
                return redirect(url_for('admin_videos', day=selected_day))

            remove_uploaded_video_file(video_row['video_url'])
            db.execute('DELETE FROM videos WHERE id = ?', (int(video_id_raw),))
            db.execute('DELETE FROM user_video_views WHERE video_id = ?', (int(video_id_raw),))
            db.commit()
            flash('Видео удалено.')
            return redirect(url_for('admin_videos', day=selected_day))

        flash('Неизвестное действие.')
        return redirect(url_for('admin_videos', day=selected_day))

    videos = db.execute(
        '''
        SELECT
            v.id,
            v.title,
            v.video_url,
            v.advertiser_name,
            v.available_on,
            v.created_at,
            creator.username AS created_by_username
        FROM videos AS v
        LEFT JOIN users AS creator ON creator.id = v.created_by
        WHERE v.available_on = ?
        ORDER BY v.id ASC
        LIMIT ?
        ''',
        (selected_day, DAILY_VIDEO_LIMIT),
    ).fetchall()
    videos_count = db.execute('SELECT COUNT(*) AS c FROM videos WHERE available_on = ?', (selected_day,)).fetchone()['c']

    return render_template(
        'admin_videos.html',
        selected_day=selected_day,
        videos=videos,
        videos_count=videos_count,
        daily_limit=DAILY_VIDEO_LIMIT,
        max_video_upload_mb=MAX_VIDEO_UPLOAD_MB,
    )


@app.route('/dashboard')
@login_required
def dashboard():
    user = get_current_user()
    assert user is not None

    db = get_db()
    user = ensure_user_referral_code(db, user)

    today = date.today().isoformat()
    videos = db.execute(
        '''
        SELECT id, title, video_url, advertiser_name, available_on
        FROM videos
        WHERE available_on = ?
        ORDER BY id ASC
        LIMIT ?
        ''',
        (today, DAILY_VIDEO_LIMIT),
    ).fetchall()

    video_ids = {row['id'] for row in videos}
    watched_ids = {
        row['video_id']
        for row in db.execute(
            'SELECT video_id FROM user_video_views WHERE user_id = ? AND viewed_on = ?',
            (user['id'], today),
        ).fetchall()
        if row['video_id'] in video_ids
    }

    active_limit = len(videos)
    watched = len(watched_ids)
    remaining = max(0, active_limit - watched)
    reward = get_user_reward(user)

    return render_template(
        'dashboard.html',
        user=user,
        videos=videos,
        watched_ids=watched_ids,
        remaining=remaining,
        active_limit=active_limit,
        reward=reward,
    )


@app.route('/referrals')
@login_required
def referrals():
    user = get_current_user()
    assert user is not None

    db = get_db()
    user = ensure_user_referral_code(db, user)
    invited_users = db.execute(
        '''
        SELECT username, phone, created_at, is_verified
        FROM users
        WHERE referred_by = ?
        ORDER BY id DESC
        ''',
        (user['id'],),
    ).fetchall()

    return render_template(
        'referrals.html',
        user=user,
        invited_users=invited_users,
        referral_link=build_referral_link(user['referral_code']),
        referral_bonus_per_signup=REFERRAL_BONUS_PER_SIGNUP,
    )


@app.route('/profile', methods=['GET', 'POST'])
@login_required
def profile():
    user = get_current_user()
    assert user is not None

    db = get_db()

    if request.method == 'POST':
        action = request.form.get('action', '').strip()

        if action == 'update_photo':
            photo_url = request.form.get('photo_url', '').strip()
            photo_file = request.files.get('photo_file')

            if photo_file and photo_file.filename:
                if not is_allowed_photo(photo_file.filename):
                    flash('Допустимы только изображения: png, jpg, jpeg, webp, gif.')
                    return redirect(url_for('profile'))

                extension = secure_filename(photo_file.filename).rsplit('.', 1)[1].lower()
                filename = f'user_{user["id"]}_{int(datetime.utcnow().timestamp())}.{extension}'
                os.makedirs(PROFILE_PHOTO_DIR, exist_ok=True)
                photo_path = os.path.join(PROFILE_PHOTO_DIR, filename)
                photo_file.save(photo_path)
                photo_url = url_for('static', filename=f'profile_photos/{filename}')

            if photo_url and not (photo_url.startswith('http://') or photo_url.startswith('https://')):
                if not photo_url.startswith('/static/'):
                    flash('Ссылка на фото должна начинаться с http:// или https://')
                    return redirect(url_for('profile'))
            if photo_url and photo_url.startswith('/static/'):
                photo_url = photo_url.lstrip('/')

            if photo_url and photo_url.startswith('static/'):
                db.execute('UPDATE users SET profile_photo_url = ? WHERE id = ?', (f'/{photo_url}', user['id']))
            else:
                db.execute('UPDATE users SET profile_photo_url = ? WHERE id = ?', (photo_url, user['id']))
            db.commit()
            flash('Фото профиля обновлено.')
            return redirect(url_for('profile'))

        if action == 'update_phone':
            new_phone = request.form.get('phone', '').strip()
            if not new_phone:
                flash('Введите новый номер телефона.')
                return redirect(url_for('profile'))
            existing = db.execute(
                'SELECT id FROM users WHERE phone = ? AND id <> ?',
                (new_phone, user['id']),
            ).fetchone()
            if existing:
                flash('Этот номер уже используется другим пользователем.')
                return redirect(url_for('profile'))
            db.execute('UPDATE users SET phone = ? WHERE id = ?', (new_phone, user['id']))
            db.commit()
            flash('Номер телефона обновлен.')
            return redirect(url_for('profile'))

        if action == 'update_password':
            current_password = request.form.get('current_password', '')
            new_password = request.form.get('new_password', '')
            confirm_password = request.form.get('confirm_password', '')

            if not current_password or not new_password or not confirm_password:
                flash('Заполните все поля для смены пароля.')
                return redirect(url_for('profile'))
            if not check_password_hash(user['password_hash'], current_password):
                flash('Текущий пароль введен неверно.')
                return redirect(url_for('profile'))
            if len(new_password) < 6:
                flash('Новый пароль должен быть не короче 6 символов.')
                return redirect(url_for('profile'))
            if new_password != confirm_password:
                flash('Подтверждение пароля не совпадает.')
                return redirect(url_for('profile'))

            db.execute(
                'UPDATE users SET password_hash = ? WHERE id = ?',
                (generate_password_hash(new_password), user['id']),
            )
            db.commit()
            flash('Пароль успешно изменен.')
            return redirect(url_for('profile'))

        flash('Неизвестное действие.')
        return redirect(url_for('profile'))

    user = db.execute('SELECT * FROM users WHERE id = ?', (user['id'],)).fetchone()
    assert user is not None
    total_views = db.execute(
        'SELECT COUNT(*) AS c FROM user_video_views WHERE user_id = ?',
        (user['id'],),
    ).fetchone()['c']
    invited_count = db.execute(
        'SELECT COUNT(*) AS c FROM users WHERE referred_by = ?',
        (user['id'],),
    ).fetchone()['c']
    return render_template(
        'profile.html',
        user=user,
        total_views=total_views,
        invited_count=invited_count,
        profile_level=get_profile_level(total_views),
        avatar_url=get_avatar_url(user),
    )


@app.route('/withdraw', methods=['GET', 'POST'])
@login_required
def withdraw():
    user = get_current_user()
    assert user is not None
    db = get_db()

    if request.method == 'POST':
        amount_raw = request.form.get('amount', '').strip()
        bank_name = request.form.get('bank_name', '').strip()
        payout_details = request.form.get('payout_details', '').strip()
        amount = parse_amount(amount_raw)

        if amount is None:
            flash('Введите корректную сумму для вывода.')
            return redirect(url_for('withdraw'))
        if amount <= MIN_WITHDRAWAL:
            flash(f'Сумма должна быть больше {MIN_WITHDRAWAL:.2f} сомони.')
            return redirect(url_for('withdraw'))
        if amount > user['balance']:
            flash('Недостаточно средств на счете.')
            return redirect(url_for('withdraw'))
        if not bank_name:
            flash('Выберите банк для вывода.')
            return redirect(url_for('withdraw'))
        if bank_name not in TAJIK_BANKS:
            flash('Выберите банк из списка.')
            return redirect(url_for('withdraw'))
        if not payout_details:
            flash('Укажите реквизиты для вывода (карта/кошелек/телефон).')
            return redirect(url_for('withdraw'))

        full_payout_details = f'Банк: {bank_name}; Реквизиты: {payout_details}'
        db.execute('UPDATE users SET balance = balance - ? WHERE id = ?', (amount, user['id']))
        db.execute(
            '''
            INSERT INTO withdrawal_requests (user_id, amount, payout_details, status, created_at)
            VALUES (?, ?, ?, 'pending', ?)
            ''',
            (user['id'], amount, full_payout_details, datetime.utcnow().isoformat()),
        )
        db.commit()
        flash(f'Заявка на вывод {amount:.2f} сомони создана.')
        return redirect(url_for('withdraw'))

    requests = db.execute(
        '''
        SELECT amount, payout_details, status, created_at
        FROM withdrawal_requests
        WHERE user_id = ?
        ORDER BY id DESC
        LIMIT 20
        ''',
        (user['id'],),
    ).fetchall()
    user = db.execute('SELECT * FROM users WHERE id = ?', (user['id'],)).fetchone()
    return render_template(
        'withdraw.html',
        user=user,
        requests=requests,
        min_withdrawal=MIN_WITHDRAWAL,
        tajik_banks=TAJIK_BANKS,
    )


@app.route('/watch/<int:video_id>')
@login_required
def watch(video_id: int):
    user = get_current_user()
    assert user is not None

    db = get_db()
    today = date.today().isoformat()
    video = db.execute(
        'SELECT * FROM videos WHERE id = ? AND available_on = ?',
        (video_id, today),
    ).fetchone()
    if not video:
        flash('Видео не найдено.')
        return redirect(url_for('dashboard'))

    if videos_watched_today(user['id']) >= DAILY_VIDEO_LIMIT:
        flash('Дневной лимит достигнут. Возвращайтесь завтра.')
        return redirect(url_for('dashboard'))

    already = db.execute(
        'SELECT id FROM user_video_views WHERE user_id = ? AND video_id = ? AND viewed_on = ?',
        (user['id'], video_id, today),
    ).fetchone()
    if already:
        flash('Это видео уже засчитано сегодня.')
        return redirect(url_for('dashboard'))

    return render_template('watch.html', video=video, reward=get_user_reward(user))


@app.route('/claim/<int:video_id>', methods=['POST'])
@login_required
def claim(video_id: int):
    user = get_current_user()
    assert user is not None

    db = get_db()
    today = date.today().isoformat()
    reward = get_user_reward(user)

    video = db.execute(
        'SELECT id FROM videos WHERE id = ? AND available_on = ?',
        (video_id, today),
    ).fetchone()
    if not video:
        flash('Видео недоступно для начисления сегодня.')
        return redirect(url_for('dashboard'))

    if videos_watched_today(user['id']) >= DAILY_VIDEO_LIMIT:
        flash('Дневной лимит достигнут.')
        return redirect(url_for('dashboard'))

    existing = db.execute(
        'SELECT id FROM user_video_views WHERE user_id = ? AND video_id = ? AND viewed_on = ?',
        (user['id'], video_id, today),
    ).fetchone()
    if existing:
        flash('Награда за это видео уже получена сегодня.')
        return redirect(url_for('dashboard'))

    db.execute(
        'INSERT INTO user_video_views (user_id, video_id, viewed_on, created_at) VALUES (?, ?, ?, ?)',
        (user['id'], video_id, today, datetime.utcnow().isoformat()),
    )
    db.execute('UPDATE users SET balance = balance + ? WHERE id = ?', (reward, user['id']))
    db.commit()

    flash(f'+{reward:.2f} сомони зачислено на счет.')
    return redirect(url_for('dashboard'))


if __name__ == '__main__':
    init_db()
    app.run(host='0.0.0.0', port=5000, debug=False)
