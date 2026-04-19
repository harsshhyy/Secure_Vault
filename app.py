import os
import sqlite3
import csv
import io
import json
import secrets
from datetime import datetime, timedelta
from functools import wraps

from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler
import numpy as np
import pyotp
from flask_mail import Mail, Message
from bcrypt import gensalt, hashpw, checkpw
from cryptography.fernet import Fernet
from flask import (
    Flask,
    flash,
    g,
    jsonify,
    redirect,
    render_template,
    request,
    send_file,
    session,
    url_for,
)
from werkzeug.utils import secure_filename

BASE_DIR = os.path.abspath(os.path.dirname(__file__))
DATABASE_PATH = os.path.join(BASE_DIR, 'secure_vault.db')
UPLOAD_FOLDER = os.path.join(BASE_DIR, 'vault_files')
FERNET_KEY_PATH = os.path.join(BASE_DIR, 'vault_key.key')
ALLOWED_EXTENSIONS = set(['txt', 'pdf', 'png', 'jpg', 'jpeg', 'doc', 'docx', 'xlsx', 'csv'])

app = Flask(__name__)
app.secret_key = os.environ.get('FLASK_SECRET_KEY', secrets.token_urlsafe(32))
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['MAX_CONTENT_LENGTH'] = 32 * 1024 * 1024  # 32 MB
app.permanent_session_lifetime = timedelta(minutes=30)

# Flask-Mail config (use environment variables in production)
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = os.environ.get('MAIL_USERNAME')
app.config['MAIL_PASSWORD'] = os.environ.get('MAIL_PASSWORD')
app.config['MAIL_DEFAULT_SENDER'] = os.environ.get('MAIL_DEFAULT_SENDER', 'noreply@securevault.com')

mail = Mail(app)

if not os.path.exists(UPLOAD_FOLDER):
    os.makedirs(UPLOAD_FOLDER, exist_ok=True)


def load_or_create_key(path: str) -> bytes:
    if os.path.exists(path):
        with open(path, 'rb') as key_file:
            return key_file.read()

    key = Fernet.generate_key()
    with open(path, 'wb') as key_file:
        key_file.write(key)
    return key

FERNET_KEY = load_or_create_key(FERNET_KEY_PATH)
fernet = Fernet(FERNET_KEY)

# Global dict to store trained models and scalers per user
user_models = {}
user_scalers = {}

# ML Configuration Constants
MIN_SAMPLES_FOR_TRAINING = 20
ANOMALY_THRESHOLD = -0.5  # Isolation Forest anomaly score threshold
CONTAMINATION_RATE = 0.1  # Percentage of anomalies expected in normal operation

# Risk-Based Adaptive Authentication Constants
RISK_LOW_THRESHOLD = 30      # Risk score < 30 = Low risk (normal auth)
RISK_MEDIUM_THRESHOLD = 70   # Risk score 30-70 = Medium risk (OTP required)
RISK_HIGH_THRESHOLD = 100    # Risk score > 70 = High risk (block + alert)

# Risk factor weights
RISK_WEIGHTS = {
    'new_device': 25,           # New device fingerprint
    'new_location': 20,         # Different IP/location
    'unusual_time': 10,         # Login outside usual hours
    'failed_attempts': 15,      # Recent failed login attempts
    'anomalous_behavior': 30,   # Anomalous user behavior detected
}


def get_db():
    db = getattr(g, '_database', None)
    if db is None:
        db = g._database = sqlite3.connect(DATABASE_PATH)
        db.row_factory = sqlite3.Row
    return db


def query_db(query, args=(), one=False):
    cur = get_db().execute(query, args)
    rv = cur.fetchall()
    cur.close()
    return (rv[0] if rv else None) if one else rv


def execute_db(query, args=()):
    conn = get_db()
    cur = conn.cursor()
    cur.execute(query, args)
    conn.commit()
    cur.close()
    return cur.lastrowid


def init_db():
    conn = sqlite3.connect(DATABASE_PATH)
    cursor = conn.cursor()
    cursor.execute(
        '''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            email TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            name TEXT DEFAULT '',
            profile_picture TEXT DEFAULT '',
            twofa_secret TEXT,
            failed_attempts INTEGER DEFAULT 0,
            lockout_until TEXT,
            allowed_ips TEXT DEFAULT '',
            reset_token TEXT,
            reset_expires TEXT,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP
        )
        '''
    )
    cursor.execute(
        '''
        CREATE TABLE IF NOT EXISTS notes (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            content BLOB NOT NULL,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY(user_id) REFERENCES users(id)
        )
        '''
    )
    cursor.execute(
        '''
        CREATE TABLE IF NOT EXISTS files (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            filename TEXT NOT NULL,
            storage_name TEXT NOT NULL,
            tags TEXT,
            uploaded_at TEXT DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY(user_id) REFERENCES users(id)
        )
        '''
    )
    cursor.execute(
        '''
        CREATE TABLE IF NOT EXISTS behavior_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            action TEXT NOT NULL,
            details TEXT,
            features TEXT,
            trust_score INTEGER,
            anomaly_score REAL,
            is_anomaly INTEGER DEFAULT 0,
            timestamp TEXT DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY(user_id) REFERENCES users(id)
        )
        '''
    )
    # Add missing columns if they don't exist
    try:
        cursor.execute('ALTER TABLE behavior_logs ADD COLUMN features TEXT')
    except sqlite3.OperationalError:
        pass
    try:
        cursor.execute('ALTER TABLE behavior_logs ADD COLUMN anomaly_score REAL')
    except sqlite3.OperationalError:
        pass
    try:
        cursor.execute('ALTER TABLE behavior_logs ADD COLUMN is_anomaly INTEGER DEFAULT 0')
    except sqlite3.OperationalError:
        pass
    
    # Create login_attempts table for risk tracking
    cursor.execute(
        '''
        CREATE TABLE IF NOT EXISTS login_attempts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            username TEXT NOT NULL,
            ip_address TEXT,
            device_fingerprint TEXT,
            risk_score INTEGER,
            risk_level TEXT,
            factors TEXT,
            success INTEGER DEFAULT 0,
            otp_verified INTEGER DEFAULT 0,
            timestamp TEXT DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY(user_id) REFERENCES users(id)
        )
        '''
    )
    
    # Add columns to users table for device tracking
    try:
        cursor.execute('ALTER TABLE users ADD COLUMN last_login_ip TEXT')
    except sqlite3.OperationalError:
        pass
    try:
        cursor.execute('ALTER TABLE users ADD COLUMN trusted_devices TEXT')  # JSON array of fingerprints
    except sqlite3.OperationalError:
        pass
    try:
        cursor.execute('ALTER TABLE users ADD COLUMN last_successful_login TEXT')
    except sqlite3.OperationalError:
        pass
    try:
        cursor.execute('ALTER TABLE users ADD COLUMN twofa_secret TEXT')
    except sqlite3.OperationalError:
        pass
    
    conn.commit()
    conn.close()


@app.teardown_appcontext
def close_connection(exception):
    db = getattr(g, '_database', None)
    if db is not None:
        db.close()


def hash_password(password: str) -> bytes:
    return hashpw(password.encode('utf-8'), gensalt())


def verify_password(password: str, hashed: bytes) -> bool:
    return checkpw(password.encode('utf-8'), hashed)


def encrypt_value(value: str) -> bytes:
    return fernet.encrypt(value.encode('utf-8'))


def decrypt_value(token: bytes) -> str:
    return fernet.decrypt(token).decode('utf-8')


def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS


def get_current_user():
    if 'user_id' not in session:
        return None
    user_row = query_db('SELECT * FROM users WHERE id = ?', [session['user_id']], one=True)
    return dict(user_row) if user_row else None


def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            return redirect(url_for('login'))
        return f(*args, **kwargs)

    return decorated_function


def generate_2fa_secret():
    return pyotp.random_base32()


def verify_2fa(secret, token):
    totp = pyotp.TOTP(secret)
    return totp.verify(token)


def is_account_locked(user):
    lockout_until = user.get('lockout_until') if isinstance(user, dict) else None
    if lockout_until:
        try:
            lockout_time = datetime.fromisoformat(lockout_until)
            if datetime.utcnow() < lockout_time:
                return True
        except (ValueError, TypeError):
            pass
    return False


def lock_account(user_id):
    lockout_until = datetime.utcnow() + timedelta(minutes=15)
    execute_db('UPDATE users SET failed_attempts = failed_attempts + 1, lockout_until = ? WHERE id = ?', [lockout_until.isoformat(), user_id])


def reset_failed_attempts(user_id):
    execute_db('UPDATE users SET failed_attempts = 0, lockout_until = NULL WHERE id = ?', [user_id])


def check_ip_allowed(user, client_ip):
    allowed_ips = user.get('allowed_ips') if isinstance(user, dict) else None
    if not allowed_ips:
        return True  # No restrictions
    allowed = allowed_ips.split(',')
    return client_ip in allowed


def send_reset_email(email, token):
    msg = Message('Password Reset Request', recipients=[email])
    msg.body = f'Click the link to reset your password: http://127.0.0.1:5000/reset_password/{token}'
    mail.send(msg)


def send_anomaly_alert(email, username, details=''):
    """Send an email alert when anomalous behavior is detected."""
    detail_msg = f'\nDetails: {details}\n' if details else ''
    msg = Message('Security Alert: Anomaly Detected', recipients=[email])
    msg.body = f'''Dear {username},

An anomalous behavior has been detected in your Secure Vault account. For security reasons, you have been automatically logged out.
{detail_msg}
If this was not you, please:
1. Change your password immediately
2. Review your recent account activity
3. Check connected devices and sessions

Secure Vault Security Team'''
    try:
        mail.send(msg)
        print(f"[EMAIL] Anomaly alert sent to {email}")
    except Exception as e:
        print(f"[ERROR] Failed to send anomaly alert to {email}: {e}")


def train_user_model(user_id):
    """Train Isolation Forest model for a user using their behavior logs."""
    # Get all behavioral logs with features for this user (last 500 records)
    logs = query_db(
        'SELECT features FROM behavior_logs WHERE user_id = ? AND features IS NOT NULL ORDER BY timestamp DESC LIMIT 500',
        [user_id]
    )
    
    if len(logs) < MIN_SAMPLES_FOR_TRAINING:
        print(f"[ML] Not enough data to train model for user {user_id}. Have {len(logs)}, need {MIN_SAMPLES_FOR_TRAINING}")
        return None
    
    features = []
    for log in logs:
        try:
            feature_vector = json.loads(log['features'])
            if isinstance(feature_vector, list) and len(feature_vector) >= 5:
                features.append(feature_vector[:5])
        except (json.JSONDecodeError, TypeError, IndexError):
            continue
    
    if len(features) < MIN_SAMPLES_FOR_TRAINING:
        print(f"[ML] Not enough valid features for user {user_id}. Have {len(features)} valid samples")
        return None
    
    features_array = np.array(features)
    
    # Standardize features using StandardScaler
    scaler = StandardScaler()
    scaled_features = scaler.fit_transform(features_array)
    user_scalers[user_id] = scaler
    
    # Train Isolation Forest with optimized parameters
    model = IsolationForest(
        contamination=CONTAMINATION_RATE,
        random_state=42,
        n_estimators=100,
        max_samples='auto',
        n_jobs=-1
    )
    model.fit(scaled_features)
    user_models[user_id] = model
    
    print(f"[ML] Successfully trained model for user {user_id} with {len(features)} samples")
    return model


def compute_trust_score(feature_vector):
    """Compute trust score from feature vector (rule-based fallback)."""
    if not feature_vector or len(feature_vector) < 5:
        return 50  # Default medium score
    
    typing_speed, key_delay, mouse_speed, click_rate, scroll_velocity = feature_vector[:5]
    
    score = 100
    
    # Penalize unusual typing patterns
    score -= min(max((typing_speed - 8) * 4, 0), 25)
    # Penalize unusual key delay patterns
    score -= min(max((key_delay - 0.3) * 16, 0), 20)
    # Penalize unusual mouse speed
    score -= min(max((mouse_speed - 400) / 30, 0), 20)
    # Penalize unusual click rate
    score -= min(max((click_rate - 2.5) * 10, 0), 15)
    # Penalize unusual scroll velocity
    score -= min(max((scroll_velocity - 500) / 50, 0), 10)
    
    return max(0, min(100, int(score)))


def detect_anomaly_ml(user_id, feature_vector):
    """Detect anomalies using ML model.
    Returns: (is_anomaly: bool, trust_score: int, method: str)
    """
    if not feature_vector or len(feature_vector) < 5:
        return False, 50, 'invalid'
    
    # Try to get trained model
    model = user_models.get(user_id)
    scaler = user_scalers.get(user_id)
    
    if model is None:
        model = train_user_model(user_id)
        scaler = user_scalers.get(user_id)
    
    if model and scaler:
        try:
            # Normalize to 5 features
            feature_vector = feature_vector[:5]
            scaled_features = scaler.transform([feature_vector])
            
            # Get anomaly score (-1 to 1, lower is more anomalous)
            anomaly_score = model.score_samples(scaled_features)[0]
            is_anomaly = anomaly_score < ANOMALY_THRESHOLD
            
            # Convert to 0-100 scale for display (anomaly_score + 1) * 50
            trust_score = max(0, min(100, int((anomaly_score + 1) * 50)))
            
            print(f"[ML] User {user_id}: anomaly_score={anomaly_score:.2f}, trust_score={trust_score}, is_anomaly={is_anomaly}")
            return is_anomaly, trust_score, 'isolation_forest'
        except Exception as e:
            print(f"[ML] Error in ML detection for user {user_id}: {e}")
    
    # Fallback to rule-based scoring
    score = compute_trust_score(feature_vector)
    is_anomaly = score <= 30
    print(f"[FALLBACK] User {user_id}: trust_score={score}, is_anomaly={is_anomaly}")
    return is_anomaly, score, 'rule_based'


def calculate_login_risk(user_id, ip_address, device_fingerprint=None):
    """Calculate risk score for a login attempt.
    Returns: (risk_score: int, risk_level: str, risk_factors: dict)
    """
    risk_score = 0
    risk_factors = {}
    
    user_row = query_db('SELECT * FROM users WHERE id = ?', [user_id], one=True)
    user = dict(user_row) if user_row else {}
    if not user:
        return 100, 'high', {'error': 'User not found'}
    
    # 1. Check for new device/fingerprint
    if device_fingerprint:
        trusted_devices = []
        if user.get('trusted_devices'):
            try:
                trusted_devices = json.loads(user.get('trusted_devices', '[]'))
            except:
                trusted_devices = []
        
        if device_fingerprint not in trusted_devices:
            risk_score += RISK_WEIGHTS['new_device']
            risk_factors['new_device'] = RISK_WEIGHTS['new_device']
    
    # 2. Check for new IP/location
    last_ip = user.get('last_login_ip')
    if last_ip and last_ip != ip_address:
        risk_score += RISK_WEIGHTS['new_location']
        risk_factors['new_location'] = RISK_WEIGHTS['new_location']
    
    # 3. Check for unusual login time
    current_hour = datetime.utcnow().hour
    # Simple check: if last login was in different timezone region (very simple)
    last_login_str = user.get('last_successful_login')
    if last_login_str:
        try:
            last_login = datetime.fromisoformat(last_login_str)
            time_diff = abs(current_hour - last_login.hour)
            # Penalize logins that are very different in time
            if time_diff > 8:
                risk_score += RISK_WEIGHTS['unusual_time']
                risk_factors['unusual_time'] = RISK_WEIGHTS['unusual_time']
        except:
            pass
    
    # 4. Check for recent failed login attempts
    recent_failures_row = query_db(
        'SELECT COUNT(*) as count FROM login_attempts WHERE user_id = ? AND success = 0 AND timestamp > datetime("now", "-30 minutes")',
        [user_id],
        one=True
    )
    recent_failures = dict(recent_failures_row) if recent_failures_row else {}
    if recent_failures and recent_failures.get('count', 0) > 2:
        risk_score += RISK_WEIGHTS['failed_attempts']
        risk_factors['failed_attempts'] = RISK_WEIGHTS['failed_attempts']
    
    # 5. Check for anomalous behavior (from behavior logs)
    recent_anomalies_row = query_db(
        'SELECT COUNT(*) as count FROM behavior_logs WHERE user_id = ? AND is_anomaly = 1 AND timestamp > datetime("now", "-2 hours")',
        [user_id],
        one=True
    )
    recent_anomalies = dict(recent_anomalies_row) if recent_anomalies_row else {}
    if recent_anomalies and recent_anomalies.get('count', 0) > 0:
        risk_score += RISK_WEIGHTS['anomalous_behavior']
        risk_factors['anomalous_behavior'] = RISK_WEIGHTS['anomalous_behavior']
    
    # Determine risk level
    if risk_score < RISK_LOW_THRESHOLD:
        risk_level = 'low'
    elif risk_score < RISK_MEDIUM_THRESHOLD:
        risk_level = 'medium'
    else:
        risk_level = 'high'
    
    print(f"[RISK] User {user_id}: risk_score={risk_score}, risk_level={risk_level}, factors={risk_factors}")
    return risk_score, risk_level, risk_factors


def record_login_attempt(user_id, username, ip_address, risk_score, risk_level, risk_factors, success=False, otp_verified=False):
    """Record a login attempt with risk information."""
    factors_json = json.dumps(risk_factors)
    execute_db(
        'INSERT INTO login_attempts (user_id, username, ip_address, risk_score, risk_level, factors, success, otp_verified, timestamp) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)',
        [user_id, username, ip_address, risk_score, risk_level, factors_json, int(success), int(otp_verified), datetime.utcnow().isoformat()],
    )


def record_behavior(user_id, action, details='', trust_score=None, feature_vector=None, is_anomaly=0, anomaly_score=None):
    """Record user behavior with optional feature vector for ML training."""
    features_json = json.dumps(feature_vector) if feature_vector else None
    
    execute_db(
        'INSERT INTO behavior_logs (user_id, action, details, features, trust_score, anomaly_score, is_anomaly, timestamp) VALUES (?, ?, ?, ?, ?, ?, ?, ?)',
        [user_id, action, details, features_json, trust_score, anomaly_score, is_anomaly, datetime.utcnow().isoformat()],
    )


@app.route('/')
def index():
    if 'user_id' in session:
        return redirect(url_for('dashboard'))
    return redirect(url_for('login'))


@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        email = request.form.get('email', '').strip().lower()
        password = request.form.get('password', '')
        confirm_password = request.form.get('confirm_password', '')

        if not username or not email or not password:
            flash('Please fill in all required fields.', 'warning')
            return redirect(url_for('register'))

        if password != confirm_password:
            flash('Passwords do not match.', 'warning')
            return redirect(url_for('register'))

        existing_user = query_db('SELECT id FROM users WHERE username = ? OR email = ?', [username, email], one=True)
        if existing_user:
            flash('Username or email already exists.', 'danger')
            return redirect(url_for('register'))

        password_hash = hash_password(password)
        # 2FA is optional - not auto-generated during registration
        execute_db('INSERT INTO users (username, email, password, twofa_secret) VALUES (?, ?, ?, ?)', [username, email, password_hash, None])
        flash('Account created successfully. Please log in.', 'success')
        return redirect(url_for('login'))

    return render_template('register.html')


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '')
        device_fingerprint = request.form.get('deviceFingerprint', '')

        # Step 1: Verify credentials
        user_row = query_db('SELECT * FROM users WHERE username = ?', [username], one=True)
        user = dict(user_row) if user_row else {}
        
        if not user or not verify_password(password, user.get('password', '')):
            flash('Invalid username or password.', 'danger')
            return redirect(url_for('login'))

        # Step 2: Calculate login risk
        ip_address = request.remote_addr
        risk_score, risk_level, risk_factors = calculate_login_risk(user.get('id'), ip_address, device_fingerprint)

        print(f"[LOGIN] User {username}: risk_score={risk_score}, risk_level={risk_level}")

        # Step 3: Handle based on risk level
        if risk_level == 'high':
            # HIGH RISK: Block login and send alert
            print(f"[ALERT] High-risk login attempt for user {username} (score: {risk_score})")
            record_login_attempt(user.get('id'), username, ip_address, risk_score, risk_level, risk_factors, success=False)
            
            # Send security alert email
            try:
                msg = Message('Security Alert: Blocked Login Attempt', recipients=[user.get('email', '')])
                msg.body = f'''Dear {user.get('username', 'User')},

A login attempt to your Secure Vault account was blocked due to unusual activity.

Risk Factors:
{chr(10).join([f"  - {k}: {v}" for k, v in risk_factors.items()])}

If this was you:
1. Please try again later
2. Contact support if you need immediate access

If this was NOT you:
1. Change your password immediately
2. Review your account security settings
3. Contact support

Secure Vault Security Team'''
                mail.send(msg)
                print(f"[EMAIL] Security alert sent to {user.get('email', '')}")
            except Exception as e:
                print(f"[ERROR] Failed to send alert email: {e}")
            
            flash('Login blocked due to unusual activity. Please try again later.', 'danger')
            return redirect(url_for('login'))

        elif risk_level == 'medium':
            # MEDIUM RISK: Require OTP verification
            print(f"[OTP_REQUIRED] Medium-risk login for user {username} (score: {risk_score})")
            
            # Generate temporary session to store login state
            temp_token = secrets.token_urlsafe(32)
            session['temp_login'] = {
                'user_id': user.get('id'),
                'username': username,
                'ip_address': ip_address,
                'device_fingerprint': device_fingerprint,
                'risk_score': risk_score,
                'risk_level': risk_level,
                'risk_factors': risk_factors,
                'timestamp': datetime.utcnow().isoformat()
            }
            
            record_login_attempt(user.get('id'), username, ip_address, risk_score, risk_level, risk_factors, success=False, otp_verified=False)
            
            flash(f'Medium-risk login detected (Score: {risk_score}/100). OTP required.', 'warning')
            return redirect(url_for('verify_otp_login'))

        else:
            # LOW RISK: Normal login
            print(f"[LOGIN_SUCCESS] Low-risk login for user {username} (score: {risk_score})")
            
            session.clear()
            session['user_id'] = user.get('id')
            session['username'] = user.get('username', '')
            session.permanent = True
            session['login_time'] = datetime.utcnow().timestamp()
            session['risk_level'] = 'low'
            session['risk_score'] = risk_score
            
            # Update user's device tracking
            if device_fingerprint:
                trusted_devices = []
                if user.get('trusted_devices'):
                    try:
                        trusted_devices = json.loads(user['trusted_devices'])
                    except:
                        trusted_devices = []
                if device_fingerprint not in trusted_devices:
                    trusted_devices.append(device_fingerprint)
                execute_db('UPDATE users SET trusted_devices = ? WHERE id = ?', [json.dumps(trusted_devices[:10]), user.get('id')])  # Keep last 10 devices
            
            # Update last login info
            execute_db('UPDATE users SET last_login_ip = ?, last_successful_login = ? WHERE id = ?', 
                      [ip_address, datetime.utcnow().isoformat(), user.get('id')])
            
            record_login_attempt(user.get('id'), username, ip_address, risk_score, risk_level, risk_factors, success=True)
            record_behavior(user.get('id'), 'login', f'User logged in successfully (risk_level={risk_level}, score={risk_score})')
            
            return redirect(url_for('dashboard'))

    return render_template('login.html')


@app.route('/verify_otp_login', methods=['GET', 'POST'])
def verify_otp_login():
    """Verify OTP for medium-risk login attempts."""
    if 'temp_login' not in session:
        flash('Session expired. Please login again.', 'danger')
        return redirect(url_for('login'))
    
    temp_login = session['temp_login']
    user_id = temp_login['user_id']
    user_row = query_db('SELECT * FROM users WHERE id = ?', [user_id], one=True)
    user = dict(user_row) if user_row else {}
    
    # If 2FA not configured, allow login to proceed anyway (medium-risk check is sufficient)
    if not user:
        flash('User not found.', 'danger')
        session.pop('temp_login', None)
        return redirect(url_for('login'))
    
    if not user.get('twofa_secret'):
        # 2FA not configured - grant access after medium-risk detection
        session.clear()
        session['user_id'] = user_id
        session['username'] = user.get('username', '')
        session.permanent = True
        session['login_time'] = datetime.utcnow().timestamp()
        session['risk_level'] = temp_login['risk_level']
        session['risk_score'] = temp_login['risk_score']
        
        # Update last login
        execute_db('UPDATE users SET last_login_ip = ?, last_successful_login = ? WHERE id = ?', 
                  [temp_login['ip_address'], datetime.utcnow().isoformat(), user_id])
        
        # Record successful login
        execute_db('INSERT INTO login_attempts (user_id, ip_address, success, timestamp) VALUES (?, ?, ?, ?)',
                  [user_id, temp_login['ip_address'], 1, datetime.utcnow().isoformat()])
        
        flash('Login successful. 2FA not configured on your account.', 'info')
        return redirect(url_for('dashboard'))
    
    if request.method == 'POST':
        otp_code = request.form.get('otp_code', '').strip()
        
        try:
            totp = pyotp.TOTP(user.get('twofa_secret'))
            if not totp.verify(otp_code):
                flash('Invalid OTP code. Please try again.', 'danger')
                return redirect(url_for('verify_otp_login'))
            
            # OTP verified - grant access
            session.clear()
            session['user_id'] = user_id
            session['username'] = user.get('username', '')
            session.permanent = True
            session['login_time'] = datetime.utcnow().timestamp()
            session['risk_level'] = temp_login['risk_level']
            session['risk_score'] = temp_login['risk_score']
            
            # Update trusted devices and last login
            if temp_login['device_fingerprint']:
                trusted_devices = []
                if user.get('trusted_devices'):
                    try:
                        trusted_devices = json.loads(user['trusted_devices'])
                    except:
                        trusted_devices = []
                if temp_login['device_fingerprint'] not in trusted_devices:
                    trusted_devices.append(temp_login['device_fingerprint'])
                execute_db('UPDATE users SET trusted_devices = ? WHERE id = ?', [json.dumps(trusted_devices[:10]), user_id])
            
            execute_db('UPDATE users SET last_login_ip = ?, last_successful_login = ? WHERE id = ?', 
                      [temp_login['ip_address'], datetime.utcnow().isoformat(), user_id])
            
            # Record successful login
            record_login_attempt(user_id, user.get('username', ''), temp_login['ip_address'], 
                               temp_login['risk_score'], temp_login['risk_level'], 
                               temp_login['risk_factors'], success=True, otp_verified=True)
            record_behavior(user_id, 'login', f'User logged in successfully via OTP (risk_level={temp_login["risk_level"]}, score={temp_login["risk_score"]})')
            
            flash('Login successful!', 'success')
            return redirect(url_for('dashboard'))
            
        except Exception as e:
            print(f"[ERROR] OTP verification failed: {e}")
            flash('OTP verification failed. Please try again.', 'danger')
            return redirect(url_for('verify_otp_login'))
    
    return render_template('verify_otp_login.html', risk_score=temp_login['risk_score'], risk_factors=temp_login['risk_factors'])


@app.route('/logout')
def logout():
    if 'user_id' in session:
        record_behavior(session['user_id'], 'logout', 'User logged out')
    session.clear()
    return redirect(url_for('login'))


@app.route('/dashboard')
@login_required
def dashboard():
    user = get_current_user()
    total_files_row = query_db('SELECT COUNT(*) AS count FROM files WHERE user_id = ?', [user['id']], one=True)
    total_files = dict(total_files_row)['count'] if total_files_row else 0
    total_notes_row = query_db('SELECT COUNT(*) AS count FROM notes WHERE user_id = ?', [user['id']], one=True)
    total_notes = dict(total_notes_row)['count'] if total_notes_row else 0
    recent_logs = query_db('SELECT * FROM behavior_logs WHERE user_id = ? ORDER BY timestamp DESC LIMIT 5', [user['id']])

    return render_template(
        'dashboard.html',
        user=user,
        total_files=total_files,
        total_notes=total_notes,
        recent_logs=recent_logs,
    )


@app.route('/profile', methods=['GET', 'POST'])
@login_required
def profile():
    user = get_current_user()
    if request.method == 'POST':
        name = request.form.get('name', '').strip()
        email = request.form.get('email', '').strip().lower()
        profile_picture = request.files.get('profile_picture')

        if profile_picture and profile_picture.filename:
            filename = secure_filename(profile_picture.filename)
            picture_path = os.path.join(app.config['UPLOAD_FOLDER'], f'profile_{user["id"]}_{filename}')
            profile_picture.save(picture_path)
            execute_db('UPDATE users SET profile_picture = ? WHERE id = ?', [picture_path, user['id']])

        execute_db('UPDATE users SET name = ?, email = ? WHERE id = ?', [name, email, user['id']])
        record_behavior(user['id'], 'profile_update', f'Updated profile name={name} email={email}')
        flash('Profile updated successfully.', 'success')
        return redirect(url_for('profile'))

    total_files_row = query_db('SELECT COUNT(*) AS count FROM files WHERE user_id = ?', [user['id']], one=True)
    total_files = dict(total_files_row)['count'] if total_files_row else 0
    total_notes_row = query_db('SELECT COUNT(*) AS count FROM notes WHERE user_id = ?', [user['id']], one=True)
    total_notes = dict(total_notes_row)['count'] if total_notes_row else 0
    recent_logs = query_db('SELECT * FROM behavior_logs WHERE user_id = ? ORDER BY timestamp DESC LIMIT 5', [user['id']])
    return render_template('dashboard.html', user=user, profile_active=True, total_files=total_files, total_notes=total_notes, recent_logs=recent_logs)


@app.route('/documents', methods=['GET', 'POST'])
@login_required
def documents():
    user = get_current_user()
    search = request.args.get('search', '').strip()
    query = 'SELECT * FROM files WHERE user_id = ?'
    params = [user['id']]
    if search:
        query += ' AND (filename LIKE ? OR tags LIKE ?)'
        params.append(f'%{search}%')
        params.append(f'%{search}%')

    files = query_db(query + ' ORDER BY uploaded_at DESC', params)

    if request.method == 'POST':
        uploaded_file = request.files.get('file')
        tags = request.form.get('tags', '').strip()
        if uploaded_file and uploaded_file.filename and allowed_file(uploaded_file.filename):
            filename = secure_filename(uploaded_file.filename)
            storage_name = f'{secrets.token_hex(16)}_{filename}'
            storage_path = os.path.join(app.config['UPLOAD_FOLDER'], storage_name)
            file_bytes = uploaded_file.read()
            encrypted_bytes = fernet.encrypt(file_bytes)
            with open(storage_path, 'wb') as out_file:
                out_file.write(encrypted_bytes)
            execute_db(
                'INSERT INTO files (user_id, filename, storage_name, tags) VALUES (?, ?, ?, ?)',
                [user['id'], filename, storage_name, tags],
            )
            record_behavior(user['id'], 'upload_file', f'Uploaded file {filename} tags={tags}')
            flash('File uploaded and encrypted successfully.', 'success')
            return redirect(url_for('documents'))

        flash('Please upload a supported file type.', 'warning')

    return render_template('dashboard.html', user=user, documents=files, documents_active=True, search=search)


@app.route('/download/<int:file_id>')
@login_required
def download(file_id):
    user = get_current_user()
    file_record_row = query_db('SELECT * FROM files WHERE id = ? AND user_id = ?', [file_id, user['id']], one=True)
    file_record = dict(file_record_row) if file_record_row else None
    if not file_record:
        flash('File not found.', 'danger')
        return redirect(url_for('documents'))

    storage_path = os.path.join(app.config['UPLOAD_FOLDER'], file_record['storage_name'])
    if not os.path.exists(storage_path):
        flash('Encrypted file missing.', 'danger')
        return redirect(url_for('documents'))

    with open(storage_path, 'rb') as input_file:
        encrypted_bytes = input_file.read()
    decrypted_bytes = fernet.decrypt(encrypted_bytes)
    record_behavior(user['id'], 'download_file', f'Downloaded file {file_record["filename"]}')

    return send_file(
        io.BytesIO(decrypted_bytes),
        download_name=file_record['filename'],
        as_attachment=True,
    )


@app.route('/delete_file/<int:file_id>', methods=['POST'])
@login_required
def delete_file(file_id):
    user = get_current_user()
    file_record_row = query_db('SELECT * FROM files WHERE id = ? AND user_id = ?', [file_id, user['id']], one=True)
    file_record = dict(file_record_row) if file_record_row else None
    if not file_record:
        flash('File not found.', 'danger')
        return redirect(url_for('documents'))

    storage_path = os.path.join(app.config['UPLOAD_FOLDER'], file_record['storage_name'])
    if os.path.exists(storage_path):
        os.remove(storage_path)

    execute_db('DELETE FROM files WHERE id = ?', [file_id])
    record_behavior(user['id'], 'delete_file', f'Deleted file {file_record["filename"]}')
    flash('File deleted successfully.', 'success')
    return redirect(url_for('documents'))


@app.route('/notes', methods=['GET', 'POST'])
@login_required
def notes():
    user = get_current_user()
    if request.method == 'POST':
        note_text = request.form.get('note_text', '').strip()
        if note_text:
            encrypted_note = encrypt_value(note_text)
            execute_db('INSERT INTO notes (user_id, content) VALUES (?, ?)', [user['id'], encrypted_note])
            record_behavior(user['id'], 'create_note', f'Created note length={len(note_text)}')
            flash('Secure note saved.', 'success')
            return redirect(url_for('notes'))
        flash('Note content cannot be blank.', 'warning')

    notes_rows = query_db('SELECT * FROM notes WHERE user_id = ? ORDER BY created_at DESC', [user['id']])
    decrypted_notes = []
    for row in notes_rows:
        try:
            decrypted_notes.append({
                'id': row['id'],
                'content': decrypt_value(row['content']),
                'created_at': row['created_at'],
            })
        except Exception:
            decrypted_notes.append({'id': row['id'], 'content': '[decrypt_error]', 'created_at': row['created_at']})

    return render_template('dashboard.html', user=user, notes=decrypted_notes, notes_active=True)


@app.route('/secure_shares')
@login_required
def secure_shares():
    user = get_current_user()
    record_behavior(user['id'], 'view_secure_shares', 'Viewed secure shares placeholder')
    return render_template('dashboard.html', user=user, secure_shares_active=True)


@app.route('/activity_logs')
@login_required
def activity_logs():
    user = get_current_user()
    log_type = request.args.get('type', '')
    search = request.args.get('search', '').strip()
    start_date = request.args.get('start_date', '')
    end_date = request.args.get('end_date', '')
    user_filter = request.args.get('user_filter', '')  # For admin view, but currently single user

    query = 'SELECT * FROM behavior_logs WHERE user_id = ?'
    params = [user['id']]
    if log_type:
        query += ' AND action = ?'
        params.append(log_type)
    if search:
        query += ' AND details LIKE ?'
        params.append(f'%{search}%')
    if start_date:
        query += ' AND timestamp >= ?'
        params.append(start_date)
    if end_date:
        query += ' AND timestamp <= ?'
        params.append(end_date)

    logs = query_db(query + ' ORDER BY timestamp DESC LIMIT 100', params)

    # Prepare chart data
    action_counts = {}
    daily_activity = {}
    for log in logs:
        # Action counts
        action = log['action']
        action_counts[action] = action_counts.get(action, 0) + 1
        
        # Daily activity
        date = log['timestamp'][:10]  # YYYY-MM-DD
        daily_activity[date] = daily_activity.get(date, 0) + 1

    chart_data = {
        'actions': [{'action': k, 'count': v} for k, v in action_counts.items()],
        'daily': [{'date': k, 'count': v} for k, v in sorted(daily_activity.items())]
    }

    if request.args.get('export') == 'csv':
        output = io.StringIO()
        writer = csv.writer(output)
        writer.writerow(['id', 'action', 'details', 'trust_score', 'timestamp'])
        for row in logs:
            writer.writerow([row['id'], row['action'], row['details'], row['trust_score'], row['timestamp']])
        output.seek(0)
        return send_file(
            io.BytesIO(output.getvalue().encode('utf-8')),
            download_name='activity_logs.csv',
            as_attachment=True,
            mimetype='text/csv',
        )

    return render_template('dashboard.html', user=user, logs=logs, chart_data=chart_data, activity_active=True)


@app.route('/trust_dashboard')
@login_required
def trust_dashboard():
    user = get_current_user()
    # Get trust score history for the last 30 days
    thirty_days_ago = (datetime.utcnow() - timedelta(days=30)).isoformat()
    trust_scores_rows = query_db(
        'SELECT trust_score, timestamp FROM behavior_logs WHERE user_id = ? AND trust_score IS NOT NULL AND timestamp >= ? ORDER BY timestamp ASC',
        [user['id'], thirty_days_ago]
    )
    
    # Convert Row objects to dictionaries for JSON serialization
    trust_scores = [dict(row) for row in trust_scores_rows] if trust_scores_rows else []
    
    # Calculate statistics
    trust_stats = {
        'avg_score': None,
        'min_score': None,
        'max_score': None,
        'total_readings': len(trust_scores)
    }
    
    if trust_scores:
        scores = [log['trust_score'] for log in trust_scores]
        trust_stats['avg_score'] = sum(scores) / len(scores)
        trust_stats['min_score'] = min(scores)
        trust_stats['max_score'] = max(scores)
    
    return render_template('dashboard.html', user=user, trust_scores=trust_scores, trust_stats=trust_stats, trust_dashboard_active=True)


@app.route('/vault_settings', methods=['GET', 'POST'])
@login_required
def vault_settings():
    user = get_current_user()
    # Convert Row to dict for safe access
    user_dict = dict(user) if user else {}
    
    if request.method == 'POST':
        action = request.form.get('action')
        if action == 'toggle_2fa':
            if user_dict.get('twofa_secret'):
                execute_db('UPDATE users SET twofa_secret = NULL WHERE id = ?', [user_dict['id']])
                flash('2FA disabled.', 'success')
            else:
                secret = generate_2fa_secret()
                execute_db('UPDATE users SET twofa_secret = ? WHERE id = ?', [secret, user_dict['id']])
                flash('2FA enabled. Scan the QR code below.', 'success')
        elif action == 'update_ips':
            allowed_ips = request.form.get('allowed_ips', '').strip()
            execute_db('UPDATE users SET allowed_ips = ? WHERE id = ?', [allowed_ips, user_dict['id']])
            flash('IP restrictions updated.', 'success')
        elif action == 'change_password':
            current = request.form.get('current_password')
            new_pass = request.form.get('new_password')
            confirm = request.form.get('confirm_password')
            if not verify_password(current, user_dict.get('password')):
                flash('Current password incorrect.', 'danger')
            elif new_pass != confirm:
                flash('New passwords do not match.', 'danger')
            else:
                execute_db('UPDATE users SET password = ? WHERE id = ?', [hash_password(new_pass), user_dict['id']])
                flash('Password changed.', 'success')
        record_behavior(user_dict['id'], 'update_vault_settings', f'Action: {action}')
        return redirect(url_for('vault_settings'))

    # Generate QR code URI for 2FA
    qr_uri = None
    if user_dict.get('twofa_secret'):
        totp = pyotp.TOTP(user_dict['twofa_secret'])
        qr_uri = totp.provisioning_uri(name=user_dict.get('email', ''), issuer_name='Secure Vault')

    return render_template('dashboard.html', user=user_dict, vault_settings_active=True, qr_uri=qr_uri)


@app.route('/log_behavior', methods=['POST', 'GET'])
@login_required
def log_behavior():
    user = get_current_user()
    if request.method == 'POST':
        payload = request.get_json(force=True, silent=True) or {}
        action = payload.get('action', 'unknown')
        details = payload.get('details', '')
        feature_vector = payload.get('featureVector', [])

        # Initialize response
        trust_score = 50
        anomaly_detected = False
        detection_method = 'none'

        # If we have a feature vector, perform ML anomaly detection
        if isinstance(feature_vector, list) and len(feature_vector) >= 5:
            is_anomaly, score, method = detect_anomaly_ml(user['id'], feature_vector)
            trust_score = int(score)
            detection_method = method
            anomaly_detected = is_anomaly
            
            print(f"[ANOMALY DETECTION] User {user['username']}: anomaly={anomaly_detected}, score={trust_score}, method={method}")
            
            # Record this behavior with ML results
            record_behavior(
                user['id'],
                'behavior_analysis',
                f'action={action} method={method}',
                trust_score=trust_score,
                feature_vector=feature_vector,
                is_anomaly=1 if anomaly_detected else 0,
                anomaly_score=score
            )
            
            # If anomaly detected, send alert and force logout
            if anomaly_detected:
                record_behavior(
                    user['id'],
                    'anomaly_detected',
                    f'Suspicious behavior detected via {method}. Score: {trust_score}',
                    trust_score=0,
                    is_anomaly=1,
                    anomaly_score=score
                )
                print(f"[ALERT] Anomaly detected for user {user['username']} (score: {trust_score}, method: {method})")
                send_anomaly_alert(
                    user['email'],
                    user['username'],
                    f"Anomalous behavior detected: {method} (Trust score: {trust_score}/100)"
                )
                session.clear()
                return jsonify({
                    'status': 'logout',
                    'trustScore': 0,
                    'anomaly': True,
                    'method': method,
                    'message': 'Anomalous behavior detected. Session terminated for security.'
                }), 401
        else:
            # No feature vector, just record the action
            record_behavior(user['id'], action, details, trust_score=trust_score)
        
        return jsonify({
            'status': 'ok',
            'trustScore': trust_score,
            'anomaly': anomaly_detected,
            'method': detection_method
        })

    # GET request: return behavior logs with parsed features
    logs = query_db('SELECT * FROM behavior_logs WHERE user_id = ? ORDER BY timestamp DESC LIMIT 100', [user['id']])
    logs_list = []
    for log in logs:
        log_dict = dict(log)
        # Parse features if present
        if log_dict.get('features'):
            try:
                log_dict['features'] = json.loads(log_dict['features'])
            except:
                pass
        logs_list.append(log_dict)
    return jsonify(logs_list)


@app.route('/reset_password/<token>', methods=['GET', 'POST'])
def reset_password(token):
    user_row = query_db('SELECT * FROM users WHERE reset_token = ?', [token], one=True)
    user = dict(user_row) if user_row else None
    if not user or not user.get('reset_expires') or datetime.utcnow() > datetime.fromisoformat(user.get('reset_expires', '')):
        flash('Invalid or expired token.', 'danger')
        return redirect(url_for('login'))

    if request.method == 'POST':
        password = request.form.get('password')
        confirm = request.form.get('confirm_password')
        if password != confirm:
            flash('Passwords do not match.', 'warning')
        else:
            execute_db('UPDATE users SET password = ?, reset_token = NULL, reset_expires = NULL WHERE id = ?', [hash_password(password), user.get('id')])
            flash('Password reset successfully.', 'success')
            return redirect(url_for('login'))
    return render_template('reset_password.html')


@app.route('/forgot_password', methods=['GET', 'POST'])
def forgot_password():
    if request.method == 'POST':
        email = request.form.get('email', '').strip().lower()
        user_row = query_db('SELECT * FROM users WHERE email = ?', [email], one=True)
        user = dict(user_row) if user_row else None
        if user:
            token = secrets.token_urlsafe(32)
            expires = datetime.utcnow() + timedelta(hours=1)
            execute_db('UPDATE users SET reset_token = ?, reset_expires = ? WHERE id = ?', [token, expires.isoformat(), user.get('id')])
            send_reset_email(email, token)
            flash('Password reset email sent.', 'success')
        else:
            flash('Email not found.', 'warning')
        return redirect(url_for('login'))
    return render_template('forgot_password.html')


if __name__ == '__main__':
    init_db()
    app.run(debug=True)
