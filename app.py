from flask import Flask, render_template, request, jsonify, redirect, url_for, session
from flask_cors import CORS
from werkzeug.security import generate_password_hash, check_password_hash
import os
import re
import random
import string
from datetime import datetime, timedelta, timezone
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import logging
from pymongo import MongoClient
from pymongo.errors import ConnectionFailure, DuplicateKeyError, ServerSelectionTimeoutError
from bson import ObjectId
import json
from dotenv import load_dotenv
from authlib.integrations.flask_client import OAuth
import requests
from functools import wraps
import ssl  # Added for MongoDB SSL

load_dotenv()

# Custom JSON encoder to handle ObjectId and datetime
class JSONEncoder(json.JSONEncoder):
    def default(self, o):
        if isinstance(o, ObjectId):
            return str(o)
        if isinstance(o, datetime):
            return o.isoformat()
        return json.JSONEncoder.default(self, o)

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY', 'acupressor-pro-secret-key-2024-render-deploy')
app.config.update(
    SESSION_COOKIE_SECURE=True,
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE='Lax',
    PERMANENT_SESSION_LIFETIME=timedelta(hours=8)
)
app.json_encoder = JSONEncoder
CORS(app)

# Security headers configuration
@app.after_request
def add_security_headers(response):
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
    return response

# OAuth Configuration
oauth = OAuth(app)
google = oauth.register(
    name='google',
    client_id=os.environ.get('GOOGLE_CLIENT_ID'),
    client_secret=os.environ.get('GOOGLE_CLIENT_SECRET'),
    server_metadata_url='https://accounts.google.com/.well-known/openid-configuration',
    client_kwargs={
        'scope': 'openid email profile',
        'prompt': 'select_account',
    },
)

# MongoDB configuration from .env
MONGODB_URI = os.environ.get('MONGODB_URI', 'mongodb://localhost:27017/acupressure_db')
DB_NAME = os.environ.get('DB_NAME', 'acupressure_db')

# Initialize MongoDB connection with enhanced error handling
db_connected = False
client = None
db = None

def init_mongodb_connection():
    global client, db, db_connected
    
    try:
        logger.info(f"🔗 Attempting to connect to MongoDB: {DB_NAME}")
        
        # Enhanced MongoDB Atlas connection with better error handling
        connection_params = {
            'serverSelectionTimeoutMS': 30000,  # 30 seconds timeout
            'connectTimeoutMS': 30000,
            'socketTimeoutMS': 30000,
            'retryWrites': True,
            'w': 'majority',
            'maxPoolSize': 50,
            'minPoolSize': 10,
            'tls': True,  # Required for Atlas
            'tlsAllowInvalidCertificates': True  # For Atlas TLS
        }
        
        # Parse and validate the connection string
        mongodb_uri = MONGODB_URI
        
        # Ensure the connection string includes the database name
        if 'retryWrites' not in mongodb_uri:
            if '?' in mongodb_uri:
                mongodb_uri += '&retryWrites=true&w=majority'
            else:
                mongodb_uri += '?retryWrites=true&w=majority'
        
        # Log connection details (without password)
        safe_uri = mongodb_uri.split('@')[1] if '@' in mongodb_uri else mongodb_uri
        logger.info(f"📡 Using MongoDB URI: {safe_uri}")
        
        client = MongoClient(mongodb_uri, **connection_params)
        
        # Test connection with more detailed information
        server_info = client.admin.command('ismaster')
        db = client[DB_NAME]
        
        # Perform a simple operation to verify connection
        db.command('ping')
        
        db_connected = True
        
        logger.info(f"✅ Successfully connected to MongoDB Atlas!")
        logger.info(f"📊 Database: {DB_NAME}")
        logger.info(f"🔌 Host: {server_info.get('hosts', ['Unknown'])}")
        logger.info(f"⚡ MongoDB Version: {server_info.get('version', 'Unknown')}")
        
        return True
        
    except ServerSelectionTimeoutError as e:
        logger.error(f"❌ MongoDB connection timeout: {str(e)}")
        logger.error("💡 Tip: Check your internet connection and MongoDB Atlas cluster status")
        logger.error("💡 Tip: Ensure your IP is whitelisted in MongoDB Atlas network settings")
    except Exception as e:
        logger.error(f"❌ MongoDB connection failed: {str(e)}")
        
        # Provide specific troubleshooting tips
        error_str = str(e).lower()
        if "authentication failed" in error_str:
            logger.error("💡 Tip: Check your MongoDB Atlas username and password")
            logger.error("💡 Tip: Ensure the user has proper permissions")
        elif "getaddrinfo" in error_str or "dns" in error_str:
            logger.error("💡 Tip: Check your internet connection and DNS resolution")
        elif "timed out" in error_str:
            logger.error("💡 Tip: Check if your IP is whitelisted in MongoDB Atlas network settings")
        elif "bad auth" in error_str:
            logger.error("💡 Tip: Authentication failed - verify username/password")
        elif "ssl" in error_str:
            logger.error("💡 Tip: SSL connection issue - check firewall/proxy settings")
        
    db_connected = False
    return False

# Initialize MongoDB connection
if not init_mongodb_connection():
    logger.warning("⚠️ Running in demo mode without database connection")

def check_db_health():
    """Check if database connection is healthy"""
    global db_connected, client, db
    
    if client is None:
        return False
    
    try:
        # Simple ping to check connection
        client.admin.command('ping')
        if not db_connected:
            logger.info("✅ MongoDB connection restored")
            db_connected = True
        return True
    except Exception as e:
        if db_connected:
            logger.warning(f"⚠️ MongoDB connection lost: {e}")
        db_connected = False
        return False

def get_db():
    """Get database instance with health check"""
    if not check_db_health():
        return None
    return db

def get_db_safe():
    """Safe get database instance for operations"""
    db = get_db()
    return db if db is not None else None

def is_db_connected():
    """Check if database is connected"""
    return check_db_health()

# Enhanced predefined users with doctor specialization mapping
PREDEFINED_USERS = {
    'admin': {
        'user_id': 'ADM001',
        'email': 'admin@dsvv.ac.in',
        'password': 'Admin@123',
        'first_name': 'System',
        'last_name': 'Administrator',
        'role': 'admin'
    },
    'receptionist': {
        'user_id': 'REC001',
        'email': 'reception@dsvv.ac.in',
        'password': 'Reception@123',
        'first_name': 'Reception',
        'last_name': 'Desk',
        'role': 'receptionist'
    },
    # Doctors mapped to specific therapies
    'doctor_acupressure': {
        'user_id': 'DOC001',
        'email': 'dr.sharma@dsvv.ac.in',
        'password': 'Doctor@123',
        'first_name': 'Rajesh',
        'last_name': 'Sharma',
        'role': 'doctor',
        'specialization': 'Acupressure Specialist',
        'therapy_type': 'acupressure'
    },
    'doctor_ayurveda': {
        'user_id': 'DOC002',
        'email': 'dr.gupta@dsvv.ac.in',
        'password': 'Doctor@123',
        'first_name': 'Priya',
        'last_name': 'Gupta',
        'role': 'doctor',
        'specialization': 'Ayurveda Expert',
        'therapy_type': 'ayurveda'
    },
    'doctor_homeopathy': {
        'user_id': 'DOC003',
        'email': 'dr.verma@dsvv.ac.in',
        'password': 'Doctor@123',
        'first_name': 'Amit',
        'last_name': 'Verma',
        'role': 'doctor',
        'specialization': 'Homeopathy Specialist',
        'therapy_type': 'homeopathy'
    },
    'doctor_naturopathy': {
        'user_id': 'DOC004',
        'email': 'dr.patel@dsvv.ac.in',
        'password': 'Doctor@123',
        'first_name': 'Sunita',
        'last_name': 'Patel',
        'role': 'doctor',
        'specialization': 'Naturopathy Doctor',
        'therapy_type': 'naturopathy'
    },
    'doctor_yoga': {
        'user_id': 'DOC005',
        'email': 'dr.kumar@dsvv.ac.in',
        'password': 'Doctor@123',
        'first_name': 'Ravi',
        'last_name': 'Kumar',
        'role': 'doctor',
        'specialization': 'Yoga Master',
        'therapy_type': 'yoga'
    },
    'doctor_unani': {
        'user_id': 'DOC006',
        'email': 'dr.singh@dsvv.ac.in',
        'password': 'Doctor@123',
        'first_name': 'Anjali',
        'last_name': 'Singh',
        'role': 'doctor',
        'specialization': 'Unani Specialist',
        'therapy_type': 'unani'
    },
    'doctor_chiropractic': {
        'user_id': 'DOC007',
        'email': 'dr.joshi@dsvv.ac.in',
        'password': 'Doctor@123',
        'first_name': 'Deepak',
        'last_name': 'Joshi',
        'role': 'doctor',
        'specialization': 'Chiropractic Expert',
        'therapy_type': 'chiropractic'
    },
    'doctor_physiotherapy': {
        'user_id': 'DOC008',
        'email': 'dr.sharma2@dsvv.ac.in',
        'password': 'Doctor@123',
        'first_name': 'Neha',
        'last_name': 'Sharma',
        'role': 'doctor',
        'specialization': 'Physiotherapist',
        'therapy_type': 'physiotherapy'
    },
    'doctor_diet': {
        'user_id': 'DOC009',
        'email': 'dr.malhotra@dsvv.ac.in',
        'password': 'Doctor@123',
        'first_name': 'Sanjay',
        'last_name': 'Malhotra',
        'role': 'doctor',
        'specialization': 'Nutritionist',
        'therapy_type': 'diet'
    },
    'doctor_herbal': {
        'user_id': 'DOC010',
        'email': 'dr.reddy@dsvv.ac.in',
        'password': 'Doctor@123',
        'first_name': 'Meera',
        'last_name': 'Reddy',
        'role': 'doctor',
        'specialization': 'Herbal Medicine Expert',
        'therapy_type': 'herbal'
    },
    'doctor_sound': {
        'user_id': 'DOC011',
        'email': 'dr.desai@dsvv.ac.in',
        'password': 'Doctor@123',
        'first_name': 'Arun',
        'last_name': 'Desai',
        'role': 'doctor',
        'specialization': 'Sound Healing Therapist',
        'therapy_type': 'sound'
    }
}

# Therapy to Doctor mapping
THERAPY_DOCTOR_MAPPING = {
    'acupressure': 'DOC001',
    'ayurveda': 'DOC002',
    'homeopathy': 'DOC003',
    'naturopathy': 'DOC004',
    'yoga': 'DOC005',
    'unani': 'DOC006',
    'chiropractic': 'DOC007',
    'physiotherapy': 'DOC008',
    'diet': 'DOC009',
    'herbal': 'DOC010',
    'sound': 'DOC011'
}

# Email configuration
EMAIL_CONFIG = {
    'smtp_server': os.environ.get('EMAIL_SMTP_SERVER', 'smtp.gmail.com'),
    'smtp_port': int(os.environ.get('EMAIL_SMTP_PORT', 587)),
    'sender_email': os.environ.get('EMAIL_SENDER', ''),
    'sender_password': os.environ.get('EMAIL_PASSWORD', '')
}

DEMO_AUTO_VERIFY = os.environ.get('DEMO_AUTO_VERIFY', 'true').lower() in ('1', 'true', 'yes')

EMAIL_REGEX = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'

# Security decorators
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not check_session():
            return redirect(url_for('index'))
        return f(*args, **kwargs)
    return decorated_function

def role_required(required_roles):
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if not check_session():
                return redirect(url_for('index'))
            if session.get('role') not in required_roles:
                return jsonify({'error': 'Insufficient permissions'}), 403
            return f(*args, **kwargs)
        return decorated_function
    return decorator

def validate_email(email):
    return re.match(EMAIL_REGEX, email) is not None

def validate_password(password):
    if len(password) < 8:
        return False, "Password must be at least 8 characters long"
    if not re.search(r'[A-Z]', password):
        return False, "Password must contain at least one uppercase letter"
    if not re.search(r'[a-z]', password):
        return False, "Password must contain at least one lowercase letter"
    if not re.search(r'\d', password):
        return False, "Password must contain at least one number"
    if not re.search(r'[!@#$%^&*(),.?":{}|<>]', password):
        return False, "Password must contain at least one special character"
    return True, "Password is valid"

def generate_otp():
    return ''.join(random.choices(string.digits, k=6))

def send_otp_email(email, otp):
    try:
        sender = EMAIL_CONFIG.get('sender_email')
        password = EMAIL_CONFIG.get('sender_password')

        subject = "Your AcuPressor Pro OTP"
        body = f"Your verification code is: {otp}\nThis code will expire in 10 minutes."

        if sender is None or password is None:
            logger.info(f"📧 (Console fallback) OTP for {email}: {otp}")
            return True

        msg = MIMEMultipart()
        msg['From'] = sender
        msg['To'] = email
        msg['Subject'] = subject
        msg.attach(MIMEText(body, 'plain'))

        server = smtplib.SMTP(EMAIL_CONFIG.get('smtp_server', 'smtp.gmail.com'), EMAIL_CONFIG.get('smtp_port', 587))
        server.ehlo()
        server.starttls()
        server.ehlo()
        server.login(sender, password)
        server.sendmail(sender, [email], msg.as_string())
        server.quit()

        logger.info(f"📧 OTP sent to {email} via SMTP")
        return True

    except smtplib.SMTPAuthenticationError as auth_err:
        logger.error(f"SMTP auth error sending email: {auth_err}")
        logger.info(f"📧 (Fallback) OTP for {email}: {otp}")
        return False
    except Exception as e:
        logger.error(f"Error sending email: {e}")
        logger.info(f"📧 (Fallback) OTP for {email}: {otp}")
        return False

def send_password_reset_otp_email(email, otp):
    """Send password reset OTP email"""
    try:
        sender = EMAIL_CONFIG.get('sender_email')
        password = EMAIL_CONFIG.get('sender_password')

        subject = "Password Reset OTP - DCAM Therapy Center"
        body = f"""
Dear User,

You have requested to reset your password for your DCAM Therapy Center account.

Your password reset OTP is: {otp}

This OTP will expire in 10 minutes. If you did not request this password reset, please ignore this email or contact our support team immediately.

For security reasons:
- Do not share this OTP with anyone
- Our team will never ask for your OTP
- This OTP is valid for one-time use only

If you have any questions, please contact our support team.

Best regards,
DCAM Team
Dev Sanskriti Vishwavidyalaya
        """

        if sender is None or password is None:
            logger.info(f"📧 (Console fallback) Password reset OTP for {email}: {otp}")
            return True

        msg = MIMEMultipart()
        msg['From'] = sender
        msg['To'] = email
        msg['Subject'] = subject
        msg.attach(MIMEText(body, 'plain'))

        server = smtplib.SMTP(EMAIL_CONFIG.get('smtp_server', 'smtp.gmail.com'), EMAIL_CONFIG.get('smtp_port', 587))
        server.ehlo()
        server.starttls()
        server.ehlo()
        server.login(sender, password)
        server.sendmail(sender, [email], msg.as_string())
        server.quit()

        logger.info(f"📧 Password reset OTP sent to {email}")
        return True

    except Exception as e:
        logger.error(f"Error sending password reset OTP email: {e}")
        logger.info(f"📧 (Fallback) Password reset OTP for {email}: {otp}")
        return False

def send_appointment_confirmation_email(patient_email, patient_name, appointment_date, therapy_name, doctor_name):
    """Send appointment confirmation email to patient"""
    try:
        sender = EMAIL_CONFIG.get('sender_email')
        password = EMAIL_CONFIG.get('sender_password')

        subject = f"Appointment Confirmation - {therapy_name}"
        body = f"""
Dear {patient_name},

Your appointment has been confirmed!

Appointment Details:
- Therapy: {therapy_name}
- Doctor: {doctor_name}
- Date & Time: {appointment_date}
- Status: Confirmed

Please arrive 10 minutes before your scheduled time.

Thank you for choosing DCAM Therapy Center.

Best regards,
DCAM Team
Dev Sanskriti Vishwavidyalaya
        """

        if sender is None or password is None:
            logger.info(f"📧 (Console fallback) Appointment confirmation for {patient_email}")
            return True

        msg = MIMEMultipart()
        msg['From'] = sender
        msg['To'] = patient_email
        msg['Subject'] = subject
        msg.attach(MIMEText(body, 'plain'))

        server = smtplib.SMTP(EMAIL_CONFIG.get('smtp_server', 'smtp.gmail.com'), EMAIL_CONFIG.get('smtp_port', 587))
        server.ehlo()
        server.starttls()
        server.ehlo()
        server.login(sender, password)
        server.sendmail(sender, [patient_email], msg.as_string())
        server.quit()

        logger.info(f"📧 Appointment confirmation sent to {patient_email}")
        return True

    except Exception as e:
        logger.error(f"Error sending appointment confirmation email: {e}")
        return False

def send_doctor_notification_email(doctor_email, doctor_name, patient_name, appointment_date, therapy_name):
    """Send appointment notification to doctor"""
    try:
        sender = EMAIL_CONFIG.get('sender_email')
        password = EMAIL_CONFIG.get('sender_password')

        subject = f"New Appointment - {therapy_name}"
        body = f"""
Dear Dr. {doctor_name},

You have a new appointment scheduled:

Patient: {patient_name}
Therapy: {therapy_name}
Date & Time: {appointment_date}

Please review the patient details in your dashboard.

Best regards,
DCAM Administration
        """

        if sender is None or password is None:
            logger.info(f"📧 (Console fallback) Doctor notification for {doctor_email}")
            return True

        msg = MIMEMultipart()
        msg['From'] = sender
        msg['To'] = doctor_email
        msg['Subject'] = subject
        msg.attach(MIMEText(body, 'plain'))

        server = smtplib.SMTP(EMAIL_CONFIG.get('smtp_server', 'smtp.gmail.com'), EMAIL_CONFIG.get('smtp_port', 587))
        server.ehlo()
        server.starttls()
        server.ehlo()
        server.login(sender, password)
        server.sendmail(sender, [doctor_email], msg.as_string())
        server.quit()

        logger.info(f"📧 Doctor notification sent to {doctor_email}")
        return True

    except Exception as e:
        logger.error(f"Error sending doctor notification email: {e}")
        return False

def generate_patient_id():
    current_db = get_db_safe()
    if current_db is None:
        return f"PAT{random.randint(1000, 9999)}"
    
    try:
        last_patient = current_db.users.find_one(
            {'role': 'patient'}, 
            sort=[('user_id', -1)]
        )
        if last_patient and last_patient.get('user_id', '').startswith('PAT'):
            last_num = int(last_patient['user_id'][3:])
            return f"PAT{last_num + 1:04d}"
        else:
            return "PAT0001"
    except Exception as e:
        logger.error(f"Error generating patient ID: {e}")
        return f"PAT{random.randint(1000, 9999)}"

def generate_doctor_id():
    current_db = get_db_safe()
    if current_db is None:
        return f"DOC{random.randint(100, 999)}"
    
    try:
        last_doctor = current_db.users.find_one(
            {'role': 'doctor'}, 
            sort=[('user_id', -1)]
        )
        if last_doctor and last_doctor.get('user_id', '').startswith('DOC'):
            last_num = int(last_doctor['user_id'][3:])
            return f"DOC{last_num + 1:03d}"
        else:
            return "DOC001"
    except Exception as e:
        logger.error(f"Error generating doctor ID: {e}")
        return f"DOC{random.randint(100, 999)}"

def generate_receptionist_id():
    current_db = get_db_safe()
    if current_db is None:
        return f"REC{random.randint(100, 999)}"
    
    try:
        last_receptionist = current_db.users.find_one(
            {'role': 'receptionist'}, 
            sort=[('user_id', -1)]
        )
        if last_receptionist and last_receptionist.get('user_id', '').startswith('REC'):
            last_num = int(last_receptionist['user_id'][3:])
            return f"REC{last_num + 1:03d}"
        else:
            return "REC001"
    except Exception as e:
        logger.error(f"Error generating receptionist ID: {e}")
        return f"REC{random.randint(100, 999)}"

def init_database():
    """Initialize MongoDB collections and indexes"""
    current_db = get_db_safe()
    if current_db is None:
        logger.error("❌ MongoDB not connected - cannot initialize database")
        return False
    
    try:
        # Create collections if they don't exist
        collections = current_db.list_collection_names()
        logger.info(f"📊 Existing collections: {collections}")
        
        # Define required collections and their indexes - FIXED STRUCTURE
        required_collections = {
            'users': [
                {'keys': [('user_id', 1)], 'options': {'unique': True}},
                {'keys': [('email', 1)], 'options': {'unique': True}},
                {'keys': [('role', 1)], 'options': {}}
            ],
            'appointments': [
                {'keys': [('appointment_id', 1)], 'options': {'unique': True}},
                {'keys': [('patient_id', 1)], 'options': {}},
                {'keys': [('therapist_id', 1)], 'options': {}},
                {'keys': [('date', 1)], 'options': {}}
            ],
            'therapy_sessions': [
                {'keys': [('session_id', 1)], 'options': {'unique': True}},
                {'keys': [('patient_id', 1)], 'options': {}},
                {'keys': [('therapist_id', 1)], 'options': {}}
            ],
            'otp_verification': [
                {'keys': [('email', 1)], 'options': {}},
                {'keys': [('created_at', 1)], 'options': {'expireAfterSeconds': 600}}
            ],
            'notifications': [
                {'keys': [('user_id', 1)], 'options': {}},
                {'keys': [('created_at', -1)], 'options': {}}
            ],
            'payments': [
                {'keys': [('payment_id', 1)], 'options': {'unique': True}},
                {'keys': [('appointment_id', 1)], 'options': {}},
                {'keys': [('patient_id', 1)], 'options': {}}
            ]
        }
        
        for collection_name, indexes in required_collections.items():
            if collection_name not in collections:
                current_db.create_collection(collection_name)
                logger.info(f"✅ Created collection: {collection_name}")
            
            # Create indexes with corrected structure
            for index_config in indexes:
                try:
                    keys = index_config['keys']
                    options = index_config['options']
                    current_db[collection_name].create_index(keys, **options)
                    logger.info(f"✅ Created index for {collection_name}: {keys}")
                except Exception as e:
                    logger.warning(f"⚠️ Could not create index for {collection_name}: {e}")
        
        # Insert predefined users
        users_created = 0
        for user_key, user_data in PREDEFINED_USERS.items():
            try:
                existing_user = current_db.users.find_one({'user_id': user_data['user_id']})
                if not existing_user:
                    user_doc = {
                        'user_id': user_data['user_id'],
                        'email': user_data['email'],
                        'password': generate_password_hash(user_data['password']),
                        'first_name': user_data['first_name'],
                        'last_name': user_data['last_name'],
                        'role': user_data['role'],
                        'specialization': user_data.get('specialization'),
                        'therapy_type': user_data.get('therapy_type'),
                        'is_predefined': True,
                        'is_active': True,
                        'email_verified': True,
                        'last_login': None,
                        'created_at': datetime.utcnow(),
                        'updated_at': datetime.utcnow()
                    }
                    current_db.users.insert_one(user_doc)
                    users_created += 1
                    logger.info(f"✅ Created predefined user: {user_data['user_id']}")
                else:
                    logger.info(f"ℹ️ Predefined user already exists: {user_data['user_id']}")
            except DuplicateKeyError:
                logger.warning(f"⚠️ Duplicate user detected: {user_data['user_id']}")
            except Exception as e:
                logger.error(f"❌ Error creating user {user_data['user_id']}: {e}")
        
        logger.info(f"🎉 Database initialization completed! Created {users_created} predefined users")
        return True
        
    except Exception as e:
        logger.error(f"❌ Database initialization error: {e}")
        return False

# Initialize database
if db_connected:
    init_database()
else:
    logger.warning("⚠️ Running in demo mode without database")

def get_dashboard_stats(role, user_id):
    """Get dashboard statistics based on user role"""
    stats = {}
    
    current_db = get_db_safe()
    if current_db is None:
        # Return demo stats if no database
        demo_stats = {
            'admin': {'total_users': 12, 'total_patients': 0, 'total_doctors': 11, 'total_appointments': 0},
            'doctor': {'todays_appointments': 0, 'total_patients': 0, 'completed_sessions': 0},
            'patient': {'upcoming_appointments': 0, 'completed_sessions': 0},
            'receptionist': {'todays_appointments': 0, 'pending_registrations': 0}
        }
        return demo_stats.get(role, {})
    
    try:
        today_start = datetime.now(timezone.utc).replace(hour=0, minute=0, second=0, microsecond=0)
        today_end = today_start + timedelta(days=1)
        
        if role == 'admin':
            stats['total_users'] = current_db.users.count_documents({})
            stats['total_patients'] = current_db.users.count_documents({'role': 'patient'})
            stats['total_doctors'] = current_db.users.count_documents({'role': 'doctor'})
            stats['total_appointments'] = current_db.appointments.count_documents({})
            stats['today_appointments'] = current_db.appointments.count_documents({
                'date': {'$gte': today_start, '$lt': today_end}
            })
            
        elif role == 'doctor':
            stats['todays_appointments'] = current_db.appointments.count_documents({
                'therapist_id': user_id,
                'date': {'$gte': today_start, '$lt': today_end},
                'status': 'scheduled'
            })
            
            stats['total_patients'] = len(current_db.appointments.distinct('patient_id', {'therapist_id': user_id}))
            stats['completed_sessions'] = current_db.therapy_sessions.count_documents({'therapist_id': user_id})
            stats['pending_appointments'] = current_db.appointments.count_documents({
                'therapist_id': user_id,
                'status': 'scheduled'
            })
            
        elif role == 'patient':
            stats['upcoming_appointments'] = current_db.appointments.count_documents({
                'patient_id': user_id,
                'status': 'scheduled'
            })
            
            stats['completed_sessions'] = current_db.therapy_sessions.count_documents({'patient_id': user_id})
            stats['total_appointments'] = current_db.appointments.count_documents({'patient_id': user_id})
            
        elif role == 'receptionist':
            stats['todays_appointments'] = current_db.appointments.count_documents({
                'date': {'$gte': today_start, '$lt': today_end}
            })
            
            stats['pending_registrations'] = current_db.users.count_documents({'is_active': False})
            stats['total_patients'] = current_db.users.count_documents({'role': 'patient'})
            stats['total_doctors'] = current_db.users.count_documents({'role': 'doctor'})
            
    except Exception as e:
        logger.error(f"Error getting dashboard stats: {e}")
    
    return stats

def create_notification(user_id, title, message, notification_type='info'):
    """Create a notification for a user"""
    current_db = get_db_safe()
    if current_db is None:
        logger.info(f"📢 [DEMO] Notification for {user_id}: {title} - {message}")
        return None
    
    try:
        notification_doc = {
            'user_id': user_id,
            'title': title,
            'message': message,
            'type': notification_type,
            'is_read': False,
            'created_at': datetime.now(timezone.utc)
        }
        result = current_db.notifications.insert_one(notification_doc)
        
        # Log notification for debugging
        logger.info(f"📢 Notification sent to {user_id}: {title} - {message}")
        
        return str(result.inserted_id)
    except Exception as e:
        logger.error(f"Error creating notification: {e}")
        return None

def check_session():
    """Enhanced session check with security validation"""
    if 'user_id' in session and 'email' in session and 'role' in session:
        # Additional security: Check if session is not too old
        login_time = session.get('login_time', None)
        now_utc = datetime.now(timezone.utc)
        if login_time is not None:
            # If login_time is naive, make it aware (assume UTC)
            if login_time.tzinfo is None:
                login_time = login_time.replace(tzinfo=timezone.utc)
            session_age = now_utc - login_time
        else:
            session_age = timedelta(0)
        if session_age > timedelta(hours=8):  # 8 hour session limit
            session.clear()
            return False
        logger.info(f"🔍 Session check: User {session['user_id']} ({session['email']}) - Role: {session['role']}")
        return True
    else:
        logger.info("🔍 Session check: No valid session")
        return False

@app.before_request
def before_request():
    """Enhanced security before each request"""
    # Skip for static files and auth endpoints
    if request.endpoint and not request.endpoint.startswith('static'):
        protected_routes = [
            'dashboard', 'book_appointment', 'acupressure_info', 
            'dashboard_data', 'get_therapists', 'patient_info', 
            'patient_data', 'appointment_receipt', 'get_appointments',
            'notifications', 'logout', 'receptionist_dashboard',
            'create_payment', 'payment_success', 'payment_cancel'
        ]
        
        if request.endpoint in protected_routes and not check_session():
            return redirect(url_for('index'))

# Payment configuration
PAYMENT_CONFIG = {
    'stripe_secret_key': os.environ.get('STRIPE_SECRET_KEY', 'sk_test_...'),
    'stripe_public_key': os.environ.get('STRIPE_PUBLIC_KEY', 'pk_test_...'),
    'currency': 'INR',
    'therapy_prices': {
        'acupressure': 1500,
        'ayurveda': 1200,
        'homeopathy': 800,
        'naturopathy': 1000,
        'yoga': 600,
        'unani': 900,
        'chiropractic': 2000,
        'physiotherapy': 1500,
        'diet': 700,
        'herbal': 800,
        'sound': 1200
    }
}

@app.route('/')
def index():
    if 'user_id' in session and request.args.get('logout') != 'true':
        return redirect(url_for('dashboard'))
    return render_template('index.html')

# Google OAuth Routes
@app.route('/google-login')
def google_login():
    try:
        redirect_uri = url_for('google_callback', _external=True)
        return google.authorize_redirect(redirect_uri)
    except Exception as e:
        logger.error(f"Google OAuth error: {e}")
        return redirect(url_for('index'))

@app.route('/google-callback')
def google_callback():
    try:
        token = google.authorize_access_token()
        user_info = token.get('userinfo')
        
        if not user_info:
            return redirect(url_for('index'))
        
        email = user_info['email']
        first_name = user_info.get('given_name', '')
        last_name = user_info.get('family_name', '')
        
        # Check if user exists
        current_db = get_db_safe()
        user = None
        
        if current_db is not None:
            user = current_db.users.find_one({'email': email})
        
        if not user:
            # Create new patient user with Google OAuth
            user_id = generate_patient_id()
            user_doc = {
                'user_id': user_id,
                'email': email,
                'first_name': first_name,
                'last_name': last_name,
                'role': 'patient',
                'patient_id': user_id,
                'is_predefined': False,
                'is_active': True,
                'email_verified': True,
                'auth_provider': 'google',
                'last_login': datetime.utcnow(),
                'created_at': datetime.utcnow(),
                'updated_at': datetime.utcnow()
            }
            
            if current_db is not None:
                current_db.users.insert_one(user_doc)
            
            user = user_doc
        else:
            # Update last login for existing user
            if current_db is not None:
                current_db.users.update_one(
                    {'user_id': user['user_id']},
                    {'$set': {'last_login': datetime.utcnow(), 'updated_at': datetime.utcnow()}}
                )
        
        # Set session with security timestamp
        session.clear()
        session['user_id'] = user['user_id']
        session['email'] = user['email']
        session['role'] = user['role']
        session['first_name'] = user['first_name']
        session['last_name'] = user['last_name']
        session['login_time'] = datetime.now(timezone.utc)
        
        if user['role'] == 'patient':
            session['patient_id'] = user.get('patient_id', user['user_id'])
        
        session.permanent = True
        session.modified = True
        
        logger.info(f"✅ Google OAuth login successful for {email}")
        return redirect(url_for('dashboard'))
        
    except Exception as e:
        logger.error(f"Google OAuth callback error: {e}")
        return redirect(url_for('index'))

# Password Reset Routes
@app.route('/forgot-password', methods=['POST'])
def forgot_password():
    """Send OTP for password reset"""
    try:
        data = request.get_json()
        email = data.get('email')
        
        if not email:
            return jsonify({'error': 'Email is required'}), 400
        
        if not validate_email(data['email']):
            return jsonify({'error': 'Invalid email format'}), 400
        
        # Check if user exists
        current_db = get_db_safe()
        user = None
        
        if current_db is not None:
            user = current_db.users.find_one({'email': data['email']})
        
        if not user:
            # For security, don't reveal if email exists or not
            logger.info(f"Password reset requested for non-existent email: {data['email']}")
            return jsonify({
                'message': 'If your email exists in our system, you will receive a password reset OTP shortly.'
            })
        
        # Generate OTP
        otp = generate_otp()
        
        # Remove existing OTPs for this email
        if current_db is not None:
            current_db.otp_verification.delete_many({
                'email': data['email'], 
                'purpose': 'password_reset'
            })
            
            # Store OTP for password reset
            otp_doc = {
                'email': data['email'],
                'otp': otp,
                'purpose': 'password_reset',
                'created_at': datetime.utcnow(),
                'expires_at': datetime.utcnow() + timedelta(minutes=10)
            }
            current_db.otp_verification.insert_one(otp_doc)
        
        # Send OTP email
        send_password_reset_otp_email(data['email'], otp)
        
        logger.info(f"📧 Password reset OTP sent to: {data['email']}")
        
        return jsonify({
            'message': 'Password reset OTP sent to your email',
            'email': data['email']
        })
        
    except Exception as e:
        logger.error(f"Error in forgot password: {e}")
        return jsonify({'error': 'Failed to process password reset request'}), 500

@app.route('/reset-password', methods=['POST'])
def reset_password():
    """Verify OTP and reset password"""
    try:
        data = request.get_json()
        email = data.get('email')
        otp = data.get('otp')
        new_password = data.get('new_password')
        confirm_password = data.get('confirm_password')
        
        if not email or not otp or not new_password or not confirm_password:
            return jsonify({'error': 'All fields are required'}), 400
        
        if new_password != confirm_password:
            return jsonify({'error': 'Passwords do not match'}), 400
        
        # Validate password strength
        is_valid, password_msg = validate_password(new_password)
        if not is_valid:
            return jsonify({'error': password_msg}), 400
        
        current_db = get_db_safe()
        if current_db is None:
            return jsonify({'error': 'Database not available. Please try again later.'}), 500
        
        # Find the OTP record
        otp_record = current_db.otp_verification.find_one({
            'email': email,
            'otp': otp,
            'purpose': 'password_reset',
            'expires_at': {'$gt': datetime.utcnow()}
        })
        
        if not otp_record:
            return jsonify({'error': 'Invalid or expired OTP'}), 400
        
        # Update user password
        hashed_password = generate_password_hash(new_password)
        result = current_db.users.update_one(
            {'email': email},
            {
                '$set': {
                    'password': hashed_password,
                    'updated_at': datetime.utcnow()
                }
            }
        )
        
        if result.modified_count == 0:
            return jsonify({'error': 'User not found'}), 404
        
        # Remove used OTP
        current_db.otp_verification.delete_one({'_id': otp_record['_id']})
        
        # Create notification
        user = current_db.users.find_one({'email': email})
        if user:
            create_notification(
                user['user_id'],
                'Password Reset Successful',
                'Your password has been reset successfully. If you did not initiate this change, please contact support immediately.',
                'warning'
            )
        
        logger.info(f"✅ Password reset successful for: {email}")
        
        return jsonify({'message': 'Password reset successfully! You can now login with your new password.'})
        
    except Exception as e:
        logger.error(f"Error resetting password: {e}")
        return jsonify({'error': 'Failed to reset password'}), 500

@app.route('/resend-password-reset-otp', methods=['POST'])
def resend_password_reset_otp():
    """Resend password reset OTP"""
    try:
        data = request.get_json()
        email = data.get('email')
        
        if not email:
            return jsonify({'error': 'Email is required'}), 400
        
        current_db = get_db_safe()
        if current_db is None:
            return jsonify({'error': 'Database not available'}), 500
        
        # Check if user exists
        user = current_db.users.find_one({'email': email})
        if not user:
            # For security, don't reveal if email exists or not
            return jsonify({
                'message': 'If your email exists in our system, you will receive a password reset OTP shortly.'
            })
        
        # Generate new OTP
        otp = generate_otp()
        
        # Remove existing OTPs for this email
        current_db.otp_verification.delete_many({
            'email': email,
            'purpose': 'password_reset'
        })
        
        # Store new OTP
        otp_doc = {
            'email': email,
            'otp': otp,
            'purpose': 'password_reset',
            'created_at': datetime.utcnow(),
            'expires_at': datetime.utcnow() + timedelta(minutes=10)
        }
        current_db.otp_verification.insert_one(otp_doc)
        
        # Send OTP email
        otp_sent = send_password_reset_otp_email(email, otp)
        
        if otp_sent:
            return jsonify({'message': 'Password reset OTP sent successfully'})
        else:
            return jsonify({'warning': 'OTP created but email delivery failed'})
            
    except Exception as e:
        logger.error(f"Error resending password reset OTP: {e}")
        return jsonify({'error': 'Failed to resend OTP'}), 500

@app.route('/register', methods=['POST'])
def register():
    try:
        data = request.get_json()
        
        required_fields = ['first_name', 'last_name', 'email', 'password', 'confirm_password', 'role']
        for field in required_fields:
            if field not in data or not data[field]:
                return jsonify({'error': f'{field.replace("_", " ").title()} is required'}), 400
        
        if not validate_email(data['email']):
            return jsonify({'error': 'Invalid email format'}), 400
        
        # Check if email already exists
        current_db = get_db_safe()
        if current_db is not None:
            existing_user = current_db.users.find_one({'email': data['email']})
            if existing_user:
                return jsonify({'error': 'User with this email already exists'}), 400
        
        # Validate password
        is_valid, password_msg = validate_password(data['password'])
        if not is_valid:
            return jsonify({'error': password_msg}), 400
        
        if data['password'] != data['confirm_password']:
            return jsonify({'error': 'Passwords do not match'}), 400
        
        # Generate appropriate ID based on role
        user_id = None
        if data['role'] == 'patient':
            user_id = generate_patient_id()
        elif data['role'] == 'doctor':
            user_id = generate_doctor_id()
        elif data['role'] == 'receptionist':
            user_id = generate_receptionist_id()
        else:
            user_id = f"USR{random.randint(1000, 9999)}"
        
        hashed_password = generate_password_hash(data['password'])
        
        # Insert user into database
        user_doc = {
            'user_id': user_id,
            'email': data['email'],
            'password': hashed_password,
            'first_name': data['first_name'],
            'last_name': data['last_name'],
            'role': data['role'],
            'patient_id': user_id if data['role'] == 'patient' else None,
            'is_predefined': False,
            'is_active': True,
            'email_verified': DEMO_AUTO_VERIFY,
            'last_login': None,
            'created_at': datetime.utcnow(),
            'updated_at': datetime.utcnow()
        }
        
        # Add specialization for doctors
        if data['role'] == 'doctor':
            user_doc['specialization'] = data.get('specialization', 'Acupressure Therapy')
            user_doc['therapy_type'] = data.get('therapy_type', 'acupressure')
        
        # Insert into database if connected
        if current_db is not None:
            try:
                result = current_db.users.insert_one(user_doc)
                logger.info(f"✅ Created user: {user_id} with ID: {result.inserted_id}")
                
                # Verify the user was actually created
                created_user = current_db.users.find_one({'user_id': user_id})
                if not created_user:
                    logger.error(f"❌ User creation failed: {user_id}")
                    return jsonify({'error': 'User creation failed'}), 500
                    
            except Exception as e:
                logger.error(f"❌ Database error creating user: {e}")
                return jsonify({'error': 'Failed to create user account'}), 500
        
        # Generate and send OTP
        otp_sent = False
        if not DEMO_AUTO_VERIFY and current_db is not None:
            otp = generate_otp()
            # Remove existing OTPs for this email
            current_db.otp_verification.delete_many({'email': data['email']})
            
            otp_doc = {
                'email': data['email'],
                'otp': otp,
                'purpose': 'email_verification',
                'created_at': datetime.utcnow(),
                'expires_at': datetime.utcnow() + timedelta(minutes=10)
            }
            current_db.otp_verification.insert_one(otp_doc)
            
            # Send OTP email
            otp_sent = send_otp_email(data['email'], otp)

        response_data = {
            'message': f'{data["role"].title()} registered successfully!',
            'user_id': user_id,
            'email': data['email'],
            'requires_verification': not DEMO_AUTO_VERIFY and current_db is not None
        }
        
        if not DEMO_AUTO_VERIFY and not otp_sent and current_db is not None:
            response_data['warning'] = 'OTP email failed but account created.'
        
        logger.info(f"🎉 Registration successful for: {data['email']}")
        return jsonify(response_data), 201
        
    except Exception as e:
        logger.error(f"🔥 Registration error: {e}")
        return jsonify({'error': 'Internal server error'}), 500


# Existing OTP verification routes
@app.route('/verify-otp', methods=['POST'])
def verify_otp():
    """Verify OTP for email verification"""
    try:
        data = request.get_json()
        email = data.get('email')
        otp = data.get('otp')
        
        if not email or not otp:
            return jsonify({'error': 'Email and OTP are required'}), 400
        
        current_db = get_db_safe()
        if current_db is None:
            return jsonify({'message': 'OTP verified successfully (demo mode)'})
        
        # Find the OTP record
        otp_record = current_db.otp_verification.find_one({
            'email': email,
            'otp': otp,
            'expires_at': {'$gt': datetime.utcnow()}
        })
        
        if otp_record:
            # Mark user as verified
            current_db.users.update_one(
                {'email': email},
                {'$set': {'email_verified': True, 'updated_at': datetime.utcnow()}}
            )
            
            # Remove used OTP
            current_db.otp_verification.delete_one({'_id': otp_record['_id']})
            
            return jsonify({'message': 'Email verified successfully'})
        else:
            return jsonify({'error': 'Invalid or expired OTP'}), 400
            
    except Exception as e:
        logger.error(f"Error verifying OTP: {e}")
        return jsonify({'error': 'Failed to verify OTP'}), 500

@app.route('/resend-otp', methods=['POST'])
def resend_otp():
    """Resend OTP for email verification"""
    try:
        data = request.get_json()
        email = data.get('email')
        
        if not email:
            return jsonify({'error': 'Email is required'}), 400
        
        current_db = get_db_safe()
        if current_db is None:
            return jsonify({'message': 'OTP would be resent (demo mode)'})
        
        # Generate new OTP
        otp = generate_otp()
        
        # Remove existing OTPs for this email
        current_db.otp_verification.delete_many({'email': email})
        
        # Create new OTP record
        otp_doc = {
            'email': email,
            'otp': otp,
            'purpose': 'email_verification',
            'created_at': datetime.utcnow(),
            'expires_at': datetime.utcnow() + timedelta(minutes=10)
        }
        current_db.otp_verification.insert_one(otp_doc)
        
        # Send OTP email
        otp_sent = send_otp_email(email, otp)
        
        if otp_sent:
            return jsonify({'message': 'OTP sent successfully'})
        else:
            return jsonify({'warning': 'OTP created but email delivery failed'})
            
    except Exception as e:
        logger.error(f"Error resending OTP: {e}")
        return jsonify({'error': 'Failed to resend OTP'}), 500
# ========== PATIENT-SPECIFIC API ROUTES ==========

@app.route('/api/patient-dashboard-stats')
@login_required
@role_required(['patient'])
def patient_dashboard_stats():
    """Get patient-specific dashboard statistics"""
    try:
        current_db = get_db_safe()
        patient_id = session['user_id']
        
        stats = {
            'upcoming_appointments': 0,
            'completed_sessions': 0,
            'therapies_tried': 0,
            'wellness_score': '0%'
        }
        
        if current_db:
            # Upcoming appointments
            stats['upcoming_appointments'] = current_db.appointments.count_documents({
                'patient_id': patient_id,
                'status': 'scheduled',
                'date': {'$gte': datetime.utcnow()}
            })
            
            # Completed sessions
            stats['completed_sessions'] = current_db.appointments.count_documents({
                'patient_id': patient_id,
                'status': 'completed'
            })
            
            # Therapies tried
            stats['therapies_tried'] = len(current_db.appointments.distinct('therapy_type', {
                'patient_id': patient_id
            }))
            
            # Wellness score (demo calculation)
            total_appointments = current_db.appointments.count_documents({'patient_id': patient_id})
            if total_appointments > 0:
                completed = current_db.appointments.count_documents({
                    'patient_id': patient_id,
                    'status': 'completed'
                })
                stats['wellness_score'] = f"{min(100, (completed / total_appointments) * 100):.0f}%"
        
        return jsonify(stats)
        
    except Exception as e:
        logger.error(f"Error getting patient stats: {e}")
        return jsonify({'error': 'Failed to load statistics'}), 500

@app.route('/api/patient-appointments')
@login_required
@role_required(['patient'])
def patient_appointments():
    """Get patient's appointments"""
    try:
        current_db = get_db_safe()
        patient_id = session['user_id']
        
        appointments = []
        
        if current_db:
            appointments_cursor = current_db.appointments.find(
                {'patient_id': patient_id}
            ).sort('date', -1).limit(5)
            
            for appt in appointments_cursor:
                # Get doctor details
                doctor = current_db.users.find_one({'user_id': appt.get('therapist_id')})
                doctor_name = f"{doctor.get('first_name', '')} {doctor.get('last_name', '')}" if doctor else 'Unknown Doctor'
                
                appointments.append({
                    'appointment_id': appt.get('appointment_id'),
                    'therapy_name': appt.get('therapy_type', '').title(),
                    'doctor_name': doctor_name,
                    'date': appt.get('date').isoformat() if appt.get('date') else '',
                    'reason': appt.get('reason', ''),
                    'status': appt.get('status', 'scheduled')
                })
        
        return jsonify(appointments)
        
    except Exception as e:
        logger.error(f"Error getting patient appointments: {e}")
        return jsonify([])    

# ========== MAIN APPLICATION ROUTES ==========

# @app.route('/dashboard')
# @login_required
# def dashboard():
#     try:
#         stats = get_dashboard_stats(session['role'], session['user_id'])
#         return render_template('dashboard.html', user=session, stats=stats)
#     except Exception as e:
#         logger.error(f"Dashboard error: {e}")
#         session.clear()
#         return redirect(url_for('index'))

# ========== ENHANCED ROLE-BASED ROUTING ==========

@app.route('/dashboard')
@login_required
def dashboard():
    """Role-based dashboard routing"""
    try:
        role = session['role']
        user_id = session['user_id']
        
        # Get real-time stats
        stats = get_dashboard_stats(role, user_id)
        
        # Role-based template selection
        if role == 'patient':
            return render_template('patient_dashboard.html', user=session, stats=stats)
        elif role == 'doctor':
            return render_template('doctor_dashboard.html', user=session, stats=stats)
        elif role == 'receptionist':
            return render_template('receptionist_dashboard.html', user=session, stats=stats)
        elif role == 'admin':
            return render_template('admin_dashboard.html', user=session, stats=stats)
        else:
            return render_template('dashboard.html', user=session, stats=stats)
            
    except Exception as e:
        logger.error(f"Dashboard routing error: {e}")
        return redirect(url_for('index'))

@app.route('/book-appointment')
@login_required
@role_required(['patient'])
def book_appointment():
    """Patient appointment booking - Only for patients"""
    return render_template('book_appointment.html')

@app.route('/doctor-dashboard')
@login_required
@role_required(['doctor'])
def doctor_dashboard():
    """Doctor dashboard - Only for doctors"""
    stats = get_dashboard_stats('doctor', session['user_id'])
    return render_template('doctor_dashboard.html', user=session, stats=stats)

@app.route('/receptionist-dashboard')
@login_required
@role_required(['receptionist', 'admin'])
def receptionist_dashboard():
    """Receptionist dashboard"""
    stats = get_dashboard_stats('receptionist', session['user_id'])
    return render_template('receptionist_dashboard.html', user=session, stats=stats)

@app.route('/admin-dashboard')
@login_required
@role_required(['admin'])
def admin_dashboard():
    """Admin dashboard"""
    stats = get_dashboard_stats('admin', session['user_id'])
    return render_template('admin_dashboard.html', user=session, stats=stats)

# ========== ENHANCED LOGIN WITH ROLE-BASED REDIRECTION ==========

@app.route('/login', methods=['POST'])
def login():
    try:
        data = request.get_json()
        
        if not data.get('email') or not data.get('password'):
            return jsonify({'error': 'Email and password are required'}), 400
        
        logger.info(f"🔐 Login attempt for: {data['email']}")
        
        # First check predefined users (admin, receptionist, doctors)
        for user_key, user_data in PREDEFINED_USERS.items():
            if data['email'] == user_data['email'] and data['password'] == user_data['password']:
                session.clear()
                session['user_id'] = user_data['user_id']
                session['email'] = user_data['email']
                session['role'] = user_data['role']
                session['first_name'] = user_data['first_name']
                session['last_name'] = user_data['last_name']
                session['login_time'] = datetime.now(timezone.utc)
                
                if user_data['role'] == 'doctor':
                    session['specialization'] = user_data.get('specialization')
                    session['therapy_type'] = user_data.get('therapy_type')
                
                session.permanent = True
                session.modified = True
                
                # Role-based redirection after login
                redirect_url = get_role_redirect_url(user_data['role'])
                
                logger.info(f"✅ Login successful for predefined user {user_data['email']}, role: {user_data['role']}")
                
                return jsonify({
                    'message': 'Login successful!',
                    'user': {
                        'id': user_data['user_id'],
                        'first_name': user_data['first_name'],
                        'last_name': user_data['last_name'],
                        'email': user_data['email'],
                        'role': user_data['role'],
                        'specialization': user_data.get('specialization'),
                        'therapy_type': user_data.get('therapy_type')
                    },
                    'redirect_url': redirect_url
                }), 200
        
        # Check database for registered patients
        current_db = get_db_safe()
        user = None
        
        if current_db is not None:
            logger.info(f"🔍 Searching for user in database: {data['email']}")
            user = current_db.users.find_one({'email': data['email']})
        
        if user:
            logger.info(f"📋 User found: {user['user_id']}")
            
            # Check if account is active
            if not user.get('is_active', True):
                logger.warning(f"❌ Account deactivated: {data['email']}")
                return jsonify({'error': 'Account is deactivated'}), 401
            
            # Verify password
            if check_password_hash(user['password'], data['password']):
                logger.info(f"✅ Password verified for: {data['email']}")
                
                # Check email verification
                if current_db is not None and not user.get('email_verified', False) and not DEMO_AUTO_VERIFY:
                    logger.warning(f"❌ Email not verified: {data['email']}")
                    return jsonify({'error': 'Please verify your email before logging in'}), 401
                
                # Login successful - set session
                session.clear()
                session['user_id'] = user['user_id']
                session['email'] = user['email']
                session['role'] = user['role']
                session['first_name'] = user['first_name']
                session['last_name'] = user['last_name']
                session['login_time'] = datetime.now(timezone.utc)
                
                if user['role'] == 'patient':
                    session['patient_id'] = user.get('patient_id', user['user_id'])
                
                session.permanent = True
                session.modified = True
                
                # Update last login
                if current_db is not None:
                    current_db.users.update_one(
                        {'user_id': user['user_id']},
                        {'$set': {'last_login': datetime.utcnow(), 'updated_at': datetime.utcnow()}}
                    )
                
                # Role-based redirection
                redirect_url = get_role_redirect_url(user['role'])
                
                user_response = {
                    'id': user['user_id'],
                    'first_name': user['first_name'],
                    'last_name': user['last_name'],
                    'email': user['email'],
                    'role': user['role']
                }
                
                if user['role'] == 'patient':
                    user_response['patient_id'] = user.get('patient_id')
                
                logger.info(f"🎉 Login successful for: {data['email']}")
                return jsonify({
                    'message': 'Login successful!',
                    'user': user_response,
                    'redirect_url': redirect_url
                }), 200
            else:
                logger.warning(f"❌ Invalid password for: {data['email']}")
                return jsonify({'error': 'Invalid email or password'}), 401
        else:
            logger.warning(f"❌ User not found: {data['email']}")
            return jsonify({'error': 'Invalid email or password'}), 401
        
    except Exception as e:
        logger.error(f"🔥 Login error: {str(e)}")
        return jsonify({'error': 'Internal server error'}), 500

def get_role_redirect_url(role):
    """Get redirect URL based on user role"""
    redirect_routes = {
        'patient': '/book-appointment',
        'doctor': '/doctor-dashboard',
        'receptionist': '/receptionist-dashboard',
        'admin': '/admin-dashboard'
    }
    return redirect_routes.get(role, '/dashboard')    





@app.route('/book-appointment')
@login_required
def book_appointment():
    """Book appointment page"""
    return render_template('book_appointment.html')

@app.route('/acupressure-info')
@login_required
def acupressure_info():
    """Acupressure information page"""
    return render_template('acupressure_info.html')

@app.route('/patient-info')
@login_required
def patient_info():
    """Patient information page"""
    return render_template('patient_info.html')

@app.route('/manage-appointments')
@login_required
def manage_appointments():
    """Manage appointments page"""
    if session.get('role') not in ['receptionist', 'admin', 'doctor']:
        return jsonify({'error': 'Insufficient permissions'}), 403
    return render_template('manage_appointments.html')

@app.route('/appointment-receipt/<appointment_id>')
@login_required
def appointment_receipt(appointment_id):
    """Appointment receipt page"""
    return render_template('appointment_receipt.html', appointment_id=appointment_id)

@app.route('/receptionist-dashboard')
@login_required
@role_required(['receptionist', 'admin'])
def receptionist_dashboard():
    """Receptionist dashboard"""
    return render_template('receptionist_dashboard.html')

# ========== API ROUTES ==========

@app.route('/api/dashboard-stats')
@login_required
def dashboard_stats():
    """Get dashboard statistics for the current user"""
    try:
        stats = get_dashboard_stats(session['role'], session['user_id'])
        return jsonify(stats)
    except Exception as e:
        logger.error(f"Error getting dashboard stats: {e}")
        return jsonify({'error': 'Failed to load dashboard statistics'}), 500

@app.route('/api/dashboard-data')
@login_required
def dashboard_data():
    """Get dashboard data for the current user"""
    try:
        stats = get_dashboard_stats(session['role'], session['user_id'])
        user_data = {
            'first_name': session.get('first_name'),
            'last_name': session.get('last_name'),
            'email': session.get('email'),
            'role': session.get('role'),
            'user_id': session.get('user_id')
        }
        return jsonify({'user': user_data, 'stats': stats})
    except Exception as e:
        logger.error(f"Error getting dashboard data: {e}")
        return jsonify({'error': 'Failed to load dashboard data'}), 500

@app.route('/api/appointments', methods=['GET', 'POST'])
@login_required
def get_appointments():
    """Get or create appointments"""
    if request.method == 'GET':
        current_db = get_db_safe()
        user_id = session['user_id']
        role = session['role']
        
        try:
            if current_db:
                if role == 'patient':
                    appointments = list(current_db.appointments.find({'patient_id': user_id}))
                elif role == 'doctor':
                    appointments = list(current_db.appointments.find({'therapist_id': user_id}))
                else:  # admin or receptionist
                    appointments = list(current_db.appointments.find({}))
                
                # Convert ObjectId to string for JSON serialization
                for appointment in appointments:
                    appointment['_id'] = str(appointment['_id'])
                    
                return jsonify(appointments)
            else:
                # Demo data
                demo_appointments = [
                    {
                        '_id': '1',
                        'appointment_id': 'APT001',
                        'patient_id': user_id,
                        'patient_name': 'Demo Patient',
                        'therapy_type': 'acupressure',
                        'therapist_id': 'DOC001',
                        'doctor_name': 'Dr. Rajesh Sharma',
                        'date': (datetime.utcnow() + timedelta(days=1)).isoformat(),
                        'reason': 'Regular checkup',
                        'status': 'scheduled',
                        'consultation_type': 'follow-up'
                    }
                ]
                return jsonify(demo_appointments)
                
        except Exception as e:
            logger.error(f"Error fetching appointments: {e}")
            return jsonify([])
    
    elif request.method == 'POST':
        # Create new appointment
        try:
            data = request.get_json()
            
            # Generate appointment ID
            appointment_id = f"APT{random.randint(1000, 9999)}"
            
            appointment_data = {
                'appointment_id': appointment_id,
                'patient_id': session['user_id'],
                'patient_name': data.get('patient_name'),
                'therapy_type': data.get('therapy_type'),
                'therapist_id': data.get('therapist_id'),
                'date': datetime.fromisoformat(data.get('date').replace('Z', '+00:00')),
                'reason': data.get('reason'),
                'consultation_type': data.get('consultation_type'),
                'status': 'pending',
                'created_at': datetime.utcnow(),
                'updated_at': datetime.utcnow()
            }
            
            # Add optional fields if provided
            optional_fields = [
                'patient_dob', 'patient_gender', 'patient_phone', 'patient_address',
                'patient_height', 'patient_weight', 'patient_blood_group', 'patient_allergies',
                'medical_conditions', 'current_medications', 'previous_surgeries',
                'family_medical_history', 'additional_notes'
            ]
            
            for field in optional_fields:
                if field in data:
                    appointment_data[field] = data[field]
            
            current_db = get_db_safe()
            if current_db:
                result = current_db.appointments.insert_one(appointment_data)
                
                # Create notification for receptionist
                create_notification(
                    'REC001',  # Receptionist user ID
                    'New Appointment Request',
                    f'New appointment request from {data.get("patient_name")} for {data.get("therapy_type")} therapy',
                    'info'
                )
                
                return jsonify({
                    'message': 'Appointment booked successfully! Waiting for confirmation.',
                    'appointment_id': appointment_id
                }), 201
            else:
                return jsonify({
                    'message': 'Appointment request recorded (demo mode)',
                    'appointment_id': appointment_id
                }), 201
                
        except Exception as e:
            logger.error(f"Error creating appointment: {e}")
            return jsonify({'error': 'Failed to book appointment'}), 500

@app.route('/api/appointments/<appointment_id>/complete', methods=['POST'])
@login_required
def complete_appointment(appointment_id):
    """Complete an appointment"""
    try:
        current_db = get_db_safe()
        if current_db:
            result = current_db.appointments.update_one(
                {'appointment_id': appointment_id},
                {'$set': {'status': 'completed', 'updated_at': datetime.utcnow()}}
            )
            
            if result.modified_count > 0:
                return jsonify({'message': 'Appointment marked as completed'})
            else:
                return jsonify({'error': 'Appointment not found'}), 404
        else:
            return jsonify({'message': 'Appointment completed (demo mode)'})
            
    except Exception as e:
        logger.error(f"Error completing appointment: {e}")
        return jsonify({'error': 'Failed to complete appointment'}), 500

@app.route('/api/appointments/<appointment_id>/cancel', methods=['POST'])
@login_required
def cancel_appointment_api(appointment_id):
    """Cancel an appointment"""
    try:
        current_db = get_db_safe()
        if current_db:
            result = current_db.appointments.update_one(
                {'appointment_id': appointment_id},
                {'$set': {'status': 'cancelled', 'updated_at': datetime.utcnow()}}
            )
            
            if result.modified_count > 0:
                return jsonify({'message': 'Appointment cancelled'})
            else:
                return jsonify({'error': 'Appointment not found'}), 404
        else:
            return jsonify({'message': 'Appointment cancelled (demo mode)'})
            
    except Exception as e:
        logger.error(f"Error cancelling appointment: {e}")
        return jsonify({'error': 'Failed to cancel appointment'}), 500

# Receptionist-specific routes
@app.route('/api/receptionist/appointments')
@login_required
@role_required(['receptionist', 'admin'])
def receptionist_appointments():
    """Get all appointments for receptionist"""
    try:
        current_db = get_db_safe()
        
        # Demo data structure
        demo_appointments = [
            {
                'appointment_id': 'APT001',
                'patient_name': 'Rahul Kumar',
                'patient_email': 'rahul@example.com',
                'patient_phone': '+91-9876543210',
                'therapy_type': 'acupressure',
                'therapy_name': 'Acupressure/Acupuncture',
                'doctor_name': 'Dr. Rajesh Sharma',
                'date': datetime.utcnow().isoformat(),
                'reason': 'Chronic back pain',
                'status': 'pending',
                'consultation_type': 'initial'
            },
            {
                'appointment_id': 'APT002',
                'patient_name': 'Priya Singh',
                'patient_email': 'priya@example.com',
                'patient_phone': '+91-9876543211',
                'therapy_type': 'ayurveda',
                'therapy_name': 'Ayurveda',
                'doctor_name': 'Dr. Priya Gupta',
                'date': (datetime.utcnow() + timedelta(days=1)).isoformat(),
                'reason': 'Digestive issues',
                'status': 'confirmed',
                'consultation_type': 'follow-up'
            }
        ]
        
        if current_db:
            appointments = list(current_db.appointments.find({}))
            # Convert to the expected format
            formatted_appointments = []
            for appt in appointments:
                # Get patient and doctor details
                patient = current_db.users.find_one({'user_id': appt.get('patient_id')})
                doctor = current_db.users.find_one({'user_id': appt.get('therapist_id')})
                
                formatted_appointments.append({
                    'appointment_id': appt.get('appointment_id'),
                    'patient_name': patient.get('first_name', '') + ' ' + patient.get('last_name', '') if patient else 'Unknown Patient',
                    'patient_email': patient.get('email', ''),
                    'patient_phone': appt.get('patient_phone', ''),
                    'therapy_type': appt.get('therapy_type'),
                    'therapy_name': appt.get('therapy_type', '').title(),
                    'doctor_name': f"Dr. {doctor.get('first_name', '')} {doctor.get('last_name', '')}" if doctor else 'Unknown Doctor',
                    'date': appt.get('date').isoformat() if appt.get('date') else datetime.utcnow().isoformat(),
                    'reason': appt.get('reason', ''),
                    'status': appt.get('status', 'pending'),
                    'consultation_type': appt.get('consultation_type', 'initial')
                })
            
            stats = {
                'total': len(formatted_appointments),
                'pending': len([a for a in formatted_appointments if a['status'] == 'pending']),
                'confirmed': len([a for a in formatted_appointments if a['status'] == 'confirmed']),
                'today': len([a for a in formatted_appointments if datetime.fromisoformat(a['date']).date() == datetime.utcnow().date()])
            }
            
            return jsonify({
                'appointments': formatted_appointments,
                'stats': stats
            })
        else:
            # Demo mode
            stats = {
                'total': len(demo_appointments),
                'pending': len([a for a in demo_appointments if a['status'] == 'pending']),
                'confirmed': len([a for a in demo_appointments if a['status'] == 'confirmed']),
                'today': 1
            }
            
            return jsonify({
                'appointments': demo_appointments,
                'stats': stats
            })
            
    except Exception as e:
        logger.error(f"Error fetching receptionist appointments: {e}")
        return jsonify({'error': 'Failed to fetch appointments'}), 500

@app.route('/api/receptionist/appointments/<appointment_id>/confirm', methods=['POST'])
@login_required
@role_required(['receptionist', 'admin'])
def confirm_appointment_api(appointment_id):
    """Confirm an appointment"""
    try:
        current_db = get_db_safe()
        if current_db:
            result = current_db.appointments.update_one(
                {'appointment_id': appointment_id},
                {'$set': {'status': 'confirmed', 'updated_at': datetime.utcnow()}}
            )
            
            if result.modified_count > 0:
                # Get appointment details for notification
                appointment = current_db.appointments.find_one({'appointment_id': appointment_id})
                patient = current_db.users.find_one({'user_id': appointment.get('patient_id')})
                doctor = current_db.users.find_one({'user_id': appointment.get('therapist_id')})
                
                # Create notifications
                if patient:
                    create_notification(
                        patient['user_id'],
                        'Appointment Confirmed',
                        f'Your {appointment.get("therapy_type")} appointment has been confirmed',
                        'success'
                    )
                
                if doctor:
                    create_notification(
                        doctor['user_id'],
                        'New Confirmed Appointment',
                        f'New appointment confirmed with {patient.get("first_name", "Patient")} for {appointment.get("therapy_type")}',
                        'info'
                    )
                
                return jsonify({'message': 'Appointment confirmed successfully'})
            else:
                return jsonify({'error': 'Appointment not found'}), 404
        else:
            return jsonify({'message': 'Appointment confirmed (demo mode)'})
            
    except Exception as e:
        logger.error(f"Error confirming appointment: {e}")
        return jsonify({'error': 'Failed to confirm appointment'}), 500

@app.route('/api/receptionist/appointments/<appointment_id>/reschedule', methods=['POST'])
@login_required
@role_required(['receptionist', 'admin'])
def reschedule_appointment_api(appointment_id):
    """Reschedule an appointment"""
    try:
        data = request.get_json()
        new_date = data.get('new_date')
        
        if not new_date:
            return jsonify({'error': 'New date is required'}), 400
            
        current_db = get_db_safe()
        if current_db:
            result = current_db.appointments.update_one(
                {'appointment_id': appointment_id},
                {'$set': {'date': datetime.fromisoformat(new_date.replace('Z', '+00:00')), 'updated_at': datetime.utcnow()}}
            )
            
            if result.modified_count > 0:
                # Get appointment details for notification
                appointment = current_db.appointments.find_one({'appointment_id': appointment_id})
                patient = current_db.users.find_one({'user_id': appointment.get('patient_id')})
                
                if patient:
                    create_notification(
                        patient['user_id'],
                        'Appointment Rescheduled',
                        f'Your {appointment.get("therapy_type")} appointment has been rescheduled',
                        'warning'
                    )
                
                return jsonify({'message': 'Appointment rescheduled successfully'})
            else:
                return jsonify({'error': 'Appointment not found'}), 404
        else:
            return jsonify({'message': 'Appointment rescheduled (demo mode)'})
            
    except Exception as e:
        logger.error(f"Error rescheduling appointment: {e}")
        return jsonify({'error': 'Failed to reschedule appointment'}), 500

# Notifications API
@app.route('/api/notifications')
@login_required
def get_notifications():
    """Get user notifications"""
    try:
        current_db = get_db_safe()
        user_id = session['user_id']
        
        if current_db:
            notifications = list(current_db.notifications.find(
                {'user_id': user_id}
            ).sort('created_at', -1).limit(10))
            
            # Convert ObjectId to string
            for notification in notifications:
                notification['_id'] = str(notification['_id'])
                
            return jsonify(notifications)
        else:
            # Demo notifications
            demo_notifications = [
                {
                    '_id': '1',
                    'title': 'Welcome to DCAM',
                    'message': 'Your account has been created successfully',
                    'type': 'success',
                    'is_read': True,
                    'created_at': (datetime.utcnow() - timedelta(hours=2)).isoformat()
                },
                {
                    '_id': '2',
                    'title': 'New Feature Available',
                    'message': 'You can now book appointments online',
                    'type': 'info',
                    'is_read': False,
                    'created_at': datetime.utcnow().isoformat()
                }
            ]
            return jsonify(demo_notifications)
            
    except Exception as e:
        logger.error(f"Error fetching notifications: {e}")
        return jsonify([])

@app.route('/api/notifications/<notification_id>/read', methods=['POST'])
@login_required
def mark_notification_read(notification_id):
    """Mark notification as read"""
    try:
        current_db = get_db_safe()
        if current_db:
            result = current_db.notifications.update_one(
                {'_id': ObjectId(notification_id)},
                {'$set': {'is_read': True}}
            )
            
            if result.modified_count > 0:
                return jsonify({'message': 'Notification marked as read'})
            else:
                return jsonify({'error': 'Notification not found'}), 404
        else:
            return jsonify({'message': 'Notification marked as read (demo mode)'})
            
    except Exception as e:
        logger.error(f"Error marking notification as read: {e}")
        return jsonify({'error': 'Failed to mark notification as read'}), 500

@app.route('/api/notifications/read', methods=['POST'])
@login_required
def mark_all_notifications_read():
    """Mark all notifications as read"""
    try:
        current_db = get_db_safe()
        user_id = session['user_id']
        
        if current_db:
            result = current_db.notifications.update_many(
                {'user_id': user_id, 'is_read': False},
                {'$set': {'is_read': True}}
            )
            
            return jsonify({'message': f'{result.modified_count} notifications marked as read'})
        else:
            return jsonify({'message': 'All notifications marked as read (demo mode)'})
            
    except Exception as e:
        logger.error(f"Error marking all notifications as read: {e}")
        return jsonify({'error': 'Failed to mark notifications as read'}), 500

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('index', logout='true'))

# Health check endpoint
@app.route('/health')
def health_check():
    db_health = check_db_health()
    status = "healthy" if db_health else "degraded"
    
    return jsonify({
        'status': status,
        'database': 'connected' if db_health else 'disconnected',
        'timestamp': datetime.now(timezone.utc).isoformat(),
        'demo_mode': not db_health,
        'app': 'DCAM Therapy Management System',
        'version': '2.0.0'
    })

# ========== ADDITIONAL API ENDPOINTS FOR TEMPLATES ==========

@app.route('/api/patient-data')
@login_required
def patient_data():
    """Get patient data for patient info page"""
    try:
        current_db = get_db_safe()
        user_id = session['user_id']
        
        if current_db:
            patient = current_db.users.find_one({'user_id': user_id})
            if patient:
                patient_data = {
                    'user_id': patient.get('user_id'),
                    'first_name': patient.get('first_name'),
                    'last_name': patient.get('last_name'),
                    'email': patient.get('email'),
                    'phone': patient.get('phone', ''),
                    'address': patient.get('address', ''),
                    'date_of_birth': patient.get('date_of_birth', ''),
                    'gender': patient.get('gender', ''),
                    'blood_group': patient.get('blood_group', ''),
                    'allergies': patient.get('allergies', ''),
                    'medical_conditions': patient.get('medical_conditions', ''),
                    'current_medications': patient.get('current_medications', ''),
                    'emergency_contact': patient.get('emergency_contact', ''),
                    'created_at': patient.get('created_at')
                }
                return jsonify(patient_data)
        
        # Demo data
        demo_patient_data = {
            'user_id': session.get('user_id'),
            'first_name': session.get('first_name', 'Patient'),
            'last_name': session.get('last_name', 'Demo'),
            'email': session.get('email'),
            'phone': '+91-9876543210',
            'address': '123 Demo Street, Haridwar, Uttarakhand',
            'date_of_birth': '1990-01-01',
            'gender': 'Prefer not to say',
            'blood_group': 'O+',
            'allergies': 'None',
            'medical_conditions': 'None',
            'current_medications': 'None',
            'emergency_contact': '+91-9876543211',
            'created_at': datetime.utcnow().isoformat()
        }
        return jsonify(demo_patient_data)
        
    except Exception as e:
        logger.error(f"Error fetching patient data: {e}")
        return jsonify({'error': 'Failed to load patient data'}), 500

@app.route('/api/therapists')
@login_required
def get_therapists():
    """Get list of therapists for booking appointments"""
    try:
        current_db = get_db_safe()
        
        if current_db:
            therapists = list(current_db.users.find({'role': 'doctor'}))
            therapist_list = []
            for therapist in therapists:
                therapist_list.append({
                    'user_id': therapist.get('user_id'),
                    'name': f"Dr. {therapist.get('first_name', '')} {therapist.get('last_name', '')}",
                    'specialization': therapist.get('specialization', 'Therapy Specialist'),
                    'therapy_type': therapist.get('therapy_type', 'acupressure'),
                    'email': therapist.get('email')
                })
            return jsonify(therapist_list)
        
        # Demo therapists data
        demo_therapists = [
            {
                'user_id': 'DOC001',
                'name': 'Dr. Rajesh Sharma',
                'specialization': 'Acupressure Specialist',
                'therapy_type': 'acupressure',
                'email': 'dr.sharma@dsvv.ac.in'
            },
            {
                'user_id': 'DOC002',
                'name': 'Dr. Priya Gupta',
                'specialization': 'Ayurveda Expert',
                'therapy_type': 'ayurveda',
                'email': 'dr.gupta@dsvv.ac.in'
            },
            {
                'user_id': 'DOC003',
                'name': 'Dr. Amit Verma',
                'specialization': 'Homeopathy Specialist',
                'therapy_type': 'homeopathy',
                'email': 'dr.verma@dsvv.ac.in'
            }
        ]
        return jsonify(demo_therapists)
        
    except Exception as e:
        logger.error(f"Error fetching therapists: {e}")
        return jsonify([])

@app.route('/api/update-patient-info', methods=['POST'])
@login_required
def update_patient_info():
    """Update patient information"""
    try:
        data = request.get_json()
        user_id = session['user_id']
        
        current_db = get_db_safe()
        if current_db:
            update_data = {}
            allowed_fields = [
                'phone', 'address', 'date_of_birth', 'gender', 'blood_group',
                'allergies', 'medical_conditions', 'current_medications', 
                'emergency_contact'
            ]
            
            for field in allowed_fields:
                if field in data:
                    update_data[field] = data[field]
            
            if update_data:
                update_data['updated_at'] = datetime.utcnow()
                result = current_db.users.update_one(
                    {'user_id': user_id},
                    {'$set': update_data}
                )
                
                if result.modified_count > 0:
                    return jsonify({'message': 'Patient information updated successfully'})
                else:
                    return jsonify({'error': 'No changes made or patient not found'}), 400
            else:
                return jsonify({'error': 'No valid fields to update'}), 400
        else:
            return jsonify({'message': 'Patient information updated (demo mode)'})
            
    except Exception as e:
        logger.error(f"Error updating patient info: {e}")
        return jsonify({'error': 'Failed to update patient information'}), 500

if __name__ == '__main__':
    # Log startup information
    logger.info("🚀 Starting DCAM Therapy Management System")
    logger.info(f"📊 Database Connected: {db_connected}")
    logger.info(f"🔐 Demo Mode: {not db_connected}")
    logger.info(f"🔑 Google OAuth Enabled: {bool(os.environ.get('GOOGLE_CLIENT_ID'))}")
    logger.info(f"💳 Payment System: {'Enabled' if os.environ.get('STRIPE_SECRET_KEY') else 'Demo Mode'}")
    
    # Log predefined user credentials for testing
    logger.info("👥 Predefined Users Available:")
    for user_key, user_data in PREDEFINED_USERS.items():
        if user_data['role'] in ['admin', 'receptionist']:
            logger.info(f"   📧 {user_data['email']} / {user_data['password']} ({user_data['role']})")
    
    app.run(host='0.0.0.0', port=5000, debug=True)