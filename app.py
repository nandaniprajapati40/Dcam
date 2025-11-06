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
import ssl
import razorpay
import uuid

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
MONGODB_URI = os.environ.get('MONGODB_URI')
DB_NAME = os.environ.get('DB_NAME')

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
    return get_db()

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

        subject = f"Appointment Confirmed - {therapy_name}"
        body = f"""
Dear {patient_name},

🎉 Your appointment has been confirmed!

Appointment Details:
- Therapy: {therapy_name}
- Doctor: {doctor_name}
- Date & Time: {appointment_date}
- Status: Confirmed ✅

Please arrive 10 minutes before your scheduled time and bring your appointment receipt.

You can download your appointment receipt from your dashboard.

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

        subject = f"New Appointment Confirmed - {therapy_name}"
        body = f"""
Dear Dr. {doctor_name},

You have a new confirmed appointment scheduled:

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
        collections = current_db.list_collection_names()
        logger.info(f"📊 Existing collections: {collections}")
        
        # Define required collections and their indexes
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
                {'keys': [('date', 1)], 'options': {}},
                {'keys': [('status', 1)], 'options': {}}  # Added for doctor dashboard
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
                {'keys': [('created_at', -1)], 'options': {}},
                {'keys': [('is_read', 1)], 'options': {}}  # Added for efficient filtering
            ],
            'payments': [
                {'keys': [('payment_id', 1)], 'options': {'unique': True}},
                {'keys': [('appointment_id', 1)], 'options': {}},
                {'keys': [('patient_id', 1)], 'options': {}}
            ],
            'doctor_availability': [  # New collection for doctor availability
                {'keys': [('doctor_id', 1), ('day_of_week', 1)], 'options': {'unique': True}},
                {'keys': [('doctor_id', 1)], 'options': {}},
                {'keys': [('is_active', 1)], 'options': {}}
            ]
        }
        
        for collection_name, indexes in required_collections.items():
            if collection_name not in collections:
                current_db.create_collection(collection_name)
                logger.info(f"✅ Created collection: {collection_name}")
            
            # Create indexes
            for index_config in indexes:
                try:
                    keys = index_config['keys']
                    options = index_config['options']
                    current_db[collection_name].create_index(keys, **options)
                    logger.info(f"✅ Created index for {collection_name}: {keys}")
                except Exception as e:
                    logger.warning(f"⚠️ Could not create index for {collection_name}: {e}")

        # for collection_name, indexes in required_collections.items():
        #     if collection_name not in collections:
        #         current_db.create_collection(collection_name)
        #         logger.info(f"✅ Created collection: {collection_name}")
            
        #     # Create indexes with corrected structure
        #     for index_config in indexes:
        #         try:
        #             keys = index_config['keys']
        #             options = index_config['options']
        #             current_db[collection_name].create_index(keys, **options)
        #             logger.info(f"✅ Created index for {collection_name}: {keys}")
        #         except Exception as e:
        #             logger.warning(f"⚠️ Could not create index for {collection_name}: {e}")
        
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
            'admin': {'total_users': 12, 'total_patients': 0, 'total_doctors': 11, 'total_appointments': 0, 'today_appointments': 0},
            'doctor': {'todays_appointments': 3, 'total_patients': 45, 'completed_sessions': 120, 'pending_followups': 8},
            'patient': {'upcoming_appointments': 2, 'completed_sessions': 5, 'pending_appointments': 1, 'therapies_tried': 3},
            'receptionist': {'todays_appointments': 5, 'pending_registrations': 2, 'total_patients': 150, 'total_doctors': 11}
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
                'status': {'$in': ['scheduled', 'confirmed']}
            })
            
            stats['total_patients'] = len(current_db.appointments.distinct('patient_id', {'therapist_id': user_id}))
            stats['completed_sessions'] = current_db.appointments.count_documents({
                'therapist_id': user_id,
                'status': 'completed'
            })
            stats['pending_followups'] = current_db.appointments.count_documents({
                'therapist_id': user_id,
                'status': 'scheduled'
            })
            
        elif role == 'patient':
            stats['upcoming_appointments'] = current_db.appointments.count_documents({
                'patient_id': user_id,
                'status': {'$in': ['scheduled', 'confirmed']}
            })
            
            stats['completed_sessions'] = current_db.appointments.count_documents({
                'patient_id': user_id,
                'status': 'completed'
            })
            
            stats['pending_appointments'] = current_db.appointments.count_documents({
                'patient_id': user_id,
                'status': 'pending'
            })
            
            stats['therapies_tried'] = len(current_db.appointments.distinct('therapy_type', {
                'patient_id': user_id
            }))
            
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
            'create_payment', 'payment_success', 'payment_cancel',
            'patient_dashboard', 'doctor_dashboard', 'admin_dashboard',
            'manage_appointments'
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



@app.route('/api/appointment-receipt/<appointment_id>')
@login_required
def get_appointment_receipt(appointment_id):
    """Get appointment receipt data"""
    try:
        current_db = get_db_safe()
        
        if current_db is None:
            return jsonify({'error': 'Database not available'}), 500
        
        # Get appointment details
        appointment = current_db.appointments.find_one({'appointment_id': appointment_id})
        if not appointment:
            return jsonify({'error': 'Appointment not found'}), 404
        
        # Get patient details
        patient = current_db.users.find_one({'user_id': appointment['patient_id']})
        
        # Get doctor details
        doctor = current_db.users.find_one({'user_id': appointment['therapist_id']})
        
        # Get payment details
        payment = current_db.payments.find_one({'appointment_id': appointment_id})
        
        # Safely handle therapy_type with null checking
        therapy_type = appointment.get('therapy_type')
        if therapy_type and isinstance(therapy_type, str):
            therapy_display = therapy_type.title()
        else:
            therapy_display = 'Therapy Session'  # Default value
        
        # Safely handle doctor name
        if doctor:
            doctor_name = f"Dr. {doctor.get('first_name', '')} {doctor.get('last_name', '')}"
        else:
            doctor_name = 'Doctor Not Assigned'
        
        # Safely handle dates
        appointment_date = appointment.get('date')
        if appointment_date:
            formatted_date = appointment_date.strftime('%d %b %Y')
            formatted_time = appointment_date.strftime('%I:%M %p')
        else:
            formatted_date = 'Not Scheduled'
            formatted_time = 'Not Scheduled'
        
        # Safely handle payment date
        payment_date = payment.get('paid_at') if payment else None
        if payment_date:
            formatted_payment_date = payment_date.strftime('%d %b %Y %I:%M %p')
        else:
            formatted_payment_date = 'N/A'
        
        receipt_data = {
            'appointment_id': appointment_id,
            'patient_name': f"{patient.get('first_name', '')} {patient.get('last_name', '')}" if patient else 'Unknown Patient',
            'patient_email': patient.get('email', ''),
            'patient_phone': patient.get('phone', 'N/A'),
            'therapy_type': therapy_display,
            'doctor_name': doctor_name,
            'appointment_date': formatted_date,
            'appointment_time': formatted_time,
            'status': appointment.get('status', 'pending'),
            'consultation_type': appointment.get('consultation_type', 'general').title(),
            'reason': appointment.get('reason', ''),
            'payment_status': payment.get('status', 'unpaid') if payment else 'unpaid',
            'amount': payment.get('amount', 100) if payment else 100,
            'payment_date': formatted_payment_date,
            'payment_id': payment.get('payment_id', 'N/A') if payment else 'N/A',
            'receipt_date': datetime.utcnow().strftime('%d %b %Y %I:%M %p')
        }
        
        return jsonify(receipt_data)
        
    except Exception as e:
        logger.error(f"Error generating receipt: {e}")
        return jsonify({'error': 'Failed to generate receipt'}), 500

# Update the create_appointment function to include payment requirement
def create_appointment():
    """Create new appointment - now requires payment"""
    try:
        data = request.get_json()
        
        # Generate appointment ID
        appointment_id = f"APT{random.randint(1000, 9999)}"
        
        # Parse appointment date
        appointment_date = datetime.fromisoformat(data.get('date').replace('Z', '+00:00'))
        
         # Ensure therapy_type has a default value
        therapy_type = data.get('therapy_type', 'general')
        if not therapy_type or therapy_type.strip() == '':
            therapy_type = 'general'

        appointment_data = {
            'appointment_id': appointment_id,
            'patient_id': session['user_id'],
            'patient_name': f"{session.get('first_name', '')} {session.get('last_name', '')}",
            'therapy_type': data.get('therapy_type'),
            'therapist_id': data.get('therapist_id'),
            'date': appointment_date,
            'reason': data.get('reason'),
            'consultation_type': data.get('consultation_type'),
           # 'status': 'payment_pending',  # New status for unpaid appointments
            'status':'pending',
            'payment_status': 'unpaid',
            'is_demo': False,
            'created_at': datetime.utcnow(),
            'updated_at': datetime.utcnow(),
            'checked_in': False,
            'checked_out': False,
            'check_in_time': None,
            'check_out_time': None,
        }
        
        # Add simplified patient information
        simplified_fields = [
            'patient_age', 'patient_gender', 'patient_phone', 'patient_email', 
            'patient_address'
        ]
        
        for field in simplified_fields:
            if field in data:
                appointment_data[field] = data[field]
        
        current_db = get_db_safe()
        if current_db is not None:
            result = current_db.appointments.insert_one(appointment_data)
            
            # Create notification for patient about payment
            create_notification(
                session['user_id'],
                'Appointment Created - Payment Required',
                f'Your {data.get("therapy_type")} appointment has been created. Please complete the payment to confirm your booking.',
                'info'
            )
            
            logger.info(f"✅ Appointment {appointment_id} created - payment required")
            
            return jsonify({
                'message': 'Appointment created! Please complete the payment to confirm your booking.',
                'appointment_id': appointment_id,
                'status': 'payment_pending',
                'requires_payment': True
            }), 201
        else:
            return jsonify({
                'message': 'Appointment created (demo mode)',
                'appointment_id': appointment_id,
                'status': 'payment_pending',
                'requires_payment': True
            }), 201
            
    except Exception as e:
        logger.error(f"Error creating appointment: {e}")
        return jsonify({'error': 'Failed to book appointment'}), 500


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
            'email_verified': True,
            'last_login': None,
            'created_at': datetime.utcnow(),
            'updated_at': datetime.utcnow()
        }
        
        # Add specialization for doctors
        if data['role'] == 'doctor':
            user_doc['specialization'] = data.get('specialization', 'Acupressure Therapy')
            user_doc['therapy_type'] = data.get('therapy_type', 'acupressure')

        if data['role'] == 'patient':
            user_doc.update({
                'phone': data.get('phone', ''),
                'address': data.get('address', ''),
                'date_of_birth': data.get('date_of_birth', ''),
                'gender': data.get('gender', ''),
              #  'blood_group': data.get('blood_group', ''),
               # 'allergies': data.get('allergies', ''),
                #'medical_conditions': data.get('medical_conditions', ''),
                #'current_medications': data.get('current_medications', ''),
                #'emergency_contact': data.get('emergency_contact', '')
            })

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

        response_data = {
            'message': f'{data["role"].title()} registered successfully!',
            'user_id': user_id,
            'email': data['email'],
            'requires_verification': False
        }
        
        logger.info(f"🎉 Registration successful for: {data['email']}")
        return jsonify(response_data), 201
        
    except Exception as e:
        logger.error(f"🔥 Registration error: {e}")
        return jsonify({'error': 'Internal server error'}), 500

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
        'patient': '/patient-dashboard',
        'doctor': '/doctor-dashboard',
        'receptionist': '/receptionist-dashboard',
        'admin': '/admin-dashboard'
    }
    return redirect_routes.get(role, '/dashboard')

# ========== PATIENT-SPECIFIC ROUTES ==========

@app.route('/api/patient-dashboard-stats')
@login_required
@role_required(['patient'])
def patient_dashboard_stats():
    """Get patient dashboard statistics"""
    try:
        stats = get_dashboard_stats('patient', session['user_id'])
        return jsonify(stats)
    except Exception as e:
        logger.error(f"Error getting patient stats: {e}")
        return jsonify({'error': 'Failed to load stats'}), 500

# @app.route('/api/patient-appointments')
# @login_required
# @role_required(['patient'])
# def get_patient_appointments():
#     """Get patient's appointments"""
#     try:
#         current_db = get_db_safe()
#         patient_id = session['user_id']

#         if current_db is not None:
#             appointments = list(current_db.appointments.find({
#                 'patient_id': patient_id
#             }).sort('date', -1))

#             # Enhance appointment data
#             enhanced_appointments = []
#             for appt in appointments:
#                 doctor = current_db.users.find_one({'user_id': appt.get('therapist_id')})
#                 enhanced_appt = {
#                     'appointment_id': appt.get('appointment_id'),
#                     'therapy_type': appt.get('therapy_type'),
#                     'therapy_name': appt.get('therapy_type', '').title(),
#                     'doctor_name': f"Dr. {doctor.get('first_name', '')} {doctor.get('last_name', '')}" if doctor else 'Not assigned',
#                     'date': appt.get('date'),
#                     'status': appt.get('status'),
#                     'payment_status': appt.get('payment_status', 'unpaid'),
#                     'reason': appt.get('reason', ''),
#                     'consultation_type': appt.get('consultation_type', 'General')
#                 }
#                 enhanced_appointments.append(enhanced_appt)

#             return jsonify(enhanced_appointments)
#         else:
#             # Return demo data
#             return jsonify([{
#                 'appointment_id': 'APT001',
#                 'therapy_type': 'acupressure',
#                 'therapy_name': 'Acupressure',
#                 'doctor_name': 'Dr. Rajesh Sharma',
#                 'date': datetime.now(timezone.utc).isoformat(),
#                 'status': 'pending',
#                 'payment_status': 'unpaid',
#                 'reason': 'Back pain',
#                 'consultation_type': 'General'
#             }])

#     except Exception as e:
#         logger.error(f"Error getting patient appointments: {e}")
#         return jsonify({'error': 'Failed to load appointments'}), 500


@app.route('/api/patient-appointments')
@login_required
@role_required(['patient'])
def get_patient_appointments():
    """Get patient's appointments with enhanced error handling and consistent response format"""
    try:
        current_db = get_db_safe()
        patient_id = session['user_id']
        
        appointments = []
        
        if current_db is not None:
            pipeline = [
                # Match appointments for this patient
                {'$match': {'patient_id': patient_id}},
                
                # Sort by date descending
                {'$sort': {'date': -1}},
                
                # Join with users collection to get doctor details
                {'$lookup': {
                    'from': 'users',
                    'localField': 'therapist_id',
                    'foreignField': 'user_id',
                    'as': 'doctor'
                }},
                
                # Unwind doctor array (convert to object)
                {'$unwind': {'path': '$doctor', 'preserveNullAndEmptyArrays': True}}
            ]
            
            appointments_cursor = current_db.appointments.aggregate(pipeline)
            
            for appt in appointments_cursor:
                try:
                    # Safely get therapy name
                    therapy_type = appt.get('therapy_type', '')
                    therapy_name = therapy_type.title() if therapy_type and isinstance(therapy_type, str) else 'Therapy Session'
                    
                    # Safely get doctor name
                    doctor = appt.get('doctor', {})
                    doctor_name = f"Dr. {doctor.get('first_name', '')} {doctor.get('last_name', '')}" if doctor else 'Not assigned'
                    
                    # Safely handle date
                    appointment_date = appt.get('date')
                    date_iso = appointment_date.isoformat() if isinstance(appointment_date, datetime) else datetime.utcnow().isoformat()
                    
                    enhanced_appt = {
                        'appointment_id': appt.get('appointment_id', f"APT{random.randint(1000, 9999)}"),
                        'therapy_type': therapy_type,
                        'therapy_name': therapy_name,
                        'doctor_name': doctor_name,
                        'doctor_id': appt.get('therapist_id'),
                        'date': date_iso,
                        'status': appt.get('status', 'pending'),
                        'payment_status': appt.get('payment_status', 'unpaid'),
                        'reason': appt.get('reason', ''),
                        'consultation_type': appt.get('consultation_type', 'General'),
                        'checked_in': appt.get('checked_in', False),
                        'checked_out': appt.get('checked_out', False)
                    }
                    appointments.append(enhanced_appt)
                    
                except Exception as appt_error:
                    logger.error(f"Error processing appointment: {appt_error}")
                    continue
        
        # Sort appointments by date, with pending first
        appointments.sort(key=lambda x: (
            0 if x['status'] == 'pending' else 1,
            x['date']
        ))
        
        return jsonify({
            'success': True,
            'appointments': appointments,
            'total': len(appointments)
        })
        
    except Exception as e:
        logger.error(f"Error getting patient appointments: {e}")
        return jsonify({
            'success': False,
            'appointments': [],
            'total': 0,
            'error': 'Failed to load appointments'
        })


@app.route('/api/patient-payments')
@login_required
@role_required(['patient'])
def get_patient_payments():
    """Get patient's payment history with enhanced error handling and complete payment details"""
    try:
        current_db = get_db_safe()
        patient_id = session['user_id']

        payments = []

        if current_db is not None:
            # Use aggregation to get payment details with appointment and doctor info
            pipeline = [
                # Match payments for this patient
                {'$match': {'patient_id': patient_id}},
                
                # Sort by created date
                {'$sort': {'created_at': -1}},
                
                # Join with appointments collection
                {'$lookup': {
                    'from': 'appointments',
                    'localField': 'appointment_id',
                    'foreignField': 'appointment_id',
                    'as': 'appointment'
                }},
                
                # Unwind appointment array
                {'$unwind': {'path': '$appointment', 'preserveNullAndEmptyArrays': True}},
                
                # Join with users collection for doctor details
                {'$lookup': {
                    'from': 'users',
                    'localField': 'appointment.therapist_id',
                    'foreignField': 'user_id',
                    'as': 'doctor'
                }},
                
                # Unwind doctor array
                {'$unwind': {'path': '$doctor', 'preserveNullAndEmptyArrays': True}}
            ]
            
            payment_cursor = current_db.payments.aggregate(pipeline)
            
            for payment in payment_cursor:
                try:
                    # Get basic payment info with safe defaults
                    payment_data = {
                        'payment_id': payment.get('payment_id', f"PAY{random.randint(1000, 9999)}"),
                        'razorpay_payment_id': payment.get('razorpay_payment_id', ''),
                        'appointment_id': payment.get('appointment_id', 'N/A'),
                        'amount': payment.get('amount', 0),
                        'currency': payment.get('currency', 'INR'),
                        'status': payment.get('status', 'unknown'),
                        'created_at': payment.get('created_at', datetime.utcnow()).isoformat(),
                        'paid_at': payment.get('paid_at', '').isoformat() if payment.get('paid_at') else None
                    }
                    
                    # Add appointment details if available
                    appointment = payment.get('appointment', {})
                    if appointment:
                        therapy_type = appointment.get('therapy_type', '')
                        payment_data.update({
                            'therapy_type': therapy_type.title() if therapy_type else 'Unknown Therapy',
                            'appointment_date': appointment.get('date', '').isoformat() if appointment.get('date') else None,
                            'appointment_status': appointment.get('status', 'unknown')
                        })
                    
                    # Add doctor details if available
                    doctor = payment.get('doctor', {})
                    if doctor:
                        payment_data['doctor_name'] = f"Dr. {doctor.get('first_name', '')} {doctor.get('last_name', '')}".strip()
                    else:
                        payment_data['doctor_name'] = 'Doctor Not Found'
                    
                    payments.append(payment_data)
                    
                except Exception as payment_error:
                    logger.error(f"Error processing payment record: {payment_error}")
                    continue

        return jsonify({
            'success': True,
            'payments': payments,
            'total': len(payments),
            'currency': 'INR'
        })

    except Exception as e:
        logger.error(f"Error getting patient payments: {e}")
        return jsonify({
            'success': False,
            'payments': [],
            'total': 0,
            'currency': 'INR',
            'error': 'Failed to load payment history'
        })

@app.route('/patient-dashboard')
@login_required
@role_required(['patient'])
def patient_dashboard():
    """Patient dashboard - Only for patients"""
    stats = get_dashboard_stats('patient', session['user_id'])
    return render_template('patient_dashboard.html', user=session, stats=stats)

@app.route('/book-appointment')
@login_required
@role_required(['patient'])
def book_appointment():
    """Patient appointment booking - Only for patients"""
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
    try:
        return render_template('patient_info.html', user=session)
    except Exception as e:
        logger.error(f"Error loading patient info: {e}")
        return render_template('patient_info.html', user=session)

@app.route('/appointment-receipt/<appointment_id>')
@login_required
def appointment_receipt(appointment_id):
    """Appointment receipt page"""
    return render_template('appointment_receipt.html', appointment_id=appointment_id)

# ========== DOCTOR-SPECIFIC ROUTES ==========

@app.route('/doctor-dashboard')
@login_required
@role_required(['doctor'])
def doctor_dashboard():
    """Doctor dashboard - Only for doctors"""
    stats = get_dashboard_stats('doctor', session['user_id'])
    return render_template('doctor_dashboard.html', user=session, stats=stats)

# ========== RECEPTIONIST-SPECIFIC ROUTES ==========

@app.route('/receptionist-dashboard')
@login_required
@role_required(['receptionist'])
def receptionist_dashboard():
    """Receptionist dashboard - Only for receptionists"""
    stats = get_dashboard_stats('receptionist', session['user_id'])
    return render_template('receptionist_dashboard.html', user=session, stats=stats)

@app.route('/manage-appointments')
@login_required
@role_required(['receptionist', 'admin'])
def manage_appointments():
    """Manage appointments page"""
    return render_template('manage_appointments.html')

# ========== ADMIN-SPECIFIC ROUTES ==========

@app.route('/admin-dashboard')
@login_required
@role_required(['admin'])
def admin_dashboard():
    """Admin dashboard - Only for admins"""
    stats = get_dashboard_stats('admin', session['user_id'])
    return render_template('admin_dashboard.html', user=session, stats=stats)

# ========== GENERAL DASHBOARD ROUTE ==========

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

# ========== ENHANCED NOTIFICATION SYSTEM ==========

@app.route('/api/doctor/appointments')
@login_required
@role_required(['doctor'])
def get_doctor_appointments():
    """Get doctor's appointments with patient details"""
    try:
        current_db = get_db_safe()
        doctor_id = session['user_id']
        
        appointments = []
        stats = {
            'today': 0,
            'totalPatients': 0,
            'completedSessions': 0,
            'pendingFollowups': 0
        }
        
        if current_db is not None:
            # Today's appointments
            today_start = datetime.now(timezone.utc).replace(hour=0, minute=0, second=0, microsecond=0)
            today_end = today_start + timedelta(days=1)
            
            today_appointments = list(current_db.appointments.find({
                'therapist_id': doctor_id,
                'date': {'$gte': today_start, '$lt': today_end},
                'status': {'$in': ['scheduled', 'confirmed']}
            }).sort('date', 1))
            
            # All appointments
            all_appointments = list(current_db.appointments.find({
                'therapist_id': doctor_id
            }).sort('date', -1).limit(10))
            
            # Enhance appointment data
            for appt in all_appointments:
                patient = current_db.users.find_one({'user_id': appt.get('patient_id')})
                if patient:
                    appt['patient_name'] = f"{patient.get('first_name', '')} {patient.get('last_name', '')}"
                    appt['patient_email'] = patient.get('email')
                    appt['patient_phone'] = patient.get('phone', 'N/A')
                    appt['medical_history'] = patient.get('medical_conditions', 'No medical history recorded')
                
                appointments.append({
                    'appointment_id': appt.get('appointment_id'),
                    'patient_name': appt.get('patient_name', 'Unknown Patient'),
                    'patient_email': appt.get('patient_email', ''),
                    'patient_phone': appt.get('patient_phone', 'N/A'),
                    'therapy_type': appt.get('therapy_type', ''),
                    'therapy_name': appt.get('therapy_type', '').title(),
                    'date': appt.get('date'),
                    'reason': appt.get('reason', ''),
                    'status': appt.get('status', 'scheduled'),
                    'consultation_type': appt.get('consultation_type', 'initial'),
                  # 'medical_history': appt.get('medical_history', 'No medical history recorded')
                })
            
            # Calculate stats
            stats['today'] = len(today_appointments)
            stats['totalPatients'] = len(current_db.appointments.distinct('patient_id', {'therapist_id': doctor_id}))
            stats['completedSessions'] = current_db.appointments.count_documents({
                'therapist_id': doctor_id,
                'status': 'completed'
            })
            stats['pendingFollowups'] = current_db.appointments.count_documents({
                'therapist_id': doctor_id,
                'status': 'scheduled'
            })
            
            # Format today's appointments for display
            formatted_today_appointments = []
            for appt in today_appointments:
                patient = current_db.users.find_one({'user_id': appt.get('patient_id')})
                formatted_today_appointments.append({
                    'appointment_id': appt.get('appointment_id'),
                    'patient_name': f"{patient.get('first_name', '')} {patient.get('last_name', '')}" if patient else 'Unknown Patient',
                    'time': appt.get('date').strftime('%I:%M %p') if appt.get('date') else 'Time not set',
                    'therapy': appt.get('therapy_type', '').title(),
                    'status': appt.get('status', 'scheduled')
                })
            
            return jsonify({
                'appointments': appointments,
                'todayAppointments': formatted_today_appointments,
                'stats': stats
            })
        else:
            # Demo data
            demo_appointments = [
                {
                    'appointment_id': 'APT001',
                    'patient_name': 'Rahul Kumar',
                    'patient_email': 'rahul@example.com',
                    'patient_phone': '+91-9876543210',
                    'therapy_name': 'Acupressure',
                    'therapy_type': 'acupressure',
                    'date': (datetime.utcnow() + timedelta(hours=2)).isoformat(),
                    'reason': 'Chronic back pain',
                    'status': 'scheduled',
                    'consultation_type': 'follow-up',
                   # 'medical_history': 'Hypertension, occasional back pain'
                }
            ]
            
            demo_today_appointments = [
                {
                    'appointment_id': 'APT001',
                    'patient_name': 'Rahul Kumar',
                    'time': '10:00 AM',
                    'therapy': 'Acupressure',
                    'status': 'scheduled'
                },
                {
                    'appointment_id': 'APT002',
                    'patient_name': 'Priya Singh',
                    'time': '11:30 AM',
                    'therapy': 'Acupressure',
                    'status': 'scheduled'
                }
            ]
            
            return jsonify({
                'appointments': demo_appointments,
                'todayAppointments': demo_today_appointments,
                'stats': {
                    'today': 2,
                    'totalPatients': 45,
                    'completedSessions': 120,
                    'pendingFollowups': 8
                }
            })
            
    except Exception as e:
        logger.error(f"Error getting doctor appointments: {e}")
        return jsonify({'error': 'Failed to load appointments'}), 500

@app.route('/api/doctor/notifications')
@login_required
@role_required(['doctor'])
def get_doctor_notifications():
    """Get notifications for doctor"""
    try:
        current_db = get_db_safe()
        doctor_id = session['user_id']
        
        notifications = []
        
        if current_db is not None:
            notifications = list(current_db.notifications.find({
                'user_id': doctor_id
            }).sort('created_at', -1).limit(10))
            
            # Convert ObjectId to string
            for notification in notifications:
                notification['_id'] = str(notification['_id'])
        else:
            # Demo notifications
            notifications = [
                {
                    'title': 'New Appointment',
                    'message': 'Rahul Kumar booked Acupressure session',
                    'type': 'info',
                    'is_read': False,
                    'created_at': datetime.now(timezone.utc).isoformat()
                },
                {
                    'title': 'Session Reminder',
                    'message': 'You have appointment with Priya Singh in 30 minutes',
                    'type': 'warning',
                    'is_read': True,
                    'created_at': (datetime.now(timezone.utc) - timedelta(minutes=30)).isoformat()
                }
            ]
        
        return jsonify(notifications)
        
    except Exception as e:
        logger.error(f"Error getting doctor notifications: {e}")
        return jsonify([])
@app.route('/api/receptionist/notifications')
@login_required
@role_required(['receptionist'])
def get_receptionist_notifications():
    """Get notifications for receptionist"""
    try:
        current_db = get_db_safe()
        receptionist_id = session['user_id']
        
        notifications = []
        
        if current_db is not None:
            notifications = list(current_db.notifications.find({
                'user_id': receptionist_id
            }).sort('created_at', -1).limit(10))
            
            # Convert ObjectId to string
            for notification in notifications:
                notification['_id'] = str(notification['_id'])
        else:
            # Demo notifications for receptionist
            notifications = [
                {
                    'title': 'New Appointment Request',
                    'message': 'Rahul Kumar requested Acupressure therapy appointment',
                    'type': 'info',
                    'is_read': False,
                    'created_at': datetime.now(timezone.utc).isoformat()
                },
                {
                    'title': 'Appointment Confirmation Required',
                    'message': '2 pending appointments need confirmation',
                    'type': 'warning',
                    'is_read': False,
                    'created_at': (datetime.now(timezone.utc) - timedelta(hours=1)).isoformat()
                }
            ]
        
        return jsonify(notifications)
        
    except Exception as e:
        logger.error(f"Error getting receptionist notifications: {e}")
        return jsonify([])




# Enhanced Payment Configuration
RAZORPAY_CONFIG = {
    'key_id': os.environ.get('RAZORPAY_KEY_ID'),
    'key_secret': os.environ.get('RAZORPAY_KEY_SECRET'),
    'therapy_prices': {
        'acupressure': 10000,  # 100 INR in paise
        'ayurveda': 10000,
        'homeopathy': 10000,
        'naturopathy': 10000,
        'yoga': 10000,
        'unani': 10000,
        'chiropractic': 10000,
        'physiotherapy': 10000,
        'diet': 10000,
        'herbal': 10000,
        'sound': 10000
    }
}

# Initialize Razorpay client
razorpay_client = razorpay.Client(auth=(RAZORPAY_CONFIG['key_id'], RAZORPAY_CONFIG['key_secret']))

# Enhanced Payment Routes
@app.route('/api/create-payment', methods=['POST'])
@login_required
def create_payment():
    """Create Razorpay payment order"""
    try:
        data = request.get_json()
        appointment_id = data.get('appointment_id')
        therapy_type = data.get('therapy_type')
        
        if not appointment_id or not therapy_type:
            return jsonify({'error': 'Appointment ID and therapy type are required'}), 400
        
        # Get therapy price
        amount = RAZORPAY_CONFIG['therapy_prices'].get(therapy_type, 10000)
        
        # Create Razorpay order
        order_data = {
            'amount': amount,
            'currency': 'INR',
            'receipt': f'receipt_{appointment_id}',
            'notes': {
                'appointment_id': appointment_id,
                'therapy_type': therapy_type,
                'patient_id': session['user_id']
            }
        }
        
        order = razorpay_client.order.create(data=order_data)
        
        # Store payment record in database
        current_db = get_db_safe()
        if current_db is not None:
            payment_doc = {
                'payment_id': order['id'],
                'appointment_id': appointment_id,
                'patient_id': session['user_id'],
                'amount': amount / 1,  # Convert to INR
                'currency': 'INR',
                'status': 'created',
                'therapy_type': therapy_type,
                'created_at': datetime.utcnow(),
                'updated_at': datetime.utcnow()
            }
            current_db.payments.insert_one(payment_doc)
        
        return jsonify({
            'order_id': order['id'],
            'amount': order['amount'],
            'currency': order['currency'],
            'key_id': RAZORPAY_CONFIG['key_id']
        })
        
    except Exception as e:
        logger.error(f"Error creating payment: {e}")
        return jsonify({'error': 'Failed to create payment'}), 500

@app.route('/api/verify-payment', methods=['POST'])
@login_required
def verify_payment():
    """Verify Razorpay payment signature"""
    try:
        data = request.get_json()
        payment_id = data.get('razorpay_payment_id')
        order_id = data.get('razorpay_order_id')
        signature = data.get('razorpay_signature')
        
        # Verify payment signature
        params_dict = {
            'razorpay_order_id': order_id,
            'razorpay_payment_id': payment_id,
            'razorpay_signature': signature
        }
        
        try:
            razorpay_client.utility.verify_payment_signature(params_dict)
        except razorpay.errors.SignatureVerificationError:
            return jsonify({'error': 'Payment verification failed'}), 400
        
        # Update payment status in database
        current_db = get_db_safe()
        if current_db is not None:
            # Update payment record
            current_db.payments.update_one(
                {'payment_id': order_id},
                {'$set': {
                    'razorpay_payment_id': payment_id,
                    'status': 'paid',
                    'paid_at': datetime.utcnow(),
                    'updated_at': datetime.utcnow()
                }}
            )
            
            # Get appointment details from payment
            payment = current_db.payments.find_one({'payment_id': order_id})
            if payment:
                # Update appointment status to pending (waiting for receptionist confirmation)
                current_db.appointments.update_one(
                    {'appointment_id': payment['appointment_id']},
                    {'$set': {
                        'status': 'pending',
                        'payment_status': 'paid',
                        'payment_id': order_id,
                        'updated_at': datetime.utcnow()
                    }}
                )
                
                # Create notification for receptionist
                create_notification(
                    'REC001',
                    'New Paid Appointment Request',
                    f'New appointment request with payment received. Appointment ID: {payment["appointment_id"]}',
                    'success'
                )
                
                # Create notification for patient
                create_notification(
                    session['user_id'],
                    'Payment Successful',
                    f'Payment received for appointment {payment["appointment_id"]}. Waiting for receptionist confirmation.',
                    'success'
                )
        
        return jsonify({
            'message': 'Payment verified successfully',
            'appointment_id': payment['appointment_id'] if payment else None
        })
        
    except Exception as e:
        logger.error(f"Error verifying payment: {e}")
        return jsonify({'error': 'Payment verification failed'}), 500

# Enhanced appointment creation with payment requirement
@app.route('/api/appointments', methods=['POST'])
@login_required
def create_appointment():
    """Create new appointment - now requires payment"""
    try:
        data = request.get_json()
        
        # Generate appointment ID
        appointment_id = f"APT{random.randint(1000, 9999)}"
        
        # Parse appointment date
        appointment_date = datetime.fromisoformat(data.get('date').replace('Z', '+00:00'))
        
        appointment_data = {
            'appointment_id': appointment_id,
            'patient_id': session['user_id'],
            'patient_name': f"{session.get('first_name', '')} {session.get('last_name', '')}",
            'therapy_type': data.get('therapy_type'),
            'therapist_id': data.get('therapist_id'),
            'date': appointment_date,
            'reason': data.get('reason'),
            'consultation_type': data.get('consultation_type'),
            'status': 'payment_pending',
            'payment_status': 'unpaid',
            'is_demo': False,
            'created_at': datetime.utcnow(),
            'updated_at': datetime.utcnow()
        }
        
        # Add patient information
        simplified_fields = [
            'patient_age', 'patient_gender', 'patient_phone', 'patient_email', 
            'patient_address'
        ]
        
        for field in simplified_fields:
            if field in data:
                appointment_data[field] = data[field]
        
        current_db = get_db_safe()
        if current_db is not None:
            result = current_db.appointments.insert_one(appointment_data)
            
            # Create notification for patient about payment
            create_notification(
                session['user_id'],
                'Appointment Created - Payment Required',
                f'Your {data.get("therapy_type")} appointment has been created. Please complete the payment to confirm your booking.',
                'info'
            )
            
            logger.info(f"✅ Appointment {appointment_id} created - payment required")
            
            return jsonify({
                'message': 'Appointment created! Please complete the payment to confirm your booking.',
                'appointment_id': appointment_id,
                'status': 'payment_pending',
                'requires_payment': True
            }), 201
        else:
            return jsonify({
                'message': 'Appointment created (demo mode)',
                'appointment_id': appointment_id,
                'status': 'payment_pending',
                'requires_payment': True
            }), 201
            
    except Exception as e:
        logger.error(f"Error creating appointment: {e}")
        return jsonify({'error': 'Failed to book appointment'}), 500

# Enhanced receptionist appointment confirmation
@app.route('/api/receptionist/appointments/<appointment_id>/confirm', methods=['POST'])
@login_required
@role_required(['receptionist', 'admin'])
def confirm_appointment_api(appointment_id):
    """Confirm an appointment with enhanced notifications"""
    try:
        data = request.get_json() or {}
        scheduled_time = data.get('scheduled_time')
        
        current_db = get_db_safe()
        
        if current_db is None:
            return jsonify({'message': 'Appointment confirmed (demo mode)'})
        
        # Get appointment details first
        appointment = current_db.appointments.find_one({'appointment_id': appointment_id})
        if not appointment:
            return jsonify({'error': 'Appointment not found'}), 404
        
        # Check if payment is completed
        if appointment.get('payment_status') != 'paid':
            return jsonify({'error': 'Cannot confirm appointment. Payment not completed.'}), 400
        
        # Update appointment status
        update_data = {
            'status': 'confirmed',
            'confirmed_by': session['user_id'],
            'confirmed_at': datetime.utcnow(),
            'updated_at': datetime.utcnow()
        }
        
        if scheduled_time:
            update_data['scheduled_time'] = scheduled_time
        
        result = current_db.appointments.update_one(
            {'appointment_id': appointment_id},
            {'$set': update_data}
        )
        
        if result.modified_count == 0:
            return jsonify({'error': 'Appointment not found'}), 404
        
        # Get updated appointment details
        appointment = current_db.appointments.find_one({'appointment_id': appointment_id})
        patient = current_db.users.find_one({'user_id': appointment.get('patient_id')})
        doctor = current_db.users.find_one({'user_id': appointment.get('therapist_id')})
        
        # Send confirmation emails
        if patient:
            send_appointment_confirmation_email(
                patient['email'],
                f"{patient.get('first_name', '')} {patient.get('last_name', '')}",
                appointment.get('date').strftime('%d %b %Y at %I:%M %p'),
                appointment.get('therapy_type', '').title(),
                f"Dr. {doctor.get('first_name', '')} {doctor.get('last_name', '')}" if doctor else 'Doctor'
            )
            
            # Create notification for patient
            create_notification(
                patient['user_id'],
                'Appointment Confirmed! 🎉',
                f'Your {appointment.get("therapy_type", "therapy")} appointment has been confirmed for {appointment.get("date").strftime("%d %b %Y at %I:%M %p")}.',
                'success'
            )
        
        # Notify doctor
        if doctor:
            send_doctor_notification_email(
                doctor['email'],
                f"{doctor.get('first_name', '')} {doctor.get('last_name', '')}",
                f"{patient.get('first_name', '')} {patient.get('last_name', '')}" if patient else 'Patient',
                appointment.get('date').strftime('%d %b %Y at %I:%M %p'),
                appointment.get('therapy_type', '').title()
            )
            
            create_notification(
                doctor['user_id'],
                'New Confirmed Appointment',
                f'New appointment confirmed with {patient.get("first_name", "Patient") if patient else "Patient"} for {appointment.get("therapy_type")} on {appointment.get("date").strftime("%d %b %Y at %I:%M %p")}.',
                'info'
            )
        
        logger.info(f"✅ Appointment {appointment_id} confirmed by {session['user_id']}")
        
        return jsonify({
            'message': 'Appointment confirmed successfully',
            'appointment_id': appointment_id,
            'patient_notified': True,
            'doctor_notified': True if doctor else False
        })
        
    except Exception as e:
        logger.error(f"Error confirming appointment: {e}")
        return jsonify({'error': 'Failed to confirm appointment'}), 500

# Refund API for cancellations within 2 days
@app.route('/api/appointments/<appointment_id>/request-refund', methods=['POST'])
@login_required
def request_refund(appointment_id):
    """Request refund for appointment cancellation within 2 days"""
    try:
        current_db = get_db_safe()
        
        if current_db is None:
            return jsonify({'message': 'Refund request recorded (demo mode)'})
        
        # Get appointment details
        appointment = current_db.appointments.find_one({'appointment_id': appointment_id})
        if not appointment:
            return jsonify({'error': 'Appointment not found'}), 404
        
        # Check if user owns this appointment
        if appointment.get('patient_id') != session['user_id']:
            return jsonify({'error': 'Unauthorized'}), 403
        
        # Check if appointment is within 2 days
        appointment_date = appointment.get('date')
        now = datetime.utcnow()
        time_diff = appointment_date - now
        
        if time_diff.days > 2:
            return jsonify({'error': 'Refund only available for cancellations within 2 days of appointment'}), 400
        
        # Check if payment was made
        payment = current_db.payments.find_one({'appointment_id': appointment_id})
        if not payment or payment.get('status') != 'paid':
            return jsonify({'error': 'No payment found or payment not completed'}), 400
        
        # Update appointment status to refund requested
        current_db.appointments.update_one(
            {'appointment_id': appointment_id},
            {'$set': {
                'status': 'refund_requested',
                'refund_requested_at': datetime.utcnow(),
                'updated_at': datetime.utcnow()
            }}
        )
        
        # Create notification for receptionist
        create_notification(
            'REC001',
            'Refund Requested',
            f'Patient {session.get("first_name")} {session.get("last_name")} requested refund for appointment {appointment_id}.',
            'warning'
        )
        
        # Create notification for patient
        create_notification(
            session['user_id'],
            'Refund Request Submitted',
            'Your refund request has been submitted. It will be processed within 3-5 business days.',
            'info'
        )
        
        logger.info(f"✅ Refund requested for appointment: {appointment_id}")
        
        return jsonify({
            'message': 'Refund request submitted successfully. It will be processed within 3-5 business days.',
            'appointment_id': appointment_id
        })
        
    except Exception as e:
        logger.error(f"Error requesting refund: {e}")
        return jsonify({'error': 'Failed to request refund'}), 500



@app.route('/api/patient-dashboard-stats')
@login_required
@role_required(['patient'])
def patient_dashboard_stats_api():
    """Get patient-specific dashboard statistics"""
    try:
        current_db = get_db_safe()
        patient_id = session['user_id']
        
        stats = {
            'upcoming_appointments': 0,
            'completed_sessions': 0,
            'pending_appointments': 0,
            'therapies_tried': 0
        }
        
        if current_db is not None:
            # Upcoming appointments
            stats['upcoming_appointments'] = current_db.appointments.count_documents({
                'patient_id': patient_id,
                'status': {'$in': ['scheduled', 'confirmed']}
            })
            
            # Completed sessions
            stats['completed_sessions'] = current_db.appointments.count_documents({
                'patient_id': patient_id,
                'status': 'completed'
            })
            
            # Pending appointments
            stats['pending_appointments'] = current_db.appointments.count_documents({
                'patient_id': patient_id,
                'status': 'pending'
            })
            
            # Therapies tried
            stats['therapies_tried'] = len(current_db.appointments.distinct('therapy_type', {
                'patient_id': patient_id
            }))
        
        return jsonify(stats)
        
    except Exception as e:
        logger.error(f"Error getting patient stats: {e}")
        return jsonify({'error': 'Failed to load statistics'}), 500

@app.route('/api/receptionist/patient-appointments/<patient_id>')
@login_required
@role_required(['receptionist', 'admin'])
def get_patient_appointments_history(patient_id):
    """Get complete appointment history for a specific patient - FOR RECEPTIONIST"""
    try:
        current_db = get_db_safe()
        
        appointments = []
        
        if current_db is not None:
            # Get all appointments for this patient
            appointments_cursor = current_db.appointments.find(
                {'patient_id': patient_id}
            ).sort('date', -1)
            
            for appt in appointments_cursor:
                # Get doctor details
                doctor = current_db.users.find_one({'user_id': appt.get('therapist_id')})
                doctor_name = f"Dr. {doctor.get('first_name', '')} {doctor.get('last_name', '')}" if doctor else 'Unknown Doctor'
                
                # Get patient details
                patient = current_db.users.find_one({'user_id': patient_id})
                patient_name = f"{patient.get('first_name', '')} {patient.get('last_name', '')}" if patient else 'Unknown Patient'
                
                appointments.append({
                    'appointment_id': appt.get('appointment_id'),
                    'patient_id': patient_id,
                    'patient_name': patient_name,
                    'therapy_name': appt.get('therapy_type', '').title(),
                    'doctor_name': doctor_name,
                    'date': appt.get('date').isoformat() if appt.get('date') else '',
                    'reason': appt.get('reason', ''),
                    'status': appt.get('status', 'scheduled'),
                    'consultation_type': appt.get('consultation_type', 'general'),
                    'created_at': appt.get('created_at').isoformat() if appt.get('created_at') else ''
                })
        
        return jsonify(appointments)
        
    except Exception as e:
        logger.error(f"Error getting patient appointment history: {e}")
        return jsonify([])        

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
                        'status': 'pending',
                        'consultation_type': 'follow-up'
                    }
                ]
                return jsonify(demo_appointments)
                
        except Exception as e:
            logger.error(f"Error fetching appointments: {e}")
            return jsonify([])
    
    elif request.method == 'POST':
        # Create new appointment with enhanced notification system
        return create_appointment()

def create_appointment():
    """Create new appointment with enhanced notification system"""
    try:
        data = request.get_json()
        
        # Generate appointment ID
        appointment_id = f"APT{random.randint(1000, 9999)}"
        
        # Parse appointment date
        appointment_date = datetime.fromisoformat(data.get('date').replace('Z', '+00:00'))
        
      

        appointment_data = {
            'appointment_id': appointment_id,
            'patient_id': session['user_id'],
            'patient_name': f"{session.get('first_name', '')} {session.get('last_name', '')}",
            'therapy_type': data.get('therapy_type'),
            'therapist_id': data.get('therapist_id'),
            'date': appointment_date,
            'reason': data.get('reason'),
            'consultation_type': data.get('consultation_type'),
            'status': 'pending',  # Receptionist confirmation required
            'is_demo': False,  # Mark as real appointment
            'created_at': datetime.utcnow(),
            'updated_at': datetime.utcnow()
        }
        # Add simplified patient information
        simplified_fields = [
            'patient_age', 'patient_gender', 'patient_phone', 'patient_email', 
            'patient_address'
        ]
        
        for field in simplified_fields:
            if field in data:
                appointment_data[field] = data[field]
        
        current_db = get_db_safe()
        if current_db is not None:
            result = current_db.appointments.insert_one(appointment_data)
            
            # Create notification for receptionist
            create_notification(
                'REC001',  # Receptionist user ID
                'New Appointment Request',
                f'New appointment request from {appointment_data["patient_name"]} for {data.get("therapy_type")} therapy. Please review and confirm.',
                'info'
            )
            
            # Create notification for patient
            create_notification(
                session['user_id'],
                'Appointment Request Submitted',
                f'Your {data.get("therapy_type")} appointment request has been submitted. Waiting for receptionist confirmation.',
                'info'
            )
            
            # Get doctor details for notification
            doctor = current_db.users.find_one({'user_id': data.get('therapist_id')})
            if doctor:
                create_notification(
                    doctor['user_id'],
                    'New Appointment Request',
                    f'New appointment request from {appointment_data["patient_name"]} for {data.get("therapy_type")}. Waiting for confirmation.',
                    'info'
                )
            
            logger.info(f"✅ Appointment {appointment_id} created and notifications sent")
            
            return jsonify({
                'message': 'Appointment booked successfully! Waiting for receptionist confirmation.',
                'appointment_id': appointment_id,
                'status': 'pending'
            }), 201
        else:
            return jsonify({
                'message': 'Appointment request recorded (demo mode)',
                'appointment_id': appointment_id,
                'status': 'pending'
            }), 201
            
    except Exception as e:
        logger.error(f"Error creating appointment: {e}")
        return jsonify({'error': 'Failed to book appointment'}), 500

@app.route('/api/patient-data')
@login_required
@role_required(['patient'])
def patient_data():
    """Get patient data for patient info page"""
    try:
        current_db = get_db_safe()
        user_id = session['user_id']
        
        if current_db is not None:
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
        
        if current_db is not None:
            therapists = list(current_db.users.find({'role': 'doctor'}))
            therapist_list = []
            for therapist in therapists:
                therapist_list.append({
                    'user_id': therapist.get('user_id'),
                    'name': f"Dr. {therapist.get('first_name', '')} {therapist.get('last_name', '')}",
                    'specialization': therapist.get('specialization', 'Therapy Specialist'),
                   # 'therapy_type': therapist.get('therapy_type', 'acupressure'),
                    'email': therapist.get('email')
                })
            return jsonify(therapist_list)
        
        # Demo therapists data
        demo_therapists = [
            {
                'user_id': 'DOC001',
                'name': 'Dr. Rajesh Sharma',
                'specialization': 'Acupressure Specialist',
             #   'therapy_type': 'acupressure',
                'email': 'dr.sharma@dsvv.ac.in'
            },
            {
                'user_id': 'DOC002',
                'name': 'Dr. Priya Gupta',
                'specialization': 'Ayurveda Expert',
               # 'therapy_type': 'ayurveda',
                'email': 'dr.gupta@dsvv.ac.in'
            },
            {
                'user_id': 'DOC003',
                'name': 'Dr. Amit Verma',
                'specialization': 'Homeopathy Specialist',
            #    'therapy_type': 'homeopathy',
                'email': 'dr.verma@dsvv.ac.in'
            }
        ]
        return jsonify(demo_therapists)
        
    except Exception as e:
        logger.error(f"Error fetching therapists: {e}")
        return jsonify([])

@app.route('/api/update-patient-info', methods=['POST'])
@login_required
@role_required(['patient'])
def update_patient_info():
    """Update patient information"""
    try:
        data = request.get_json()
        user_id = session['user_id']
        
        current_db = get_db_safe()
        if current_db is not None:
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

@app.route('/api/receptionist/patients')
@login_required
@role_required(['receptionist', 'admin'])
def get_receptionist_patients():
    """Get all patients for receptionist view"""
    try:
        current_db = get_db_safe()
        patients = []
        
        if current_db:
            patients_cursor = current_db.users.find({'role': 'patient'})
            patients = list(patients_cursor)
            
            # Remove sensitive information
            for patient in patients:
                if 'password' in patient:
                    del patient['password']
                patient['_id'] = str(patient['_id'])
        
        return jsonify(patients)
        
    except Exception as e:
        logger.error(f"Error getting patients: {e}")
        return jsonify([])

@app.route('/api/receptionist/appointments')
@login_required
@role_required(['receptionist', 'admin'])
def get_receptionist_appointments():
    """Get all appointments for receptionist view - SIMPLIFIED"""
    try:
        current_db = get_db_safe()
        
        # Get filter parameters
        status_filter = request.args.get('status', 'all')
        
        # Build query - SIMPLIFIED: removed therapy filter
        query = {}
        if status_filter != 'all':
            query['status'] = status_filter
        
        # Remove demo appointments filter
        query['is_demo'] = {'$ne': True}
        
        appointments = []
        if current_db is not None:
            appointment_cursor = current_db.appointments.find(query).sort('date', 1)
            appointments = list(appointment_cursor)
            
            # Enhance appointment data with user information
            for appointment in appointments:
                appointment['_id'] = str(appointment['_id'])
                
                # Get patient details - SIMPLIFIED
                patient = current_db.users.find_one({'user_id': appointment.get('patient_id')})
                if patient:
                    appointment['patient_name'] = f"{patient.get('first_name', '')} {patient.get('last_name', '')}"
                    appointment['patient_email'] = patient.get('email')
                    appointment['patient_phone'] = patient.get('phone', 'N/A')
                    # Removed extra patient fields
                
                # Get doctor details
                try:
                    doctor = current_db.users.find_one({'user_id': appointment.get('therapist_id')})
                except Exception as _e:
                    logger.warning(f"Error fetching doctor for appointment {appointment.get('appointment_id')}: {_e}")
                    doctor = None

                if doctor:
                    appointment['doctor_name'] = f"Dr. {doctor.get('first_name', '')} {doctor.get('last_name', '')}"
                else:
                    appointment['doctor_name'] = 'Doctor Not Found'

                # Determine a safe therapy name. Prefer explicit appointment therapy_type,
                # otherwise fall back to doctor's specialization, then a general label.
                try:
                    therapy_type = appointment.get('therapy_type')
                    therapy_name_source = None
                    if therapy_type and isinstance(therapy_type, str) and therapy_type.strip():
                        therapy_name_source = therapy_type
                    elif doctor and doctor.get('specialization'):
                        therapy_name_source = doctor.get('specialization')
                    else:
                        therapy_name_source = 'General Therapy'

                    appointment['therapy_name'] = (therapy_name_source or 'General Therapy').title()
                except Exception as e_inner:
                    logger.warning(f"Error determining therapy name for appointment {appointment.get('appointment_id')}: {e_inner}")
                    appointment['therapy_name'] = 'General Therapy'
        else:
            # When no database, return empty array instead of demo data
            appointments = []
        
        # Calculate stats based on real appointments only
        stats = {
            'total': len(appointments),
            'pending': len([a for a in appointments if a.get('status') == 'pending']),
            'confirmed': len([a for a in appointments if a.get('status') == 'confirmed']),
            'completed': len([a for a in appointments if a.get('status') == 'completed']),
            'cancelled': len([a for a in appointments if a.get('status') == 'cancelled']),
            'today': len([a for a in appointments if a.get('date') and a.get('date').date() == datetime.now(timezone.utc).date()])
        }
        
        return jsonify({
            'appointments': appointments,
            'stats': stats
        })
        
    except Exception as e:
        logger.error(f"Error getting receptionist appointments: {e}")
        return jsonify({'error': 'Failed to load appointments'}), 500

@app.route('/api/notifications')
@login_required
def get_notifications():
    """Get notifications for current user"""
    try:
        current_db = get_db_safe()
        
        if current_db is None:
            # Return demo notifications
            demo_notifications = [
                {
                    'title': 'New Appointment Request',
                    'message': 'Rahul Kumar requested Acupressure therapy',
                    'type': 'info',
                    'is_read': False,
                    'created_at': datetime.now(timezone.utc).isoformat()
                },
                {
                    'title': 'Appointment Confirmed',
                    'message': 'You confirmed appointment with Priya Singh',
                    'type': 'success',
                    'is_read': True,
                    'created_at': (datetime.now(timezone.utc) - timedelta(hours=1)).isoformat()
                }
            ]
            return jsonify(demo_notifications)
        
        # Get notifications from database
        notifications = list(current_db.notifications.find(
            {'user_id': session['user_id']}
        ).sort('created_at', -1).limit(20))
        
        # Convert ObjectId to string
        for notification in notifications:
            notification['_id'] = str(notification['_id'])
        
        return jsonify(notifications)
        
    except Exception as e:
        logger.error(f"Error getting notifications: {e}")
        return jsonify([])

@app.route('/api/notifications/read', methods=['POST'])
@login_required
def mark_all_notifications_read():
    """Mark all notifications as read"""
    try:
        current_db = get_db_safe()
        
        if current_db is not None:
            current_db.notifications.update_many(
                {'user_id': session['user_id'], 'is_read': False},
                {'$set': {'is_read': True}}
            )
        
        return jsonify({'message': 'All notifications marked as read'})
        
    except Exception as e:
        logger.error(f"Error marking notifications as read: {e}")
        return jsonify({'error': 'Failed to mark notifications as read'}), 500
    
@app.route('/api/appointments/<appointment_id>/cancel', methods=['POST'])
@login_required
def cancel_appointment(appointment_id):
    """Cancel an appointment"""
    try:
        current_db = get_db_safe()
        
        if current_db is None:
            return jsonify({'message': 'Appointment cancelled (demo mode)'})
        
        # Get appointment details
        appointment = current_db.appointments.find_one({'appointment_id': appointment_id})
        if not appointment:
            return jsonify({'error': 'Appointment not found'}), 404
        
        # Check if user owns this appointment or has permission
        if session['role'] == 'patient' and appointment.get('patient_id') != session['user_id']:
            return jsonify({'error': 'Unauthorized to cancel this appointment'}), 403
        
        # Update appointment status
        result = current_db.appointments.update_one(
            {'appointment_id': appointment_id},
            {'$set': {
                'status': 'cancelled',
                'cancelled_by': session['user_id'],
                'cancelled_at': datetime.utcnow(),
                'updated_at': datetime.utcnow()
            }}
        )
        
        if result.modified_count == 0:
            return jsonify({'error': 'Failed to cancel appointment'}), 400
        
        # Create notifications
        create_notification(
            session['user_id'],
            'Appointment Cancelled',
            f'Your {appointment.get("therapy_type", "therapy")} appointment has been cancelled.',
            'warning'
        )
        
        # Notify receptionist if applicable
        if session['role'] == 'patient':
            create_notification(
                'REC001',
                'Appointment Cancelled by Patient',
                f'Appointment {appointment_id} for {appointment.get("therapy_type")} has been cancelled by patient.',
                'warning'
            )
        
        # If payment was made, handle refund (you can implement this based on your Razorpay setup)
        payment = current_db.payments.find_one({'appointment_id': appointment_id})
        if payment and payment.get('status') == 'paid':
            # Here you can implement Razorpay refund logic
            create_notification(
                session['user_id'],
                'Refund Initiated',
                'Refund for your cancelled appointment will be processed within 5-7 business days.',
                'info'
            )
        
        logger.info(f"✅ Appointment {appointment_id} cancelled by {session['user_id']}")
        
        return jsonify({
            'message': 'Appointment cancelled successfully',
            'appointment_id': appointment_id
        })
        
    except Exception as e:
        logger.error(f"Error cancelling appointment: {e}")
        return jsonify({'error': 'Failed to cancel appointment'}), 500    
@app.route('/api/receptionist/patients/<patient_id>/history')
@login_required
@role_required(['receptionist', 'admin'])
def get_patient_history(patient_id):
    """Get complete patient history with appointments"""
    try:
        current_db = get_db_safe()
        
        if current_db is None:
            return jsonify({'error': 'Database not available'}), 500
        
        # Get patient details
        patient = current_db.users.find_one({'user_id': patient_id})
        if not patient:
            return jsonify({'error': 'Patient not found'}), 404
        
        # Get patient's appointments
        appointments = list(current_db.appointments.find(
            {'patient_id': patient_id}
        ).sort('date', -1))
        
        # Enhance appointment data
        enhanced_appointments = []
        for appt in appointments:
            # Get doctor details
            doctor = current_db.users.find_one({'user_id': appt.get('therapist_id')})
            doctor_name = f"Dr. {doctor.get('first_name', '')} {doctor.get('last_name', '')}" if doctor else 'Unknown Doctor'
            
            enhanced_appointments.append({
                'appointment_id': appt.get('appointment_id'),
                'date': appt.get('date'),
                'doctor_name': doctor_name,
                'therapy_name': appt.get('therapy_type', '').title(),
                'status': appt.get('status', 'scheduled'),
                'reason': appt.get('reason', '')
            })
        
        patient_history = {
            'patient_id': patient_id,
            'patient_name': f"{patient.get('first_name', '')} {patient.get('last_name', '')}",
            'phone': patient.get('phone', 'N/A'),
            'email': patient.get('email'),
            'total_appointments': len(appointments),
            'last_visit': max([appt.get('date') for appt in appointments]) if appointments else None,
            'appointments': enhanced_appointments
        }
        
        return jsonify(patient_history)
        
    except Exception as e:
        logger.error(f"Error getting patient history: {e}")
        return jsonify({'error': 'Failed to load patient history'}), 500


@app.route('/api/receptionist/appointments/<appointment_id>/check-in', methods=['POST'])
@login_required
@role_required(['receptionist', 'admin'])
def check_in_appointment(appointment_id):
    """Check in patient for appointment"""
    try:
        current_db = get_db_safe()
        
        if current_db is None:
            return jsonify({'message': 'Patient checked in (demo mode)'})
        
        # Update appointment status
        result = current_db.appointments.update_one(
            {'appointment_id': appointment_id},
            {'$set': {
                'checked_in': True,
                'checked_in_at': datetime.utcnow(),
                'updated_at': datetime.utcnow()
            }}
        )
        
        if result.modified_count == 0:
            return jsonify({'error': 'Appointment not found'}), 404
        
        # Get appointment details for notification
        appointment = current_db.appointments.find_one({'appointment_id': appointment_id})
        if appointment:
            doctor = current_db.users.find_one({'user_id': appointment.get('therapist_id')})
            
            # Create notification for doctor
            if doctor:
                create_notification(
                    doctor['user_id'],
                    'Patient Checked In',
                    f'Patient {appointment.get("patient_name", "")} has checked in for their {appointment.get("therapy_type")} appointment.',
                    'info'
                )
        
        logger.info(f"✅ Patient checked in for appointment: {appointment_id}")
        
        return jsonify({
            'message': 'Patient checked in successfully',
            'appointment_id': appointment_id
        })
        
    except Exception as e:
        logger.error(f"Error checking in patient: {e}")
        return jsonify({'error': 'Failed to check in patient'}), 500


@app.route('/api/receptionist/appointments/<appointment_id>', methods=['GET'])
@login_required
@role_required(['receptionist', 'admin'])
def get_appointment_details(appointment_id):
    """Get detailed appointment information for receptionist"""
    try:
        current_db = get_db_safe()
        
        if current_db is None:
            return jsonify({
                'success': False,
                'error': 'Database not available'
            }), 500
        
        # Get appointment with patient and doctor details using aggregation
        pipeline = [
            {'$match': {'appointment_id': appointment_id}},
            {'$lookup': {
                'from': 'users',
                'localField': 'patient_id',
                'foreignField': 'user_id',
                'as': 'patient'
            }},
            {'$lookup': {
                'from': 'users',
                'localField': 'therapist_id',
                'foreignField': 'user_id',
                'as': 'doctor'
            }},
            {'$lookup': {
                'from': 'payments',
                'localField': 'appointment_id',
                'foreignField': 'appointment_id',
                'as': 'payment'
            }},
            {'$unwind': {'path': '$patient', 'preserveNullAndEmptyArrays': True}},
            {'$unwind': {'path': '$doctor', 'preserveNullAndEmptyArrays': True}},
            {'$unwind': {'path': '$payment', 'preserveNullAndEmptyArrays': True}}
        ]
        
        appointment = next(current_db.appointments.aggregate(pipeline), None)
        
        if not appointment:
            return jsonify({
                'success': False,
                'error': 'Appointment not found'
            }), 404
            
        # Format the response
        formatted_appointment = {
            'appointment_id': appointment.get('appointment_id'),
            'date': appointment.get('date').isoformat() if appointment.get('date') else None,
            'status': appointment.get('status', 'pending'),
            'therapy_type': appointment.get('therapy_type', ''),
            'therapy_name': appointment.get('therapy_type', '').title(),
            'reason': appointment.get('reason', ''),
            'consultation_type': appointment.get('consultation_type', 'General'),
            'payment_status': appointment.get('payment_status', 'unpaid'),
            'checked_in': appointment.get('checked_in', False),
            'checked_out': appointment.get('checked_out', False),
            'patient': {
                'id': appointment.get('patient', {}).get('user_id'),
                'name': f"{appointment.get('patient', {}).get('first_name', '')} {appointment.get('patient', {}).get('last_name', '')}",
                'email': appointment.get('patient', {}).get('email'),
                'phone': appointment.get('patient', {}).get('phone', 'N/A')
            },
            'doctor': {
                'id': appointment.get('doctor', {}).get('user_id'),
                'name': f"Dr. {appointment.get('doctor', {}).get('first_name', '')} {appointment.get('doctor', {}).get('last_name', '')}",
                'specialization': appointment.get('doctor', {}).get('specialization', 'General')
            },
            'payment': {
                'id': appointment.get('payment', {}).get('payment_id'),
                'amount': appointment.get('payment', {}).get('amount'),
                'status': appointment.get('payment', {}).get('status', 'unpaid'),
                'paid_at': appointment.get('payment', {}).get('paid_at', '').isoformat() if appointment.get('payment', {}).get('paid_at') else None
            }
        }
        
        return jsonify({
            'success': True,
            'appointment': formatted_appointment
        })
        
    except Exception as e:
        logger.error(f"Error getting appointment details: {e}")
        return jsonify({
            'success': False,
            'error': 'Failed to load appointment details'
        }), 500

@app.route('/api/receptionist/notifications/read-all', methods=['POST'])
@login_required
@role_required(['receptionist'])
def mark_receptionist_notifications_read():
    """Mark all receptionist notifications as read"""
    try:
        current_db = get_db_safe()
        
        if current_db is not None:
            result = current_db.notifications.update_many(
                {
                    'user_id': session['user_id'],
                    'is_read': False
                },
                {'$set': {'is_read': True}}
            )
            
            return jsonify({
                'success': True,
                'message': f'Marked {result.modified_count} notifications as read'
            })
        
        return jsonify({
            'success': True,
            'message': 'Marked all notifications as read (demo mode)'
        })
        
    except Exception as e:
        logger.error(f"Error marking notifications as read: {e}")
        return jsonify({
            'success': False,
            'error': 'Failed to mark notifications as read'
        }), 500

@app.route('/api/receptionist/appointments/<appointment_id>/confirm-payment', methods=['POST'])
@login_required
@role_required(['receptionist', 'admin'])
def confirm_appointment_payment(appointment_id):
    """Confirm payment for an appointment"""
    try:
        current_db = get_db_safe()
        
        if current_db is None:
            return jsonify({
                'success': False,
                'error': 'Database not available'
            }), 500
            
        # Get appointment
        appointment = current_db.appointments.find_one({'appointment_id': appointment_id})
        if not appointment:
            return jsonify({
                'success': False,
                'error': 'Appointment not found'
            }), 404
            
        # Update appointment payment status
        result = current_db.appointments.update_one(
            {'appointment_id': appointment_id},
            {'$set': {
                'payment_status': 'paid',
                'payment_confirmed_by': session['user_id'],
                'payment_confirmed_at': datetime.utcnow(),
                'updated_at': datetime.utcnow()
            }}
        )
        
        if result.modified_count > 0:
            # Update payment record if exists
            payment = current_db.payments.find_one({'appointment_id': appointment_id})
            if payment:
                current_db.payments.update_one(
                    {'appointment_id': appointment_id},
                    {'$set': {
                        'status': 'paid',
                        'confirmed_by': session['user_id'],
                        'confirmed_at': datetime.utcnow(),
                        'updated_at': datetime.utcnow()
                    }}
                )
            
            # Create notifications
            create_notification(
                appointment['patient_id'],
                'Payment Confirmed',
                f'Your payment for appointment {appointment_id} has been confirmed.',
                'success'
            )
            
            if appointment.get('therapist_id'):
                create_notification(
                    appointment['therapist_id'],
                    'Payment Confirmed',
                    f'Payment confirmed for appointment {appointment_id}.',
                    'info'
                )
            
            return jsonify({
                'success': True,
                'message': 'Payment confirmed successfully'
            })
        
        return jsonify({
            'success': False,
            'error': 'Failed to confirm payment'
        }), 400
        
    except Exception as e:
        logger.error(f"Error confirming payment: {e}")
        return jsonify({
            'success': False,
            'error': 'Failed to confirm payment'
        }), 500

@app.route('/api/receptionist/appointments/<appointment_id>/check-out', methods=['POST'])
@login_required
@role_required(['receptionist', 'admin'])
def check_out_appointment(appointment_id):
    """Check-out a patient and mark appointment as completed"""
    try:
        current_db = get_db_safe()
        
        if current_db is None:
            return jsonify({'message': 'Patient checked out (demo mode)'})
        
        # Update appointment status to completed and mark checked out
        result = current_db.appointments.update_one(
            {'appointment_id': appointment_id},
            {'$set': {
                'status': 'completed',
                'checked_out': True,
                'check_out_time': datetime.utcnow(),
                'updated_at': datetime.utcnow()
            }}
        )
        
        if result.modified_count == 0:
            return jsonify({'error': 'Appointment not found'}), 404
        
        # Get appointment details for notification
        appointment = current_db.appointments.find_one({'appointment_id': appointment_id})
        if appointment:
            # Create notification for patient
            create_notification(
                appointment['patient_id'],
                'Appointment Completed',
                f'Your {appointment.get("therapy_type", "therapy")} appointment has been completed. Thank you for visiting!',
                'success'
            )
            
            # Create notification for doctor
            create_notification(
                appointment['therapist_id'],
                'Appointment Completed',
                f'Appointment with {appointment.get("patient_name", "Patient")} has been completed.',
                'info'
            )
        
        logger.info(f"✅ Patient checked out and appointment completed: {appointment_id}")
        
        return jsonify({
            'message': 'Patient checked out successfully and appointment marked as completed',
            'appointment_id': appointment_id
        })
        
    except Exception as e:
        logger.error(f"Error checking out patient: {e}")
        return jsonify({'error': 'Failed to check out patient'}), 500


# Add these MongoDB routes to your existing Flask app

# API Routes for Doctor Dashboard with MongoDB
@app.route('/api/doctor/dashboard-stats')
@login_required
@role_required(['doctor'])
def doctor_dashboard_stats():
    """Get doctor dashboard statistics with enhanced error handling and data formatting"""
    try:
        current_db = get_db_safe()
        doctor_id = session['user_id']
        
        stats = {
            'today': {
                'total': 0,
                'scheduled': 0,
                'completed': 0,
                'cancelled': 0
            },
            'overall': {
                'total_patients': 0,
                'total_sessions': 0,
                'completed_sessions': 0,
                'pending_followups': 0
            },
            'recent': {
                'appointments': [],
                'patients': []
            }
        }
        
        if current_db is not None:
            try:
                # Today's date range
                today_start = datetime.now(timezone.utc).replace(hour=0, minute=0, second=0, microsecond=0)
                today_end = today_start + timedelta(days=1)
                
                # Today's appointments breakdown
                today_pipeline = [
                    {'$match': {
                        'therapist_id': doctor_id,
                        'date': {'$gte': today_start, '$lt': today_end}
                    }},
                    {'$group': {
                        '_id': '$status',
                        'count': {'$sum': 1}
                    }}
                ]
                
                today_results = list(current_db.appointments.aggregate(today_pipeline))
                
                for result in today_results:
                    status = result['_id']
                    count = result['count']
                    stats['today']['total'] += count
                    if status in ['scheduled', 'completed', 'cancelled']:
                        stats['today'][status] = count
                
                # Overall statistics
                stats['overall']['total_patients'] = len(
                    current_db.appointments.distinct('patient_id', {'therapist_id': doctor_id})
                )
                
                stats['overall']['total_sessions'] = current_db.appointments.count_documents({
                    'therapist_id': doctor_id
                })
                
                stats['overall']['completed_sessions'] = current_db.appointments.count_documents({
                    'therapist_id': doctor_id,
                    'status': 'completed'
                })
                
                stats['overall']['pending_followups'] = current_db.appointments.count_documents({
                    'therapist_id': doctor_id,
                    'status': 'pending',
                    'date': {'$gt': datetime.now(timezone.utc)}
                })
                
                # Recent appointments (last 5)
                recent_appointments = list(current_db.appointments.find(
                    {'therapist_id': doctor_id}
                ).sort('date', -1).limit(5))
                
                for appt in recent_appointments:
                    patient = current_db.users.find_one({'user_id': appt['patient_id']})
                    if patient:
                        stats['recent']['appointments'].append({
                            'id': appt['appointment_id'],
                            'patient_name': f"{patient['first_name']} {patient['last_name']}",
                            'date': appt['date'].isoformat(),
                            'status': appt['status'],
                            'therapy': appt.get('therapy_type', '').title()
                        })
                
                # Recent patients (last 5 unique)
                recent_patients = list(current_db.appointments.aggregate([
                    {'$match': {'therapist_id': doctor_id}},
                    {'$sort': {'date': -1}},
                    {'$group': {
                        '_id': '$patient_id',
                        'last_visit': {'$first': '$date'},
                        'visit_count': {'$sum': 1}
                    }},
                    {'$limit': 5}
                ]))
                
                for patient_stat in recent_patients:
                    patient = current_db.users.find_one({'user_id': patient_stat['_id']})
                    if patient:
                        stats['recent']['patients'].append({
                            'id': patient['user_id'],
                            'name': f"{patient['first_name']} {patient['last_name']}",
                            'last_visit': patient_stat['last_visit'].isoformat(),
                            'visit_count': patient_stat['visit_count']
                        })
                
            except Exception as inner_error:
                logger.error(f"Error processing dashboard stats: {inner_error}")
        
        return jsonify({
            'success': True,
            'stats': stats
        })
        
    except Exception as e:
        logger.error(f"Error loading doctor dashboard stats: {e}")
        return jsonify({
            'success': False,
            'error': 'Failed to load dashboard statistics',
            'stats': {
                'today': {'total': 0, 'scheduled': 0, 'completed': 0, 'cancelled': 0},
                'overall': {'total_patients': 0, 'total_sessions': 0, 'completed_sessions': 0, 'pending_followups': 0},
                'recent': {'appointments': [], 'patients': []}
            }
        })

@app.route('/api/doctor/today-schedule')
@login_required
@role_required(['doctor'])
def doctor_today_schedule():
    """Get today's schedule for doctor"""
    try:
        current_db = get_db_safe()
        doctor_id = session['user_id']
        
        today_start = datetime.now(timezone.utc).replace(hour=0, minute=0, second=0, microsecond=0)
        today_end = today_start + timedelta(days=1)
        
        appointments = []
        
        if current_db is not None:
            appointments_cursor = current_db.appointments.find({
                'therapist_id': doctor_id,
                'date': {'$gte': today_start, '$lt': today_end},
                'status': {'$in': ['pending', 'confirmed', 'in-progress']}
            }).sort('date', 1)
            
            for appt in appointments_cursor:
                # Get patient details
                patient = current_db.users.find_one({'user_id': appt.get('patient_id')})
                patient_name = f"{patient.get('first_name', '')} {patient.get('last_name', '')}" if patient else 'Unknown Patient'
                
                appointments.append({
                    'appointment_id': appt.get('appointment_id'),
                    'date': appt.get('date').isoformat() if appt.get('date') else None,
                    'status': appt.get('status', 'pending'),
                    'reason': appt.get('reason', ''),
                    'notes': appt.get('notes', ''),
                    'patient_name': patient_name,
                    'patient_id': appt.get('patient_id'),
                    'therapy_name': appt.get('therapy_type', '').title()
                })
        
        return jsonify(appointments)
        
    except Exception as e:
        logger.error(f"Error loading today's schedule: {e}")
        return jsonify({'error': 'Failed to load schedule'}), 500

@app.route('/api/doctor/appointments')
@login_required
@role_required(['doctor'])
def doctor_appointments():
    """Get all appointments for doctor with filtering"""
    try:
        current_db = get_db_safe()
        doctor_id = session['user_id']
        
        status_filter = request.args.get('status', 'all')
        limit = int(request.args.get('limit', 0))
        
        # Build query
        query = {'therapist_id': doctor_id}
        
        if status_filter != 'all':
            query['status'] = status_filter
        
        appointments = []
        
        if current_db is not None:
            appointments_cursor = current_db.appointments.find(query).sort('date', -1)
            
            if limit > 0:
                appointments_cursor = appointments_cursor.limit(limit)
            
            for appt in appointments_cursor:
                # Get patient details
                patient = current_db.users.find_one({'user_id': appt.get('patient_id')})
                patient_name = f"{patient.get('first_name', '')} {patient.get('last_name', '')}" if patient else 'Unknown Patient'
                
                appointments.append({
                    'appointment_id': appt.get('appointment_id'),
                    'date': appt.get('date').isoformat() if appt.get('date') else None,
                    'status': appt.get('status', 'pending'),
                    'reason': appt.get('reason', ''),
                    'notes': appt.get('notes', ''),
                    'patient_name': patient_name,
                    'patient_id': appt.get('patient_id'),
                    'therapy_name': appt.get('therapy_type', '').title(),
                    'consultation_type': appt.get('consultation_type', 'general')
                })
        
        return jsonify({'appointments': appointments})
        
    except Exception as e:
        logger.error(f"Error loading doctor appointments: {e}")
        return jsonify({'error': 'Failed to load appointments'}), 500

@app.route('/api/doctor/patients')
@login_required
@role_required(['doctor'])
def doctor_patients():
    """Get all patients for the doctor"""
    try:
        current_db = get_db_safe()
        doctor_id = session['user_id']
        
        patients = []
        
        if current_db is not None:
            # Get distinct patient IDs from appointments
            patient_ids = current_db.appointments.distinct('patient_id', {
                'therapist_id': doctor_id
            })
            
            # Get patient details
            for patient_id in patient_ids:
                patient = current_db.users.find_one({
                    'user_id': patient_id,
                    'role': 'patient'
                })
                
                if patient:
                    # Get appointment stats for this patient
                    patient_appointments = list(current_db.appointments.find({
                        'patient_id': patient_id,
                        'therapist_id': doctor_id
                    }).sort('date', -1))
                    
                    total_sessions = len(patient_appointments)
                    last_visit = patient_appointments[0].get('date') if patient_appointments else None
                    
                    # Calculate age from date of birth if available
                    age = None
                    if patient.get('date_of_birth'):
                        try:
                            birth_date = patient['date_of_birth']
                            if isinstance(birth_date, str):
                                birth_date = datetime.fromisoformat(birth_date.replace('Z', '+00:00'))
                            today = datetime.now(timezone.utc)
                            age = today.year - birth_date.year - ((today.month, today.day) < (birth_date.month, birth_date.day))
                        except:
                            age = None
                    
                    patients.append({
                        'patient_id': patient['user_id'],
                        'first_name': patient.get('first_name', ''),
                        'last_name': patient.get('last_name', ''),
                        'phone': patient.get('phone', ''),
                        'email': patient.get('email', ''),
                        'age': age,
                        'gender': patient.get('gender', ''),
                        'address': patient.get('address', ''),
                        'last_visit': last_visit.isoformat() if last_visit else None,
                        'total_sessions': total_sessions
                    })
        
        return jsonify(patients)
        
    except Exception as e:
        logger.error(f"Error loading doctor patients: {e}")
        return jsonify({'error': 'Failed to load patients'}), 500

@app.route('/api/doctor/patients/<patient_id>')
@login_required
@role_required(['doctor'])
def doctor_patient_detail(patient_id):
    """Get detailed patient information"""
    try:
        current_db = get_db_safe()
        doctor_id = session['user_id']
        
        if current_db is None:
            return jsonify({'error': 'Database not available'}), 500
        
        # Get patient details
        patient = current_db.users.find_one({
            'user_id': patient_id,
            'role': 'patient'
        })
        
        if not patient:
            return jsonify({'error': 'Patient not found'}), 404
        
        # Get appointment history with this doctor
        appointments = list(current_db.appointments.find({
            'patient_id': patient_id,
            'therapist_id': doctor_id
        }).sort('date', -1))
        
        # Calculate age
        age = None
        if patient.get('date_of_birth'):
            try:
                birth_date = patient['date_of_birth']
                if isinstance(birth_date, str):
                    birth_date = datetime.fromisoformat(birth_date.replace('Z', '+00:00'))
                today = datetime.now(timezone.utc)
                age = today.year - birth_date.year - ((today.month, today.day) < (birth_date.month, birth_date.day))
            except:
                age = None
        
        patient_data = {
            'patient_id': patient['user_id'],
            'first_name': patient.get('first_name', ''),
            'last_name': patient.get('last_name', ''),
            'phone': patient.get('phone', ''),
            'email': patient.get('email', ''),
            'age': age,
            'gender': patient.get('gender', ''),
            'address': patient.get('address', ''),
            'date_of_birth': patient.get('date_of_birth'),
            'medical_history': patient.get('medical_conditions', ''),
            'allergies': patient.get('allergies', ''),
            'current_medications': patient.get('current_medications', ''),
            'total_sessions': len(appointments),
            'last_visit': appointments[0].get('date').isoformat() if appointments else None
        }
        
        return jsonify(patient_data)
        
    except Exception as e:
        logger.error(f"Error loading patient details: {e}")
        return jsonify({'error': 'Failed to load patient details'}), 500

@app.route('/api/doctor/appointments/<appointment_id>')
@login_required
@role_required(['doctor'])
def doctor_appointment_detail(appointment_id):
    """Get detailed appointment information"""
    try:
        current_db = get_db_safe()
        doctor_id = session['user_id']
        
        if current_db is None:
            return jsonify({'error': 'Database not available'}), 500
        
        # Get appointment details
        appointment = current_db.appointments.find_one({
            'appointment_id': appointment_id,
            'therapist_id': doctor_id
        })
        
        if not appointment:
            return jsonify({'error': 'Appointment not found'}), 404
        
        # Get patient details
        patient = current_db.users.find_one({'user_id': appointment.get('patient_id')})
        
        # Get doctor details
        doctor = current_db.users.find_one({'user_id': doctor_id})
        
        appointment_data = {
            'appointment_id': appointment.get('appointment_id'),
            'date': appointment.get('date').isoformat() if appointment.get('date') else None,
            'status': appointment.get('status', 'pending'),
            'reason': appointment.get('reason', ''),
            'notes': appointment.get('notes', ''),
            'consultation_type': appointment.get('consultation_type', 'general'),
            'patient_name': f"{patient.get('first_name', '')} {patient.get('last_name', '')}" if patient else 'Unknown Patient',
            'patient_id': appointment.get('patient_id'),
            'patient_phone': patient.get('phone', '') if patient else '',
            'patient_email': patient.get('email', '') if patient else '',
            'therapy_name': appointment.get('therapy_type', '').title(),
            'doctor_name': f"Dr. {doctor.get('first_name', '')} {doctor.get('last_name', '')}" if doctor else 'Unknown Doctor'
        }
        
        return jsonify(appointment_data)
        
    except Exception as e:
        logger.error(f"Error loading appointment details: {e}")
        return jsonify({'error': 'Failed to load appointment details'}), 500

@app.route('/api/doctor/appointments/<appointment_id>/start', methods=['POST'])
@login_required
@role_required(['doctor'])
def start_appointment_session(appointment_id):
    """Start an appointment session"""
    try:
        current_db = get_db_safe()
        doctor_id = session['user_id']
        
        if current_db is None:
            return jsonify({'success': False, 'message': 'Database not available'})
        
        # Check if appointment exists and belongs to this doctor
        appointment = current_db.appointments.find_one({
            'appointment_id': appointment_id,
            'therapist_id': doctor_id
        })
        
        if not appointment:
            return jsonify({'success': False, 'message': 'Appointment not found'})
        
        if appointment.get('status') != 'confirmed':
            return jsonify({'success': False, 'message': 'Cannot start session for this appointment status'})
        
        # Update appointment status to 'in-progress'
        result = current_db.appointments.update_one(
            {'appointment_id': appointment_id},
            {
                '$set': {
                    'status': 'in-progress',
                    'updated_at': datetime.utcnow()
                }
            }
        )
        
        if result.modified_count > 0:
            # Create notification for patient
            create_notification(
                appointment.get('patient_id'),
                'Session Started',
                f'Your {appointment.get("therapy_type", "therapy")} session has started with Dr. {session.get("first_name")} {session.get("last_name")}.',
                'info'
            )
            
            logger.info(f"Doctor {doctor_id} started session for appointment {appointment_id}")
            return jsonify({'success': True})
        else:
            return jsonify({'success': False, 'message': 'Failed to update appointment'})
        
    except Exception as e:
        logger.error(f"Error starting appointment session: {e}")
        return jsonify({'success': False, 'message': 'Internal server error'}), 500

@app.route('/api/doctor/appointments/<appointment_id>/complete', methods=['POST'])
@login_required
@role_required(['doctor'])
def complete_appointment_session(appointment_id):
    """Complete an appointment session"""
    try:
        current_db = get_db_safe()
        doctor_id = session['user_id']
        
        if current_db is None:
            return jsonify({'success': False, 'message': 'Database not available'})
        
        # Check if appointment exists and belongs to this doctor
        appointment = current_db.appointments.find_one({
            'appointment_id': appointment_id,
            'therapist_id': doctor_id
        })
        
        if not appointment:
            return jsonify({'success': False, 'message': 'Appointment not found'})
        
        if appointment.get('status') != 'in-progress':
            return jsonify({'success': False, 'message': 'Cannot complete session for this appointment status'})
        
        # Update appointment status to 'completed'
        result = current_db.appointments.update_one(
            {'appointment_id': appointment_id},
            {
                '$set': {
                    'status': 'completed',
                    'updated_at': datetime.utcnow()
                }
            }
        )
        
        if result.modified_count > 0:
            # Create notification for patient
            create_notification(
                appointment.get('patient_id'),
                'Session Completed',
                f'Your {appointment.get("therapy_type", "therapy")} session has been completed. Thank you for your visit!',
                'success'
            )
            
            # Create notification for receptionist
            create_notification(
                'REC001',
                'Appointment Completed',
                f'Appointment {appointment_id} has been completed by Dr. {session.get("first_name")} {session.get("last_name")}.',
                'info'
            )
            
            logger.info(f"Doctor {doctor_id} completed session for appointment {appointment_id}")
            return jsonify({'success': True})
        else:
            return jsonify({'success': False, 'message': 'Failed to update appointment'})
        
    except Exception as e:
        logger.error(f"Error completing appointment session: {e}")
        return jsonify({'success': False, 'message': 'Internal server error'}), 500

@app.route('/api/doctor/appointments/<appointment_id>/notes', methods=['POST'])
@login_required
@role_required(['doctor'])
def add_appointment_notes(appointment_id):
    """Add notes to an appointment"""
    try:
        current_db = get_db_safe()
        doctor_id = session['user_id']
        data = request.get_json()
        
        if not data or 'notes' not in data:
            return jsonify({'success': False, 'message': 'Notes are required'})
        
        notes = data['notes'].strip()
        if not notes:
            return jsonify({'success': False, 'message': 'Notes cannot be empty'})
        
        if current_db is None:
            return jsonify({'success': False, 'message': 'Database not available'})
        
        # Check if appointment exists and belongs to this doctor
        appointment = current_db.appointments.find_one({
            'appointment_id': appointment_id,
            'therapist_id': doctor_id
        })
        
        if not appointment:
            return jsonify({'success': False, 'message': 'Appointment not found'})
        
        # Update appointment notes
        result = current_db.appointments.update_one(
            {'appointment_id': appointment_id},
            {
                '$set': {
                    'notes': notes,
                    'updated_at': datetime.utcnow()
                }
            }
        )
        
        if result.modified_count > 0:
            logger.info(f"Doctor {doctor_id} added notes to appointment {appointment_id}")
            return jsonify({'success': True})
        else:
            return jsonify({'success': False, 'message': 'Failed to update notes'})
        
    except Exception as e:
        logger.error(f"Error adding appointment notes: {e}")
        return jsonify({'success': False, 'message': 'Internal server error'}), 500

@app.route('/api/doctor/treatment-records')
@login_required
@role_required(['doctor'])
def doctor_treatment_records():
    """Get treatment records (completed appointments with notes)"""
    try:
        current_db = get_db_safe()
        doctor_id = session['user_id']
        
        records = []
        
        if current_db is not None:
            # Get completed appointments with notes
            appointments_cursor = current_db.appointments.find({
                'therapist_id': doctor_id,
                'status': 'completed',
                'notes': {'$exists': True, '$ne': ''}
            }).sort('date', -1)
            
            for appt in appointments_cursor:
                # Get patient details
                patient = current_db.users.find_one({'user_id': appt.get('patient_id')})
                patient_name = f"{patient.get('first_name', '')} {patient.get('last_name', '')}" if patient else 'Unknown Patient'
                
                records.append({
                    'appointment_id': appt.get('appointment_id'),
                    'date': appt.get('date').isoformat() if appt.get('date') else None,
                    'patient_name': patient_name,
                    'patient_id': appt.get('patient_id'),
                    'therapy_name': appt.get('therapy_type', '').title(),
                    'notes': appt.get('notes', ''),
                    'reason': appt.get('reason', '')
                })
        
        return jsonify(records)
        
    except Exception as e:
        logger.error(f"Error loading treatment records: {e}")
        return jsonify({'error': 'Failed to load treatment records'}), 500

@app.route('/api/doctor/availability')
@login_required
@role_required(['doctor'])
def doctor_availability():
    """Get doctor's availability"""
    try:
        current_db = get_db_safe()
        doctor_id = session['user_id']
        
        availability = []
        
        if current_db is not None:
            # Check if availability collection exists, if not return empty
            if 'doctor_availability' in current_db.list_collection_names():
                availability_cursor = current_db.doctor_availability.find({
                    'doctor_id': doctor_id,
                    'is_active': True
                }).sort('day_of_week', 1)
                
                for slot in availability_cursor:
                    availability.append({
                        'id': str(slot['_id']),
                        'day': slot.get('day_of_week'),
                        'start_time': slot.get('start_time'),
                        'end_time': slot.get('end_time'),
                        'max_appointments': slot.get('max_appointments', 3)
                    })
        
        return jsonify(availability)
        
    except Exception as e:
        logger.error(f"Error loading availability: {e}")
        return jsonify({'error': 'Failed to load availability'}), 500

@app.route('/api/doctor/availability', methods=['POST'])
@login_required
@role_required(['doctor'])
def update_doctor_availability():
    """Update doctor's availability"""
    try:
        current_db = get_db_safe()
        doctor_id = session['user_id']
        data = request.get_json()
        
        if not data:
            return jsonify({'success': False, 'message': 'No data provided'})
        
        required_fields = ['day', 'start_time', 'end_time']
        for field in required_fields:
            if field not in data:
                return jsonify({'success': False, 'message': f'Missing required field: {field}'})
        
        if current_db is None:
            return jsonify({'success': False, 'message': 'Database not available'})
        
        # Create or update availability slot
        availability_data = {
            'doctor_id': doctor_id,
            'day_of_week': data['day'],
            'start_time': data['start_time'],
            'end_time': data['end_time'],
            'max_appointments': data.get('max_appointments', 3),
            'is_active': True,
            'created_at': datetime.utcnow(),
            'updated_at': datetime.utcnow()
        }
        
        # Check if slot already exists for this day
        existing_slot = current_db.doctor_availability.find_one({
            'doctor_id': doctor_id,
            'day_of_week': data['day'],
            'is_active': True
        })
        
        if existing_slot:
            # Update existing slot
            result = current_db.doctor_availability.update_one(
                {'_id': existing_slot['_id']},
                {'$set': availability_data}
            )
        else:
            # Create new slot
            result = current_db.doctor_availability.insert_one(availability_data)
        
        # Create notification for receptionist
        create_notification(
            'REC001',
            'Doctor Availability Updated',
            f'Dr. {session.get("first_name")} {session.get("last_name")} has updated their availability.',
            'info'
        )
        
        logger.info(f"Doctor {doctor_id} updated availability")
        return jsonify({'success': True})
        
    except Exception as e:
        logger.error(f"Error updating availability: {e}")
        return jsonify({'success': False, 'message': 'Internal server error'}), 500

@app.route('/api/doctor/availability/<availability_id>', methods=['DELETE'])
@login_required
@role_required(['doctor'])
def delete_doctor_availability(availability_id):
    """Delete doctor's availability slot"""
    try:
        current_db = get_db_safe()
        doctor_id = session['user_id']
        
        if current_db is None:
            return jsonify({'success': False, 'message': 'Database not available'})
        
        # Convert string ID to ObjectId
        from bson.objectid import ObjectId
        try:
            obj_id = ObjectId(availability_id)
        except:
            return jsonify({'success': False, 'message': 'Invalid availability ID'})
        
        # Delete availability slot
        result = current_db.doctor_availability.delete_one({
            '_id': obj_id,
            'doctor_id': doctor_id
        })
        
        if result.deleted_count > 0:
            logger.info(f"Doctor {doctor_id} deleted availability slot {availability_id}")
            return jsonify({'success': True})
        else:
            return jsonify({'success': False, 'message': 'Availability slot not found'})
        
    except Exception as e:
        logger.error(f"Error deleting availability: {e}")
        return jsonify({'success': False, 'message': 'Internal server error'}), 500

@app.route('/api/doctor/notifications')
@login_required
@role_required(['doctor'])
def doctor_notifications():
    """Get notifications for doctor"""
    try:
        current_db = get_db_safe()
        doctor_id = session['user_id']
        
        notifications = []
        
        if current_db is not None:
            notifications_cursor = current_db.notifications.find({
                'user_id': doctor_id
            }).sort('created_at', -1).limit(10)
            
            for notif in notifications_cursor:
                notifications.append({
                    'id': str(notif['_id']),
                    'title': notif.get('title', ''),
                    'message': notif.get('message', ''),
                    'type': notif.get('type', 'info'),
                    'is_read': notif.get('is_read', False),
                    'created_at': notif.get('created_at').isoformat() if notif.get('created_at') else None
                })
        
        return jsonify(notifications)
        
    except Exception as e:
        logger.error(f"Error loading doctor notifications: {e}")
        return jsonify({'error': 'Failed to load notifications'}), 500

@app.route('/api/doctor/notifications/read-all', methods=['POST'])
@login_required
@role_required(['doctor'])
def mark_all_doctor_notifications_read():
    """Mark all notifications as read for doctor"""
    try:
        current_db = get_db_safe()
        doctor_id = session['user_id']
        
        if current_db is not None:
            result = current_db.notifications.update_many(
                {
                    'user_id': doctor_id,
                    'is_read': False
                },
                {
                    '$set': {
                        'is_read': True,
                        'updated_at': datetime.utcnow()
                    }
                }
            )
            
            logger.info(f"Marked {result.modified_count} notifications as read for doctor {doctor_id}")
        
        return jsonify({'success': True})
        
    except Exception as e:
        logger.error(f"Error marking notifications as read: {e}")
        return jsonify({'success': False, 'message': 'Internal server error'}), 500
# Add to app.py for real-time features
from flask_socketio import SocketIO, emit

socketio = SocketIO(app, cors_allowed_origins="*")

@socketio.on('connect')
def handle_connect():
    if 'user_id' in session:
        join_room(session['user_id'])
        emit('connected', {'message': 'Connected to real-time updates'})

@socketio.on('join_room')
def handle_join_room(data):
    room = data.get('room')
    if room:
        join_room(room)

def send_real_time_notification(user_id, notification_data):
    socketio.emit('new_notification', notification_data, room=user_id)

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
        if user_data['role'] in ['admin', 'receptionist','doctor']:
            logger.info(f"   📧 {user_data['email']} / {user_data['password']} ({user_data['role']})")
    
    app.run(host='0.0.0.0', port=5000, debug=True)