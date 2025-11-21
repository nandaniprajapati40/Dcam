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
from bson.objectid import ObjectId
import razorpay.errors 
import traceback
load_dotenv()
import google.generativeai as genai
import markdown

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
    authorize_params={'redirect_uri': os.environ.get('GOOGLE_REDIRECT_URI', 'http://127.0.0.1:5000/google-callback')}
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
        
        logger.info(f"Successfully connected to MongoDB Atlas!")
        logger.info(f"Database: {DB_NAME}")
        logger.info(f"Host: {server_info.get('hosts', ['Unknown'])}")
        logger.info(f"MongoDB Version: {server_info.get('version', 'Unknown')}")
        
        return True
        
    except ServerSelectionTimeoutError as e:
        logger.error(f"MongoDB connection timeout: {str(e)}")
        logger.error("Tip: Check your internet connection and MongoDB Atlas cluster status")
        logger.error("Tip: Ensure your IP is whitelisted in MongoDB Atlas network settings")
    except Exception as e:
        logger.error(f"MongoDB connection failed: {str(e)}")
        
        # Provide specific troubleshooting tips
        error_str = str(e).lower()
        if "authentication failed" in error_str:
            logger.error("Tip: Check your MongoDB Atlas username and password")
            logger.error("Tip: Ensure the user has proper permissions")
        elif "getaddrinfo" in error_str or "dns" in error_str:
            logger.error("Tip: Check your internet connection and DNS resolution")
        elif "timed out" in error_str:
            logger.error("Tip: Check if your IP is whitelisted in MongoDB Atlas network settings")
        elif "bad auth" in error_str:
            logger.error("Tip: Authentication failed - verify username/password")
        elif "ssl" in error_str:
            logger.error("Tip: SSL connection issue - check firewall/proxy settings")
        
    db_connected = False
    return False

# Initialize MongoDB connection
if not init_mongodb_connection():
    logger.warning("Running in demo mode without database connection")

def check_db_health():
    """Check if database connection is healthy"""
    global db_connected, client, db
    
    if client is None:
        return False
    
    try:
        # Simple ping to check connection
        client.admin.command('ping')
        if not db_connected:
            logger.info("MongoDB connection restored")
            db_connected = True
        return True
    except Exception as e:
        if db_connected:
            logger.warning(f"MongoDB connection lost: {e}")
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
    'physiotherapy': 'DOC008',
    'sound': 'DOC011'
}

# Email configuration
EMAIL_CONFIG = {
    'smtp_server': os.environ.get('EMAIL_SMTP_SERVER', 'smtp.gmail.com'),
    'smtp_port': int(os.environ.get('EMAIL_SMTP_PORT', 587)),
    'sender_email': os.environ.get('EMAIL_SENDER', ''),
    'sender_password': os.environ.get('EMAIL_PASSWORD', ''),
    'use_tls': True
}


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
            logger.info(f"(Console fallback) OTP for {email}: {otp}")
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

        logger.info(f"OTP sent to {email} via SMTP")
        return True

    except smtplib.SMTPAuthenticationError as auth_err:
        logger.error(f"SMTP auth error sending email: {auth_err}")
        logger.info(f"(Fallback) OTP for {email}: {otp}")
        return False
    except Exception as e:
        logger.error(f"Error sending email: {e}")
        logger.info(f"(Fallback) OTP for {email}: {otp}")
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
            logger.info(f"(Console fallback) Password reset OTP for {email}: {otp}")
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

        logger.info(f"Password reset OTP sent to {email}")
        return True

    except Exception as e:
        logger.error(f"Error sending password reset OTP email: {e}")
        logger.info(f"(Fallback) Password reset OTP for {email}: {otp}")
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
- Status: Confirmed 

Please arrive 10 minutes before your scheduled time and bring your appointment receipt.

You can download your appointment receipt from your dashboard.

Thank you for choosing DCAM Therapy Center.

Best regards,
DCAM Team
Dev Sanskriti Vishwavidyalaya
        """

        if sender is None or password is None:
            logger.info(f"(Console fallback) Appointment confirmation for {patient_email}")
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

        logger.info(f"Appointment confirmation sent to {patient_email}")
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
            logger.info(f"(Console fallback) Doctor notification for {doctor_email}")
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

        logger.info(f"Doctor notification sent to {doctor_email}")
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
        logger.error("MongoDB not connected - cannot initialize database")
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
                logger.info(f"Created collection: {collection_name}")
            
            # Create indexes
            for index_config in indexes:
                try:
                    keys = index_config['keys']
                    options = index_config['options']
                    current_db[collection_name].create_index(keys, **options)
                    logger.info(f"Created index for {collection_name}: {keys}")
                except Exception as e:
                    logger.warning(f"Could not create index for {collection_name}: {e}")

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
                    logger.info(f"Created predefined user: {user_data['user_id']}")
                else:
                    logger.info(f"ℹ Predefined user already exists: {user_data['user_id']}")
            except DuplicateKeyError:
                logger.warning(f" Duplicate user detected: {user_data['user_id']}")
            except Exception as e:
                logger.error(f" Error creating user {user_data['user_id']}: {e}")
        
        logger.info(f" Database initialization completed! Created {users_created} predefined users")
        return True
        
    except Exception as e:
        logger.error(f" Database initialization error: {e}")
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
        return ("hello")
    
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
        logger.info(f" [DEMO] Notification for {user_id}: {title} - {message}")
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
            'manage_appointments_pages'
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
        'physiotherapy': 1500,
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

@app.route('/')
def index():
    if 'user_id' in session and request.args.get('logout') != 'true':
        return redirect(url_for('dashboard'))
    return render_template('index.html')

# Google OAuth Routes
@app.route('/google-login')
def google_login():
    try:
        # Use the environment variable or fallback to localhost
        redirect_uri = os.environ.get('GOOGLE_REDIRECT_URI', 'http://127.0.0.1:5000/google-callback')
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


@app.route('/api/users/therapists')
@login_required
def get_therapists_legacy():
    """Legacy endpoint for backward compatibility"""
    return get_therapists()

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

        if data['role'] == 'patient':
            user_doc['patient_id'] = user_id
            user_doc.update({
                'phone': data.get('phone', ''),
                'address': data.get('address', ''),
                'date_of_birth': data.get('date_of_birth', ''),
                'gender': data.get('gender', ''),
            
            })
        elif data['role'] == 'doctor':
            user_doc.update({
                'specialization': data.get('specialization', 'General Therapy'),
                'therapy_type': data.get('therapy_type', 'general'),
                'qualifications': data.get('qualifications', ''),
                'experience': data.get('experience', 0),
                'consultation_fee': data.get('consultation_fee', 0),
                'is_available': True
            })
        # Insert into database if connected
        if current_db is not None:
            try:
                result = current_db.users.insert_one(user_doc)
                logger.info(f"Created user: {user_id} with ID: {result.inserted_id}")
                
                # Verify the user was actually created
                created_user = current_db.users.find_one({'user_id': user_id})
                if not created_user:
                    logger.error(f"User creation failed: {user_id}")
                    return jsonify({'error': 'User creation failed'}), 500
                    
            except Exception as e:
                logger.error(f"Database error creating user: {e}")
                return jsonify({'error': 'Failed to create user account'}), 500

        response_data = {
            'message': f'{data["role"].title()} registered successfully!',
            'user_id': user_id,
            'email': data['email'],
            'requires_verification': False
        }
        
        logger.info(f" Registration successful for: {data['email']}")
        return jsonify(response_data), 201
        
    except Exception as e:
        logger.error(f" Registration error: {e}")
        return jsonify({'error': 'Internal server error'}), 500

@app.route('/login', methods=['POST'])
def login():
    try:
        data = request.get_json()
        
        if not data.get('email') or not data.get('password'):
            return jsonify({'error': 'Email and password are required'}), 400
        
        logger.info(f"Login attempt for: {data['email']}")

        current_db = get_db_safe()
        user = None

        if current_db is not None:
            logger.info(f" Searching for user in database: {data['email']}")
            user = current_db.users.find_one({'email': data['email']})
        if user:
            logger.info(f" User found: {user['user_id']}")
            
            # Check if account is active
            if not user.get('is_active', True):
                logger.warning(f" Account deactivated: {data['email']}")
                return jsonify({'error': 'Account is deactivated'}), 401
            
            # Verify password
            if check_password_hash(user['password'], data['password']):
                logger.info(f"Password verified for: {data['email']}")
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
                
                if user['role'] == 'patient':
                    session['patient_id'] = user.get('patient_id', user['user_id'])
                

                if user_data['role'] == 'doctor':
                    session['specialization'] = user_data.get('specialization')
                    session['therapy_type'] = user_data.get('therapy_type')
                
                session.permanent = True
                session.modified = True
                

                # Update last login
                if current_db is not None:
                    current_db.users.update_one(
                        {'user_id': user['user_id']},
                        {'$set': {'last_login': datetime.utcnow(), 'updated_at': datetime.utcnow()}}

                    )
                # Role-based redirection after login
                redirect_url = get_role_redirect_url(user_data['role'])
                
                logger.info(f"Login successful for predefined user {user_data['email']}, role: {user_data['role']}")
                
               

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
            logger.info(f" Searching for user in database: {data['email']}")
            user = current_db.users.find_one({'email': data['email']})
        
        if user:
            logger.info(f" User found: {user['user_id']}")
            
            # Check if account is active
            if not user.get('is_active', True):
                logger.warning(f"Account deactivated: {data['email']}")
                return jsonify({'error': 'Account is deactivated'}), 401
            
            # Verify password
            if check_password_hash(user['password'], data['password']):
                logger.info(f"Password verified for: {data['email']}")
                
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
                elif user['role'] == 'doctor':
                    user_response['specialization'] = user.get('specialization')
                    user_response['therapy_type'] = user.get('therapy_type')
                logger.info(f"🎉 Login successful for: {data['email']}")
                return jsonify({
                    'message': 'Login successful!',
                    'user': user_response,
                    'redirect_url': redirect_url
                }), 200
            else:
                logger.warning(f"Invalid password for: {data['email']}")
                return jsonify({'error': 'Invalid email or password'}), 401
        else:
            logger.warning(f" User not found: {data['email']}")
            return jsonify({'error': 'Invalid email or password'}), 401
        
    except Exception as e:
        logger.error(f" Login error: {str(e)}")
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
    

# Gemini AI Configuration
GEMINI_API_KEY = os.environ.get('GEMINI_API_KEY')

# Initialize Gemini AI
if GEMINI_API_KEY:
    try:
        genai.configure(api_key=GEMINI_API_KEY)
        # Use gemini-1.5-flash for faster responses (free tier friendly)
        gemini_model = genai.GenerativeModel('gemini-2.5-flash')
        logger.info("Gemini AI configured successfully")
    except Exception as e:
        logger.error(f"Gemini AI configuration failed: {e}")
        gemini_model = None
else:
    logger.warning("Gemini API key not found - AI chat disabled")
    gemini_model = None  
      
@app.route('/ai-chat-assistant')
@login_required
def ai_chat_assistant():
    """AI Chat Assistant page"""
    return render_template('ai_chat_assistant.html')

@app.route('/api/ai-chat', methods=['POST'])
@login_required
def ai_chat():
    """Handle AI chat messages"""
    try:
        if not gemini_model:
            return jsonify({
                'success': False,
                'error': 'AI service is currently unavailable. Please try again later.'
            }), 503

        data = request.get_json()
        user_message = data.get('message', '').strip()
        
        if not user_message:
            return jsonify({
                'success': False,
                'error': 'Message cannot be empty'
            }), 400

        # Create context for the AI about therapy and healthcare
        context = """
        You are a friendly and knowledgeable AI assistant for DCAM Therapy Center, 
        a holistic healthcare facility offering various therapies including:
        - Acupressure
        - Ayurveda
        - Homeopathy
        - Naturopathy
        - Yoga
        - Physiotherapy
        - Sound Therapy
        
        You should:
        1. Provide helpful information about therapies and wellness
        2. Offer general health advice (but always recommend consulting doctors for medical issues)
        3. Be empathetic and supportive
        4. Guide users to book appointments for specific concerns
        5. Explain benefits of different therapies
        6. Provide general wellness tips
        
        Important: Always remind users that for medical emergencies or specific health concerns, 
        they should consult with our qualified doctors and not rely solely on AI advice.
        """

        # Generate response using Gemini
        prompt = f"{context}\n\nUser: {user_message}\n\nAssistant:"
        
        response = gemini_model.generate_content(prompt)
        
        # Convert markdown to HTML for better formatting
        ai_response = response.text
        html_response = markdown.markdown(ai_response)
        
        # Log the interaction (without storing personal health info)
        logger.info(f"AI Chat - User: {session['user_id']}, Message: {user_message[:100]}...")
        
        return jsonify({
            'success': True,
            'response': html_response,
            'timestamp': datetime.utcnow().isoformat()
        })
        
    except Exception as e:
        logger.error(f"Error in AI chat: {e}")
        return jsonify({
            'success': False,
            'error': 'Sorry, I encountered an error. Please try again.'
        }), 500

@app.route('/api/ai-suggested-questions')
@login_required
def get_ai_suggested_questions():
    """Get suggested questions for AI chat"""
    suggested_questions = [
        "What are the benefits of acupressure therapy?",
        "How can yoga help with stress management?",
        "What is the difference between Ayurveda and Homeopathy?",
        "Can you suggest some natural remedies for better sleep?",
        "What therapy would you recommend for back pain?",
        "How does sound therapy work?",
        "What are the advantages of naturopathy?",
        "Can physiotherapy help with sports injuries?",
        "What are some daily wellness practices you recommend?",
        "How do I know which therapy is right for me?"
    ]
    
    return jsonify({
        'success': True,
        'questions': suggested_questions
    })

@app.route('/api/confirm-payment', methods=['POST'])
@login_required
def confirm_payment():
    """Confirm payment for demo mode"""
    try:
        data = request.get_json()
        appointment_id = data.get('appointment_id')
        payment_id = data.get('payment_id')
        amount = data.get('amount')
        
        if not appointment_id:
            return jsonify({'success': False, 'error': 'Appointment ID is required'}), 400
        
        current_db = get_db_safe()
        
        if current_db is not None:
            # Update appointment payment status
            result = current_db.appointments.update_one(
                {'appointment_id': appointment_id},
                {'$set': {
                    'payment_status': 'paid',
                    'status': 'pending',  # Waiting for receptionist confirmation
                    'updated_at': datetime.utcnow()
                }}
            )
            
            if result.modified_count == 0:
                return jsonify({'success': False, 'error': 'Appointment not found'}), 404
            
            # Create or update payment record
            payment_data = {
                'payment_id': payment_id or f"PAY{random.randint(1000, 9999)}",
                'appointment_id': appointment_id,
                'patient_id': session['user_id'],
                'amount': amount or 50,
                'currency': 'INR',
                'status': 'paid',
                'paid_at': datetime.utcnow(),
                'updated_at': datetime.utcnow()
            }
            
            existing_payment = current_db.payments.find_one({'appointment_id': appointment_id})
            if existing_payment:
                current_db.payments.update_one(
                    {'appointment_id': appointment_id},
                    {'$set': payment_data}
                )
            else:
                payment_data['created_at'] = datetime.utcnow()
                current_db.payments.insert_one(payment_data)
            
            # Generate receipt automatically
            receipt_data = generate_appointment_receipt(appointment_id)
            
            # Create notifications
            create_notification(
                session['user_id'],
                'Payment Successful! 🎉',
                f'Your payment of ₹{amount or 50} for appointment {appointment_id} has been received. Waiting for receptionist confirmation.',
                'success'
            )
            
            create_notification(
                'REC001',
                'New Payment Received',
                f'Payment received for appointment {appointment_id}. Please confirm the appointment.',
                'info'
            )
        
        logger.info(f"✅ Payment confirmed for appointment: {appointment_id}")
        
        return jsonify({
            'success': True,
            'message': 'Payment confirmed successfully! ₹50 payment received. Your appointment is pending receptionist confirmation.',
            'appointment_id': appointment_id,
            'receipt_generated': True,
            'redirect_url': f'/appointment-receipt/{appointment_id}'  # Add redirect URL
        })
        
    except Exception as e:
        logger.error(f"Error confirming payment: {e}")
        return jsonify({'success': False, 'error': 'Failed to confirm payment'}), 500

@app.route('/api/cancel-appointment', methods=['POST'])
@login_required
def cancel_appointment_api():
    """Cancel appointment API endpoint - matches the JavaScript call"""
    try:
        data = request.get_json()#book_appointment
        appointment_id = data.get('appointment_id')
        
        if not appointment_id:
            return jsonify({'success': False, 'error': 'Appointment ID is required'}), 400
        
        current_db = get_db_safe()
        
        if current_db is None:
            return jsonify({'success': True, 'message': 'Appointment cancelled (demo mode)'})
        
        # Get appointment details
        appointment = current_db.appointments.find_one({'appointment_id': appointment_id})
        if not appointment:
            return jsonify({'success': False, 'error': 'Appointment not found'}), 404
        
        # Check if user owns this appointment or has permission
        if session['role'] == 'patient' and appointment.get('patient_id') != session['user_id']:
            return jsonify({'success': False, 'error': 'Unauthorized to cancel this appointment'}), 403
        
        # Check if appointment can be cancelled (not already completed or cancelled)
        if appointment.get('status') in ['completed', 'cancelled']:
            return jsonify({'success': False, 'error': f'Cannot cancel appointment with status: {appointment.get("status")}'}), 400
        
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
            return jsonify({'success': False, 'error': 'Failed to cancel appointment'}), 400
        
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
        
        # If payment was made, handle refund notification
        payment = current_db.payments.find_one({'appointment_id': appointment_id})
        if payment and payment.get('status') == 'paid':
            create_notification(
                session['user_id'],
                'Refund Initiated',
                'Refund for your cancelled appointment will be processed within 5-7 business days.',
                'info'
            )
        
        logger.info(f"✅ Appointment {appointment_id} cancelled by {session['user_id']}")
        
        return jsonify({
            'success': True,
            'message': 'Appointment cancelled successfully',
            'appointment_id': appointment_id
        })
        
    except Exception as e:
        logger.error(f"Error cancelling appointment: {e}")
        return jsonify({'success': False, 'error': 'Failed to cancel appointment'}), 500

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
@app.route('/patient-receipt/<appointment_id>')
@login_required
def patient_receipt_page(appointment_id):
    """Legacy route - redirect to new appointment receipt page"""
    logger.info(f"Redirecting from legacy patient-receipt to appointment-receipt for {appointment_id}")
    return redirect(url_for('appointment_receipt_page', appointment_id=appointment_id))
# @app.route('/appointment-receipt/<appointment_id>')
# @login_required
# def appointment_receipt_page(appointment_id):
#     """Serve the appointment receipt HTML page"""
#     return render_template('appointment_receipt.html', appointment_id=appointment_id)

# ========== DOCTOR-SPECIFIC ROUTES ==========

@app.route('/doctor-dashboard')
@login_required
@role_required(['doctor'])
def doctor_dashboard():
    """Doctor dashboard - Only for doctors"""
    stats = get_dashboard_stats('doctor', session['user_id'])
    return render_template('doctor_dashboard.html', user=session, stats=stats)

# ========== RECEPTIONIST-SPECIFIC ROUTES ==========
@app.route('/api/current-user')
@login_required
def get_current_user():
    """Get current user information"""
    try:
        current_db = get_db_safe()
        user_id = session['user_id']
        
        user_data = {
            'user_id': session.get('user_id'),
            'first_name': session.get('first_name'),
            'last_name': session.get('last_name'),
            'email': session.get('email'),
            'role': session.get('role')
        }
        
        # If database is available, get additional user details
        if current_db is not None:
            user = current_db.users.find_one({'user_id': user_id})
            if user:
                user_data.update({
                    'first_name': user.get('first_name', session.get('first_name')),
                    'last_name': user.get('last_name', session.get('last_name')),
                    'email': user.get('email', session.get('email')),
                    'role': user.get('role', session.get('role')),
                    'phone': user.get('phone', ''),
                    'specialization': user.get('specialization', ''),
                    'therapy_type': user.get('therapy_type', '')
                })
        
        return jsonify(user_data)
        
    except Exception as e:
        logger.error(f"Error getting current user: {e}")
        return jsonify({
            'user_id': session.get('user_id', ''),
            'first_name': session.get('first_name', 'User'),
            'last_name': session.get('last_name', ''),
            'email': session.get('email', ''),
            'role': session.get('role', 'user')
        })


@app.route('/receptionist/appointments')
@login_required
@role_required(['receptionist'])
def receptionist_manage_appointments():
    return render_template('manage_appointments.html')


@app.route('/receptionist-dashboard')
@login_required
@role_required(['receptionist'])
def receptionist_dashboard():
    """Receptionist dashboard - Only for receptionists"""
    stats = get_dashboard_stats('receptionist', session['user_id'])
    return render_template('receptionist_dashboard.html', user=session, stats=stats)

@app.route('/manage-appointments')
@login_required
@role_required(['receptionist'])
def manage_appointments():
    try:
        return render_template('manage_appointments.html', user=session)
    except Exception as e:
        print("Error loading manage appointments page:", e)
        return jsonify({"error": "Failed to load manage appointments page"}), 500



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
            print("hello")
    except Exception as e:
        logger.error(f"Error getting doctor appointments: {e}")
        return jsonify({'error': 'Failed to load appointments'}), 500


@app.route('/api/receptionist/notifications')
@login_required
@role_required(['receptionist'])
def get_receptionist_notifications():
    """Get REAL notifications for receptionist - NO DEMO DATA"""
    try:
        current_db = get_db_safe()
        receptionist_id = session['user_id']
        
        notifications = []
        
        if current_db is not None:
            # Get only real notifications from database
            notifications = list(current_db.notifications.find({
                'user_id': receptionist_id
            }).sort([('is_read', 1), ('created_at', -1)]).limit(50))  # Increased limit
            
            # Convert ObjectId to string
            for notification in notifications:
                notification['_id'] = str(notification['_id'])
                
                # Categorize notifications
                message = notification.get('message', '').lower()
                title = notification.get('title', '').lower()
                
                if any(keyword in message or keyword in title for keyword in ['appointment', 'booking', 'schedule']):
                    notification['category'] = 'appointment'
                    notification['priority'] = 'high'
                else:
                    notification['category'] = 'general'
        
        # If no notifications, return empty array
        return jsonify(notifications)
        
    except Exception as e:
        logger.error(f"Error getting receptionist notifications: {e}")
        return jsonify([])  # Return empty array on error        

# Razorpay Configuration - REAL PAYMENT
RAZORPAY_CONFIG = {
    'key_id': os.environ.get('RAZORPAY_KEY_ID'),
    'key_secret': os.environ.get('RAZORPAY_KEY_SECRET'),
    'therapy_prices': {
        'acupressure': 5000,  # 50 INR in paise (50 * 100)
        'ayurveda': 5000,
        'homeopathy': 5000,
        'naturopathy': 5000,
        'yoga': 5000,
        'unani': 5000,
        'chiropractic': 5000,
        'physiotherapy': 5000,
        'diet': 5000,
        'herbal': 5000,
        'sound': 5000
    }
}

# Initialize Razorpay client
try:
    if RAZORPAY_CONFIG['key_id'] and RAZORPAY_CONFIG['key_secret']:
        razorpay_client = razorpay.Client(auth=(RAZORPAY_CONFIG['key_id'], RAZORPAY_CONFIG['key_secret']))
        logger.info("✅ Razorpay client initialized successfully")
    else:
        razorpay_client = None
        logger.warning("⚠️ Razorpay keys not found - payment system disabled")
except Exception as e:
    logger.error(f"❌ Razorpay initialization failed: {e}")
    razorpay_client = None

@app.route('/api/verify-payment', methods=['POST'])
@login_required
def verify_payment():
    """Verify REAL Razorpay payment and update records"""
    try:
        if razorpay_client is None:
            return jsonify({
                'success': False,
                'error': 'Payment system temporarily unavailable'
            }), 503
            
        data = request.get_json()
        razorpay_payment_id = data.get('razorpay_payment_id')
        razorpay_order_id = data.get('razorpay_order_id')
        razorpay_signature = data.get('razorpay_signature')
        
        if not all([razorpay_payment_id, razorpay_order_id, razorpay_signature]):
            return jsonify({
                'success': False,
                'error': 'Missing payment verification data'
            }), 400
        
        logger.info(f"🔍 Verifying REAL payment: {razorpay_payment_id}")
        
        # Verify payment signature - CRITICAL STEP
        params_dict = {
            'razorpay_order_id': razorpay_order_id,
            'razorpay_payment_id': razorpay_payment_id,
            'razorpay_signature': razorpay_signature
        }
        
        try:
            razorpay_client.utility.verify_payment_signature(params_dict)
            logger.info(f"✅ Payment signature verified: {razorpay_payment_id}")
        except razorpay.errors.SignatureVerificationError as e:
            logger.error(f"❌ Payment signature verification FAILED: {e}")
            return jsonify({
                'success': False,
                'error': 'Payment verification failed. Please contact support.'
            }), 400
        
        # Update payment status in database
        current_db = get_db_safe()
        if current_db is not None:
            # Update payment record
            update_result = current_db.payments.update_one(
                {'payment_id': razorpay_order_id},
                {'$set': {
                    'razorpay_payment_id': razorpay_payment_id,
                    'status': 'paid',
                    'paid_at': datetime.utcnow(),
                    'updated_at': datetime.utcnow(),
                    'signature_verified': True
                }}
            )
            
            if update_result.modified_count == 0:
                logger.error(f"Payment record not found for order: {razorpay_order_id}")
                return jsonify({
                    'success': False,
                    'error': 'Payment record not found'
                }), 404
            
            # Get payment details to update appointment
            payment = current_db.payments.find_one({'payment_id': razorpay_order_id})
            if payment:
                # Update appointment status to confirmed
                appointment_update = current_db.appointments.update_one(
                    {'appointment_id': payment['appointment_id']},
                    {'$set': {
                        'status': 'confirmed',
                        'payment_status': 'paid',
                        'payment_id': razorpay_order_id,
                        'razorpay_payment_id': razorpay_payment_id,
                        'updated_at': datetime.utcnow()
                    }}
                )
                
                if appointment_update.modified_count > 0:
                    # Get appointment details for notification
                    appointment = current_db.appointments.find_one({'appointment_id': payment['appointment_id']})
                    
                    # Create success notifications
                    create_notification(
                        session['user_id'],
                        'Payment Successful! 🎉',
                        f'Payment of ₹{payment["amount"]} received for your {payment["therapy_type"]} appointment. Your appointment is now confirmed.',
                        'success'
                    )
                    
                    create_notification(
                        'REC001',
                        'New Paid Appointment - Confirmed',
                        f'Payment received for appointment {payment["appointment_id"]}. Patient: {session.get("first_name")} {session.get("last_name")}',
                        'info'
                    )
                    
                    logger.info(f"✅ REAL Payment completed: {razorpay_payment_id}, Appointment: {payment['appointment_id']}")
        
        return jsonify({
            'success': True,
            'message': 'Payment verified successfully! Your appointment is now confirmed.',
            'appointment_id': payment['appointment_id'] if payment else None,
            'payment_id': razorpay_payment_id
        })
        
    except Exception as e:
        logger.error(f"Error verifying REAL payment: {e}")
        return jsonify({
            'success': False,
            'error': 'Payment verification failed. Please contact support with your payment ID.'
        }), 500

@app.route('/api/create-payment', methods=['POST'])
@login_required
def create_payment():
    """Create REAL Razorpay payment order"""
    try:
        # Check if Razorpay is properly configured
        if razorpay_client is None:
            return jsonify({
                'success': False,
                'error': 'Payment system is currently unavailable. Please try again later.'
            }), 503
        
        data = request.get_json()
        appointment_id = data.get('appointment_id')
        therapy_type = data.get('therapy_type', 'acupressure')
        
        if not appointment_id:
            return jsonify({
                'success': False,
                'error': 'Appointment ID is required'
            }), 400
        
        # Get therapy price (convert to paise)
        amount = RAZORPAY_CONFIG['therapy_prices'].get(therapy_type, 5000)
        
        logger.info(f"💰 Creating payment order for {appointment_id}, Amount: {amount} paise")
        
        # Create Razorpay order
        order_data = {
            'amount': amount,
            'currency': 'INR',
            'receipt': f'receipt_{appointment_id}_{int(datetime.utcnow().timestamp())}',
            'notes': {
                'appointment_id': appointment_id,
                'therapy_type': therapy_type,
                'patient_id': session['user_id']
            },
            'payment_capture': 1
        }
        
        # Create order in Razorpay
        order = razorpay_client.order.create(data=order_data)
        
        # Store payment record in database
        current_db = get_db_safe()
        if current_db is not None:
            payment_doc = {
                'payment_id': order['id'],
                'appointment_id': appointment_id,
                'patient_id': session['user_id'],
                'amount': amount / 100,  # Convert back to rupees for display
                'currency': 'INR',
                'status': 'created',
                'therapy_type': therapy_type,
                'razorpay_order_id': order['id'],
                'created_at': datetime.utcnow(),
                'updated_at': datetime.utcnow()
            }
            current_db.payments.insert_one(payment_doc)
        
        logger.info(f"✅ Razorpay order created: {order['id']}")
        
        return jsonify({
            'success': True,
            'order_id': order['id'],
            'amount': order['amount'],
            'currency': order['currency'],
            'key_id': RAZORPAY_CONFIG['key_id'],  # This sends the REAL key to frontend
            'amount_in_rupees': amount / 100
        })
        
    except Exception as e:
        logger.error(f"Error creating payment: {e}")
        return jsonify({
            'success': False,
            'error': 'Failed to create payment order. Please try again.'
        }), 500
def generate_appointment_receipt(appointment_id):
    """Generate appointment receipt and return receipt data"""
    try:
        current_db = get_db_safe()
        
        if current_db is None:
            logger.warning(f"Cannot generate receipt - database not available for appointment {appointment_id}")
            return None
        
        # Get appointment with all details using aggregation
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
        
        appointment_result = current_db.appointments.aggregate(pipeline)
        appointment = next(appointment_result, None)
        
        if not appointment:
            logger.error(f"Appointment {appointment_id} not found for receipt generation")
            return None
        
        # Create receipt data with safe defaults
        patient = appointment.get('patient', {})
        doctor = appointment.get('doctor', {})
        payment = appointment.get('payment', {})
        
        # Safely handle dates
        appointment_date = appointment.get('date')
        if isinstance(appointment_date, datetime):
            formatted_date = appointment_date.strftime('%d %b %Y')
            formatted_time = appointment_date.strftime('%I:%M %p')
        else:
            formatted_date = 'Not scheduled'
            formatted_time = 'Not scheduled'
        
        # Safely handle payment date
        payment_date = payment.get('paid_at')
        if payment_date and isinstance(payment_date, datetime):
            formatted_payment_date = payment_date.strftime('%d %b %Y %I:%M %p')
        else:
            formatted_payment_date = 'N/A'
        
        receipt_data = {
            'receipt_id': f"RCP{random.randint(1000, 9999)}",
            'appointment_id': appointment_id,
            'generated_at': datetime.utcnow(),
            'patient_name': f"{patient.get('first_name', '')} {patient.get('last_name', '')}".strip() or 'Unknown Patient',
            'patient_email': patient.get('email', ''),
            'patient_phone': patient.get('phone', 'N/A'),
            'doctor_name': f"Dr. {doctor.get('first_name', '')} {doctor.get('last_name', '')}".strip() or 'Doctor Not Assigned',
            'therapy_type': appointment.get('therapy_type', '').title(),
            'appointment_date': formatted_date,
            'appointment_time': formatted_time,
            'consultation_type': appointment.get('consultation_type', 'General').title(),
            'amount': payment.get('amount', 100),
            'payment_status': payment.get('status', 'unpaid'),
            'payment_date': formatted_payment_date,
            'payment_id': payment.get('payment_id', 'N/A'),
            'reason': appointment.get('reason', 'Not specified'),
            'status': appointment.get('status', 'pending')
        }
        
        # Store receipt in database
        receipt_doc = {
            'receipt_id': receipt_data['receipt_id'],
            'appointment_id': appointment_id,
            'receipt_data': receipt_data,
            'created_at': datetime.utcnow(),
            'created_by': session.get('user_id', 'system')
        }
        
        # Create receipts collection if it doesn't exist
        if 'receipts' not in current_db.list_collection_names():
            current_db.create_collection('receipts')
        
        current_db.receipts.insert_one(receipt_doc)
        
        # Create notification about receipt generation
        create_notification(
            appointment.get('patient_id'),
            'Appointment Receipt Generated',
            f'Receipt for your {appointment.get("therapy_type", "therapy")} appointment has been generated. You can download it from your dashboard.',
            'info'
        )
        
        logger.info(f"✅ Receipt generated for appointment: {appointment_id}")
        return receipt_data
        
    except Exception as e:
        logger.error(f"Error generating receipt for appointment {appointment_id}: {e}")
        return None
@app.route('/api/receptionist/confirm-appointment-with-time', methods=['POST'])
@login_required
@role_required(['receptionist', 'admin'])
def confirm_appointment_with_time():
    """Confirm appointment with specific time slot and send notifications"""
    try:
        data = request.get_json()
        appointment_id = data.get('appointment_id')
        scheduled_time = data.get('scheduled_time')
        notes = data.get('notes', '')
        
        if not appointment_id or not scheduled_time:
            return jsonify({'success': False, 'error': 'Appointment ID and scheduled time are required'}), 400
        
        current_db = get_db_safe()
        
        if current_db is None:
            return jsonify({'success': True, 'message': 'Appointment confirmed (demo mode)'})
        
        # Get appointment details
        appointment = current_db.appointments.find_one({'appointment_id': appointment_id})
        if not appointment:
            return jsonify({'success': False, 'error': 'Appointment not found'}), 404
        
        # Parse scheduled time
        scheduled_datetime = datetime.fromisoformat(scheduled_time.replace('Z', '+00:00'))
        
        # Update appointment with confirmed time
        update_data = {
            'status': 'confirmed',
            'date': scheduled_datetime,
            'confirmed_by': session['user_id'],
            'confirmed_at': datetime.utcnow(),
            'updated_at': datetime.utcnow(),
            'receptionist_notes': notes
        }
        
        result = current_db.appointments.update_one(
            {'appointment_id': appointment_id},
            {'$set': update_data}
        )
        
        if result.modified_count == 0:
            return jsonify({'success': False, 'error': 'Failed to update appointment'}), 400
        
        # Get patient and doctor details for notifications
        patient = current_db.users.find_one({'user_id': appointment.get('patient_id')})
        doctor = current_db.users.find_one({'user_id': appointment.get('therapist_id')})
        
        # Format date for display
        formatted_date = scheduled_datetime.strftime('%d %b %Y at %I:%M %p')
        
        # Send email notifications
        if patient:
            # Send appointment confirmation email to patient
            send_appointment_confirmation_email(
                patient['email'],
                f"{patient.get('first_name', '')} {patient.get('last_name', '')}",
                formatted_date,
                appointment.get('therapy_type', '').title(),
                f"Dr. {doctor.get('first_name', '')} {doctor.get('last_name', '')}" if doctor else 'Doctor'
            )
            
            # Create notification for patient
            create_notification(
                patient['user_id'],
                'Appointment Confirmed! 🎉',
                f'Your {appointment.get("therapy_type", "therapy")} appointment has been confirmed for {formatted_date}. Please arrive 10 minutes before your scheduled time.',
                'success'
            )
        
        # Notify doctor
        if doctor:
            send_doctor_notification_email(
                doctor['email'],
                f"{doctor.get('first_name', '')} {doctor.get('last_name', '')}",
                f"{patient.get('first_name', '')} {patient.get('last_name', '')}" if patient else 'Patient',
                formatted_date,
                appointment.get('therapy_type', '').title()
            )
            
            create_notification(
                doctor['user_id'],
                'New Appointment Confirmed',
                f'New appointment confirmed with {patient.get("first_name", "Patient") if patient else "Patient"} for {appointment.get("therapy_type")} on {formatted_date}.',
                'info'
            )
        
        # Generate receipt automatically
        receipt_data = generate_appointment_receipt(appointment_id)
        
        logger.info(f"✅ Appointment {appointment_id} confirmed with time slot by {session['user_id']}")
        
        return jsonify({
            'success': True,
            'message': 'Appointment confirmed successfully! Notifications sent to patient and doctor.',
            'appointment_id': appointment_id,
            'scheduled_time': formatted_date,
            'receipt_generated': True,
            'patient_notified': True,
            'doctor_notified': True if doctor else False
        })
        
    except Exception as e:
        logger.error(f"Error confirming appointment with time: {e}")
        return jsonify({'success': False, 'error': 'Failed to confirm appointment'}), 500

@app.route('/api/receptionist/send-doctor-info/<appointment_id>', methods=['POST'])
@login_required
@role_required(['receptionist', 'admin'])
def send_doctor_info_endpoint(appointment_id):
    """Send patient information to doctor"""
    try:
        current_db = get_db_safe()
        
        if current_db is None:
            return jsonify({'success': True, 'message': 'Doctor info sent (demo mode)'})
        
        # Get appointment details
        appointment = current_db.appointments.find_one({'appointment_id': appointment_id})
        if not appointment:
            return jsonify({'success': False, 'error': 'Appointment not found'}), 404
        
        # Get patient details
        patient = current_db.users.find_one({'user_id': appointment.get('patient_id')})
        if not patient:
            return jsonify({'success': False, 'error': 'Patient not found'}), 404
        
        # Get doctor details
        doctor = current_db.users.find_one({'user_id': appointment.get('therapist_id')})
        if not doctor:
            return jsonify({'success': False, 'error': 'Doctor not found'}), 404
        
        # Create notification for doctor
        create_notification(
            doctor['user_id'],
            'Patient Information',
            f'Patient information for {patient.get("first_name", "")} {patient.get("last_name", "")} has been sent for appointment {appointment_id}.',
            'info'
        )
        
        # Update appointment to mark info as sent
        current_db.appointments.update_one(
            {'appointment_id': appointment_id},
            {'$set': {
                'doctor_info_sent': True,
                'info_sent_at': datetime.utcnow(),
                'info_sent_by': session['user_id'],
                'updated_at': datetime.utcnow()
            }}
        )
        
        logger.info(f"Patient info sent to doctor for appointment: {appointment_id}")
        
        return jsonify({
            'success': True,
            'message': f'Patient information sent successfully to Dr. {doctor.get("first_name")} {doctor.get("last_name")}'
        })
        
    except Exception as e:
        logger.error(f"Error sending doctor info: {e}")
        return jsonify({'success': False, 'error': 'Failed to send patient information to doctor'}), 500




def send_patient_info_to_doctor(doctor_email, patient_info, doctor_first_name):
    """Send patient information to doctor via email"""
    try:
        sender = EMAIL_CONFIG.get('sender_email')
        password = EMAIL_CONFIG.get('sender_password')
        
        subject = f"Patient Information - {patient_info['name']} - {patient_info['therapy_type']}"
        
        body = f"""
Dear Dr. {doctor_first_name},

Please find below the patient information for your upcoming appointment:

PATIENT DETAILS:
----------------
Name: {patient_info['name']}
Patient ID: {patient_info['patient_id']}
Age: {patient_info['age']}
Gender: {patient_info['gender']}
Phone: {patient_info['phone']}
Email: {patient_info['email']}
Address: {patient_info['address']}

MEDICAL INFORMATION:
-------------------
Medical History: {patient_info['medical_history']}
Allergies: {patient_info['allergies']}
Current Medications: {patient_info['current_medications']}

APPOINTMENT DETAILS:
-------------------
Therapy Type: {patient_info['therapy_type']}
Appointment Date: {patient_info['appointment_date']}
Consultation Type: {patient_info['consultation_type']}
Reason for Visit: {patient_info['appointment_reason']}

Please review this information before the appointment.

Best regards,
Reception Desk
DCAM Therapy Center
Dev Sanskriti Vishwavidyalaya
        """
        
        if sender is None or password is None:
            logger.info(f"📧 (Console) Patient info for Dr. {doctor_first_name}:")
            logger.info(f"    Patient: {patient_info['name']}")
            logger.info(f"    Appointment: {patient_info['appointment_date']}")
            logger.info(f"    Therapy: {patient_info['therapy_type']}")
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
        
        logger.info(f"📧 Patient information sent to Dr. {doctor_first_name}")
        return True
        
    except Exception as e:
        logger.error(f"Error sending patient info email: {e}")
        logger.info(f"📧 (Fallback) Patient info for Dr. {doctor_first_name}: {patient_info['name']}")
        return False




@app.route('/api/appointments', methods=['POST'])
@login_required
def create_appointment():
    """Create new appointment with enhanced notification system"""
    try:
        data = request.get_json()
        
        # Input validation
        if not data:
            return jsonify({'error': 'No data provided'}), 400
            
        required_fields = ['therapy_type', 'date', 'reason']
        for field in required_fields:
            if field not in data or not data[field]:
                return jsonify({'error': f'Missing required field: {field}'}), 400
        
        # Generate appointment ID
        appointment_id = f"APT{random.randint(1000, 9999)}"
        
        # Parse appointment date with error handling
        try:
            appointment_date = datetime.fromisoformat(data.get('date').replace('Z', '+00:00'))
        except (ValueError, AttributeError) as e:
            return jsonify({'error': 'Invalid date format'}), 400

        # Get therapy type and assign doctor
        therapy_type = data.get('therapy_type', 'general')
        therapist_id = data.get('therapist_id')

        # If no therapist specified, find one based on therapy type
        if not therapist_id:
            current_db = get_db_safe()
            if current_db is not None:
                # Find doctor specializing in this therapy
                doctor = current_db.users.find_one({
                    'role': 'doctor',
                    'therapy_type': therapy_type,
                    'is_available': True
                })
                if doctor:
                    therapist_id = doctor['user_id']

        appointment_data = {
            'appointment_id': appointment_id,
            'patient_id': session['user_id'],
            'patient_name': f"{session.get('first_name', '')} {session.get('last_name', '')}",
            'therapy_type': therapy_type,
            'therapist_id': therapist_id,
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
            
            # ✅ ENHANCED: Send notification to ALL receptionists
            send_receptionist_appointment_notification(appointment_data)
            
            # Create notification for patient
            create_notification(
                session['user_id'],
                'Appointment Request Submitted ✅',
                f'Your {therapy_type} appointment request has been submitted (ID: {appointment_id}). We will confirm shortly.',
                'info'
            )
            
            # Get doctor details for notification
            if therapist_id:
                doctor = current_db.users.find_one({'user_id': therapist_id})
                if doctor:
                    create_notification(
                        doctor['user_id'],
                        'New Appointment Request 📋',
                        f'New {therapy_type} appointment request from {appointment_data["patient_name"]}. Waiting for receptionist confirmation.',
                        'info'
                    )
            
            logger.info(f"✅ REAL Appointment {appointment_id} created - Notifications sent to receptionists")
            
        return jsonify({
            'message': 'Appointment requested successfully! Waiting for receptionist confirmation.',
            'appointment_id': appointment_id,
            'status': 'pending'
        }), 201
            
    except Exception as e:
        logger.error(f"Error creating appointment: {str(e)}")
        return jsonify({'error': 'Failed to book appointment'}), 500

def send_receptionist_appointment_notification(appointment_data):
    """Send detailed appointment notification to ALL receptionists"""
    try:
        current_db = get_db_safe()
        if current_db is None:
            logger.info("📢 Appointment notification - Database not available")
            return
        
        # Find all active receptionists
        receptionists = current_db.users.find({
            'role': 'receptionist', 
            'is_active': True
        })
        
        appointment_id = appointment_data.get('appointment_id')
        patient_name = appointment_data.get('patient_name', 'New Patient')
        therapy_type = appointment_data.get('therapy_type', 'Therapy').title()
        appointment_date = appointment_data.get('date')
        
        # Format date for display
        if appointment_date:
            formatted_date = appointment_date.strftime('%d %b %Y at %I:%M %p')
        else:
            formatted_date = 'Date not specified'
        
        notification_count = 0
        
        for receptionist in receptionists:
            receptionist_id = receptionist.get('user_id')
            receptionist_name = receptionist.get('first_name', 'Receptionist')
            
            # Create detailed notification message
            notification_title = "📋 New Appointment Request - Action Required"
            notification_message = f"""
 **New Appointment Booking**

**Patient Details:**
Name: {patient_name}
Phone: {appointment_data.get('patient_phone', 'Not provided')}
Email: {appointment_data.get('patient_email', 'Not provided')}

**Appointment Details:**
Therapy: {therapy_type}
Date & Time: {formatted_date}
Reason: {appointment_data.get('reason', 'Not specified')}
Appointment ID: {appointment_id}

**Required Action:**
Please review and confirm this appointment at the earliest.
            """.strip()
            
            # Create notification in database
            notification_id = create_notification(
                receptionist_id,
                notification_title,
                notification_message,
                'info'
            )
            
            if notification_id:
                notification_count += 1
                logger.info(f"📢 REAL Notification sent to receptionist {receptionist_name} ({receptionist_id}) for appointment {appointment_id}")
        
        logger.info(f"✅ Successfully sent {notification_count} receptionist notifications for appointment {appointment_id}")
            
    except Exception as e:
        logger.error(f"❌ Error sending receptionist appointment notification: {e}")


@app.route('/api/receptionist/appointments/<appointment_id>/confirm', methods=['POST'])
@login_required
@role_required(['receptionist', 'admin'])
def confirm_appointment_api(appointment_id):
    """Confirm an appointment and send notifications - FIXED VERSION"""
    try:
        current_db = get_db_safe()
        
        if current_db is None:
            return jsonify({'success': True, 'message': 'Appointment confirmed (demo mode)'})
        
        # Get appointment details first
        appointment = current_db.appointments.find_one({'appointment_id': appointment_id})
        if not appointment:
            return jsonify({'success': False, 'error': 'Appointment not found'}), 404
        
        # Update appointment status
        update_data = {
            'status': 'confirmed',
            'confirmed_by': session['user_id'],
            'confirmed_at': datetime.utcnow(),
            'updated_at': datetime.utcnow()
        }
        
        result = current_db.appointments.update_one(
            {'appointment_id': appointment_id},
            {'$set': update_data}
        )
        
        if result.modified_count == 0:
            return jsonify({'success': False, 'error': 'Failed to update appointment'}), 400
        
        # Get patient and doctor details for notifications
        patient = current_db.users.find_one({'user_id': appointment.get('patient_id')})
        doctor = current_db.users.find_one({'user_id': appointment.get('therapist_id')})
        
        # Format date for notifications
        appointment_date = appointment.get('date')
        formatted_date = appointment_date.strftime('%d %b %Y at %I:%M %p') if appointment_date else 'To be scheduled'
        
        # Create notifications for all parties
        if patient:
            create_notification(
                patient['user_id'],
                'Appointment Confirmed! 🎉',
                f'Your {appointment.get("therapy_type", "therapy")} appointment has been confirmed for {formatted_date}. Please arrive 10 minutes before your scheduled time.',
                'success'
            )
        
        # Notify doctor
        if doctor:
            create_notification(
                doctor['user_id'],
                'New Appointment Confirmed',
                f'New appointment confirmed with {patient.get("first_name", "Patient") if patient else "Patient"} for {appointment.get("therapy_type")} on {formatted_date}.',
                'info'
            )
        
        logger.info(f"✅ Appointment {appointment_id} confirmed by {session['user_id']}")
        
        return jsonify({
            'success': True,
            'message': 'Appointment confirmed successfully! Notifications sent to patient and doctor.',
            'appointment_id': appointment_id,
            'patient_notified': True if patient else False,
            'doctor_notified': True if doctor else False
        })
        
    except Exception as e:
        logger.error(f"Error confirming appointment: {e}")
        return jsonify({'success': False, 'error': 'Failed to confirm appointment'}), 500




# Enhanced notification function
def create_appointment_notification(appointment_id, action_type, performed_by):
    """Create notifications for appointment actions with enhanced messages"""
    try:
        current_db = get_db_safe()
        if current_db is None:
            return
        
        # Get appointment details
        appointment = current_db.appointments.find_one({'appointment_id': appointment_id})
        if not appointment:
            return
        
        patient_id = appointment.get('patient_id')
        doctor_id = appointment.get('therapist_id')
        therapy_type = appointment.get('therapy_type', 'therapy')
        patient_name = appointment.get('patient_name', 'Patient')
        
        notifications = []
        
        if action_type == 'confirmed':
            # Notify patient
            notifications.append({
                'user_id': patient_id,
                'title': 'Appointment Confirmed! 🎉',
                'message': f'Your {therapy_type} appointment has been confirmed by receptionist. Please arrive 10 minutes before your scheduled time.',
                'type': 'success',
                'is_read': False,
                'created_at': datetime.utcnow()
            })
            
            # Notify doctor
            if doctor_id:
                notifications.append({
                    'user_id': doctor_id,
                    'title': 'New Confirmed Appointment',
                    'message': f'New {therapy_type} appointment confirmed with {patient_name}. Please check your schedule.',
                    'type': 'info',
                    'is_read': False,
                    'created_at': datetime.utcnow()
                })
                
        elif action_type == 'cancelled':
            # Notify patient
            notifications.append({
                'user_id': patient_id,
                'title': 'Appointment Cancelled',
                'message': f'Your {therapy_type} appointment has been cancelled by receptionist.',
                'type': 'warning',
                'is_read': False,
                'created_at': datetime.utcnow()
            })
            
            # Notify doctor if assigned
            if doctor_id:
                notifications.append({
                    'user_id': doctor_id,
                    'title': 'Appointment Cancelled',
                    'message': f'Your {therapy_type} appointment with {patient_name} has been cancelled.',
                    'type': 'warning',
                    'is_read': False,
                    'created_at': datetime.utcnow()
                })
        
        # Insert all notifications
        if notifications and current_db is not None:
            current_db.notifications.insert_many(notifications)
            logger.info(f"Created {len(notifications)} notifications for appointment {appointment_id}")
            
    except Exception as e:
        logger.error(f"Error creating appointment notifications: {e}")



@app.route('/api/receptionist/appointments/<appointment_id>/cancel', methods=['POST'])
@login_required
@role_required(['receptionist', 'admin'])
def cancel_appointment_receptionist(appointment_id):
    """Cancel appointment by receptionist"""
    try:
        data = request.get_json() or {}
        reason = data.get('reason', 'Cancelled by receptionist')
        
        current_db = get_db_safe()
        
        if current_db is None:
            return jsonify({'message': 'Appointment cancelled (demo mode)'})
        
        # Get appointment details
        appointment = current_db.appointments.find_one({'appointment_id': appointment_id})
        if not appointment:
            return jsonify({'error': 'Appointment not found'}), 404
        
        # Update appointment status
        result = current_db.appointments.update_one(
            {'appointment_id': appointment_id},
            {'$set': {
                'status': 'cancelled',
                'cancelled_by': session['user_id'],
                'cancelled_at': datetime.utcnow(),
                'cancellation_reason': reason,
                'updated_at': datetime.utcnow()
            }}
        )
        
        if result.modified_count == 0:
            return jsonify({'error': 'Failed to cancel appointment'}), 400
        
        # Create notifications
        create_notification(
            appointment['patient_id'],
            'Appointment Cancelled',
            f'Your {appointment.get("therapy_type", "therapy")} appointment has been cancelled by receptionist. Reason: {reason}',
            'warning'
        )
        
        # Notify doctor if applicable
        if appointment.get('therapist_id'):
            create_notification(
                appointment['therapist_id'],
                'Appointment Cancelled',
                f'Appointment {appointment_id} for {appointment.get("therapy_type")} has been cancelled by receptionist.',
                'warning'
            )
        
        logger.info(f"✅ Appointment {appointment_id} cancelled by receptionist {session['user_id']}")
        
        return jsonify({
            'message': 'Appointment cancelled successfully',
            'appointment_id': appointment_id
        })
        
    except Exception as e:
        logger.error(f"Error cancelling appointment: {e}")
        return jsonify({'error': 'Failed to cancel appointment'}), 500

@app.route('/api/patient-notifications')
@login_required
@role_required(['patient'])
def get_patient_notifications():
    """Get notifications for patient"""
    try:
        current_db = get_db_safe()
        patient_id = session['user_id']
        
        notifications = []
        
        if current_db is not None:
            notifications = list(current_db.notifications.find({
                'user_id': patient_id
            }).sort('created_at', -1).limit(10))
            
            # Convert ObjectId to string
            for notification in notifications:
                notification['_id'] = str(notification['_id'])
        
        return jsonify(notifications)
        
    except Exception as e:
        logger.error(f"Error getting patient notifications: {e}")
        return jsonify([])

@app.route('/api/notifications/<notification_id>/mark-read', methods=['POST'])
@login_required
def mark_notification_read(notification_id):
    """Mark a notification as read"""
    try:
        current_db = get_db_safe()
        
        if current_db is not None:
            current_db.notifications.update_one(
                {'_id': ObjectId(notification_id)},
                {'$set': {'is_read': True}}
            )
        
        return jsonify({'success': True})
        
    except Exception as e:
        logger.error(f"Error marking notification as read: {e}")
        return jsonify({'error': 'Failed to mark notification as read'}), 500


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
                print("hello")
                return jsonify("")
                
        except Exception as e:
            logger.error(f"Error fetching appointments: {e}")
            return jsonify([])
    
    elif request.method == 'POST':
        # Create new appointment with enhanced notification system
        return create_appointment()


@app.route('/api/doctor/status', methods=['POST'])
@login_required
@role_required(['doctor'])
def update_doctor_status():
    """Update doctor availability status"""
    try:
        current_db = get_db_safe()
        doctor_id = session['user_id']
        data = request.get_json()
        
        is_available = data.get('is_available', True)
        
        result = current_db.users.update_one(
            {'user_id': doctor_id},
            {'$set': {
                'is_available': is_available,
                'status_updated_at': datetime.utcnow(),
                'updated_at': datetime.utcnow()
            }}
        )
        
        if result.modified_count > 0:
            status_text = "available" if is_available else "busy"
            
            # Create notification for receptionist
            create_notification(
                'REC001',
                f'Doctor Status Changed',
                f'Dr. {session.get("first_name")} {session.get("last_name")} is now {status_text}.',
                'info' if is_available else 'warning'
            )
            
            return jsonify({
                'success': True, 
                'message': f'Status updated to {status_text}',
                'is_available': is_available
            })
        else:
            return jsonify({'error': 'Failed to update status'}), 400
            
    except Exception as e:
        logger.error(f"Error updating doctor status: {e}")
        return jsonify({'error': 'Failed to update status'}), 500

@app.route('/api/doctors')
@login_required
def get_all_doctors():
    """Get all doctors for receptionist and patient views"""
    try:
        current_db = get_db_safe()
        
        doctors = []
        
        if current_db is not None:
            doctors_cursor = current_db.users.find({'role': 'doctor'})
            
            for doctor in doctors_cursor:
                # Get today's availability
                today = datetime.now(timezone.utc).strftime('%A').lower()
                today_availability = current_db.doctor_availability.find_one({
                    'doctor_id': doctor['user_id'],
                    'day_of_week': today,
                    'is_active': True
                })
                
                # Get today's appointments count
                today_start = datetime.now(timezone.utc).replace(hour=0, minute=0, second=0, microsecond=0)
                today_end = today_start + timedelta(days=1)
                
                today_appointments = current_db.appointments.count_documents({
                    'therapist_id': doctor['user_id'],
                    'date': {'$gte': today_start, '$lt': today_end},
                    'status': {'$in': ['scheduled', 'confirmed']}
                })
                
                doctor_data = {
                    'user_id': doctor['user_id'],
                    'name': f"Dr. {doctor.get('first_name', '')} {doctor.get('last_name', '')}",
                    'specialization': doctor.get('specialization', 'Therapy Specialist'),
                    'email': doctor.get('email'),
                    'phone': doctor.get('phone', ''),
                    'qualifications': doctor.get('qualifications', ''),
                    'experience': doctor.get('experience', 0),
                    'bio': doctor.get('bio', ''),
                    'consultation_fee': doctor.get('consultation_fee', 0),
                    'languages': doctor.get('languages', ''),
                    'is_available': doctor.get('is_available', True),
                    'status_updated_at': doctor.get('status_updated_at'),
                    'today_availability': today_availability is not None,
                    'today_appointments': today_appointments,
                    'profile_photo': doctor.get('profile_photo', ''),
                    'therapy_type': doctor.get('therapy_type', 'general')  # ADD THIS LINE
                }
                
                doctors.append(doctor_data)
        
        return jsonify(doctors)
        
    except Exception as e:
        logger.error(f"Error getting doctors: {e}")
        return jsonify([])

@app.route('/api/doctor/<doctor_id>/profile')
@login_required
def get_doctor_profile(doctor_id):
    """Get specific doctor profile for patient view"""
    try:
        current_db = get_db_safe()
        
        doctor = current_db.users.find_one({
            'user_id': doctor_id,
            'role': 'doctor'
        })
        
        if not doctor:
            return jsonify({'error': 'Doctor not found'}), 404
        
        # Get availability
        availability = list(current_db.doctor_availability.find({
            'doctor_id': doctor_id,
            'is_active': True
        }))
        
        profile_data = {
            'user_id': doctor['user_id'],
            'name': f"Dr. {doctor.get('first_name', '')} {doctor.get('last_name', '')}",
            'specialization': doctor.get('specialization', 'Therapy Specialist'),
            'email': doctor.get('email'),
            'phone': doctor.get('phone', ''),
            'qualifications': doctor.get('qualifications', ''),
            'experience': doctor.get('experience', 0),
            'bio': doctor.get('bio', ''),
            'consultation_fee': doctor.get('consultation_fee', 0),
            'languages': doctor.get('languages', ''),
            'awards': doctor.get('awards', ''),
            'is_available': doctor.get('is_available', True),
            'availability': availability,
            'profile_photo': doctor.get('profile_photo', '')
        }
        
        return jsonify(profile_data)
        
    except Exception as e:
        logger.error(f"Error getting doctor profile: {e}")
        return jsonify({'error': 'Failed to load doctor profile'}), 500

@app.route('/api/patient-data')
@login_required
@role_required(['patient'])
def patient_data():
    """Get patient data for patient info page - FIXED VERSION"""
    try:
        current_db = get_db_safe()
        user_id = session['user_id']
        
        print(f"📋 Loading patient data for: {user_id}")  # Debug log
        
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
                    'blood_group': patient.get('blood_group', ''),
                    'allergies': patient.get('allergies', ''),
                    'medical_conditions': patient.get('medical_conditions', ''),
                    'current_medications': patient.get('current_medications', ''),
                    'emergency_contact': patient.get('emergency_contact', ''),
                    'created_at': patient.get('created_at')
                }
                print(f"✅ Patient data loaded: {patient_data}")  # Debug log
                return jsonify(patient_data)
        
        # Demo data with all fields
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
            'emergency_contact': '+91-9876543210',
            'created_at': datetime.utcnow().isoformat()
        }
        return jsonify(demo_patient_data)
        
    except Exception as e:
        print(f"❌ Error fetching patient data: {e}")
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
        return jsonify("")
        
    except Exception as e:
        logger.error(f"Error fetching therapists: {e}")
        return jsonify([])

@app.route('/api/update-patient-info', methods=['POST'])
@login_required
@role_required(['patient'])
def update_patient_info():
    """Update patient information - FIXED VERSION"""
    try:
        data = request.get_json()
        user_id = session['user_id']
        
        print(f"📝 Updating patient info for {user_id}:", data)  # Debug log
        
        current_db = get_db_safe()
        if current_db is None:
            return jsonify({'message': 'Patient information updated (demo mode)'})
        
        update_data = {}
        allowed_fields = [
            'phone', 'address', 'date_of_birth', 'gender', 'blood_group',
            'allergies', 'medical_conditions', 'current_medications', 
            'emergency_contact'
        ]
        
        for field in allowed_fields:
            if field in data:
                update_data[field] = data[field]
                print(f"✅ Setting {field} to: {data[field]}")  # Debug log
        
        if update_data:
            update_data['updated_at'] = datetime.utcnow()
            result = current_db.users.update_one(
                {'user_id': user_id},
                {'$set': update_data}
            )
            
            if result.modified_count > 0:
                print(f"✅ Successfully updated patient info for {user_id}")
                return jsonify({'message': 'Patient information updated successfully'})
            else:
                print(f"❌ No changes made for patient {user_id}")
                return jsonify({'error': 'No changes made or patient not found'}), 400
        else:
            print("❌ No valid fields to update")
            return jsonify({'error': 'No valid fields to update'}), 400
            
    except Exception as e:
        print(f"❌ Error updating patient info: {e}")
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
    """Get all appointments for receptionist view - ENHANCED VERSION"""
    try:
        current_db = get_db_safe()
        
        # Get filter parameters with defaults
        status_filter = request.args.get('status', 'all')
        date_filter = request.args.get('date', 'all')
        search_term = request.args.get('search', '')
        
        # Build query
        query = {}
        
        if status_filter != 'all':
            query['status'] = status_filter
        
        # Date filtering
        if date_filter == 'today':
            today_start = datetime.now(timezone.utc).replace(hour=0, minute=0, second=0, microsecond=0)
            today_end = today_start + timedelta(days=1)
            query['date'] = {'$gte': today_start, '$lt': today_end}
        elif date_filter == 'upcoming':
            query['date'] = {'$gte': datetime.now(timezone.utc)}
        elif date_filter == 'past':
            query['date'] = {'$lt': datetime.now(timezone.utc)}
        
        appointments = []
        if current_db is not None:
            # If search term provided, build search query
            if search_term:
                # Get patient IDs that match search
                patient_search = {
                    '$or': [
                        {'first_name': {'$regex': search_term, '$options': 'i'}},
                        {'last_name': {'$regex': search_term, '$options': 'i'}},
                        {'email': {'$regex': search_term, '$options': 'i'}},
                        {'phone': {'$regex': search_term, '$options': 'i'}}
                    ]
                }
                matching_patients = list(current_db.users.find(patient_search))
                patient_ids = [p['user_id'] for p in matching_patients]
                
                # Add to query
                query['$or'] = [
                    {'patient_id': {'$in': patient_ids}},
                    {'appointment_id': {'$regex': search_term, '$options': 'i'}},
                    {'therapy_type': {'$regex': search_term, '$options': 'i'}}
                ]
            
            appointment_cursor = current_db.appointments.find(query).sort('date', -1)
            appointments = list(appointment_cursor)
            
            # Enhance appointment data with user information
            for appointment in appointments:
                appointment['_id'] = str(appointment['_id'])
                
                # Get patient details
                patient = current_db.users.find_one({'user_id': appointment.get('patient_id')})
                if patient:
                    appointment['patient_name'] = f"{patient.get('first_name', '')} {patient.get('last_name', '')}"
                    appointment['patient_email'] = patient.get('email')
                    appointment['patient_phone'] = patient.get('phone', 'N/A')
                    appointment['patient_details'] = {
                        'name': f"{patient.get('first_name', '')} {patient.get('last_name', '')}",
                        'email': patient.get('email'),
                        'phone': patient.get('phone', 'N/A'),
                        'id': patient.get('user_id')
                    }
                else:
                    appointment['patient_name'] = 'Unknown Patient'
                    appointment['patient_email'] = 'N/A'
                    appointment['patient_phone'] = 'N/A'
                
                # Get doctor details
                doctor = current_db.users.find_one({'user_id': appointment.get('therapist_id')})
                if doctor:
                    appointment['doctor_name'] = f"Dr. {doctor.get('first_name', '')} {doctor.get('last_name', '')}"
                    appointment['doctor_details'] = {
                        'name': f"Dr. {doctor.get('first_name', '')} {doctor.get('last_name', '')}",
                        'specialization': doctor.get('specialization', ''),
                        'id': doctor.get('user_id')
                    }
                else:
                    appointment['doctor_name'] = 'Not Assigned'

                # Determine therapy name
                therapy_type = appointment.get('therapy_type')
                if therapy_type and isinstance(therapy_type, str):
                    appointment['therapy_name'] = therapy_type.title()
                else:
                    appointment['therapy_name'] = 'General Therapy'
                
                # Ensure payment_status exists
                if 'payment_status' not in appointment:
                    appointment['payment_status'] = 'unpaid'
                
                # Format date for frontend
                if appointment.get('date'):
                    appointment['formatted_date'] = appointment['date'].strftime('%Y-%m-%d %H:%M')
                    appointment['date_iso'] = appointment['date'].isoformat()
        
        # Calculate stats
        stats = {
            'total': len(appointments),
            'pending': len([a for a in appointments if a.get('status') == 'pending']),
            'confirmed': len([a for a in appointments if a.get('status') == 'confirmed']),
            'completed': len([a for a in appointments if a.get('status') == 'completed']),
            'cancelled': len([a for a in appointments if a.get('status') == 'cancelled']),
        }
        
        return jsonify({
            'success': True,
            'appointments': appointments,
            'stats': stats,
            'filters': {
                'status': status_filter,
                'date': date_filter,
                'search': search_term
            }
        })
        
    except Exception as e:
        logger.error(f"Error getting receptionist appointments: {e}")
        return jsonify({
            'success': False,
            'error': 'Failed to load appointments',
            'appointments': [],
            'stats': {}
        }), 500
@app.route('/api/notifications')
@login_required
def get_notifications():
    """Get notifications for current user"""
    try:
        current_db = get_db_safe()
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
def check_in_appointment_api(appointment_id):
    """Check in patient for appointment"""
    try:
        current_db = get_db_safe()
        
        if current_db is None:
            return jsonify({'success': True, 'message': 'Patient checked in (demo mode)'})
        
        # Update appointment status
        result = current_db.appointments.update_one(
            {'appointment_id': appointment_id},
            {'$set': {
                'checked_in': True,
                'check_in_time': datetime.utcnow(),
                'updated_at': datetime.utcnow()
            }}
        )
        
        if result.modified_count == 0:
            return jsonify({'success': False, 'error': 'Appointment not found'}), 404
        
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
            
            # Create notification for patient
            create_notification(
                appointment['patient_id'],
                'Checked In Successfully',
                f'You have been checked in for your {appointment.get("therapy_type")} appointment.',
                'success'
            )
        
        logger.info(f"✅ Patient checked in for appointment: {appointment_id}")
        
        return jsonify({
            'success': True,
            'message': 'Patient checked in successfully',
            'appointment_id': appointment_id
        })
        
    except Exception as e:
        logger.error(f"Error checking in patient: {e}")
        return jsonify({'success': False, 'error': 'Failed to check in patient'}), 500

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
            else:
                # Create payment record if doesn't exist
                payment_data = {
                    'payment_id': f"PAY{random.randint(1000, 9999)}",
                    'appointment_id': appointment_id,
                    'patient_id': appointment.get('patient_id'),
                    'amount': 100,  # Default amount
                    'currency': 'INR',
                    'status': 'paid',
                    'paid_at': datetime.utcnow(),
                    'confirmed_by': session['user_id'],
                    'created_at': datetime.utcnow(),
                    'updated_at': datetime.utcnow()
                }
                current_db.payments.insert_one(payment_data)
            
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
            
            logger.info(f"Payment confirmed for appointment: {appointment_id}")
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
def check_out_appointment_api(appointment_id):
    """Check-out a patient and mark appointment as completed"""
    try:
        current_db = get_db_safe()
        
        if current_db is None:
            return jsonify({'success': True, 'message': 'Patient checked out (demo mode)'})
        
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
            return jsonify({'success': False, 'error': 'Appointment not found'}), 404
        
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
            if appointment.get('therapist_id'):
                create_notification(
                    appointment['therapist_id'],
                    'Appointment Completed',
                    f'Appointment with {appointment.get("patient_name", "Patient")} has been completed.',
                    'info'
                )
        
        logger.info(f"✅ Patient checked out and appointment completed: {appointment_id}")
        
        return jsonify({
            'success': True,
            'message': 'Patient checked out successfully and appointment marked as completed',
            'appointment_id': appointment_id
        })
        
    except Exception as e:
        logger.error(f"Error checking out patient: {e}")
        return jsonify({'success': False, 'error': 'Failed to check out patient'}), 500

@app.route('/api/receptionist/stats')
@login_required
@role_required(['receptionist', 'admin'])
def get_receptionist_stats():
    """Get receptionist dashboard statistics"""
    try:
        current_db = get_db_safe()
        
        stats = {
            'todays_appointments': 0,
            'pending_appointments': 0,
            'total_patients': 0,
            'total_doctors': 0,
            'available_doctors': 0
        }
        
        if current_db is not None:
            # Today's date range
            today_start = datetime.now(timezone.utc).replace(hour=0, minute=0, second=0, microsecond=0)
            today_end = today_start + timedelta(days=1)
            
            # Today's appointments
            stats['todays_appointments'] = current_db.appointments.count_documents({
                'date': {'$gte': today_start, '$lt': today_end}
            })
            
            # Pending appointments
            stats['pending_appointments'] = current_db.appointments.count_documents({
                'status': 'pending'
            })
            
            # Total patients
            stats['total_patients'] = current_db.users.count_documents({
                'role': 'patient'
            })
            
            # Total doctors
            stats['total_doctors'] = current_db.users.count_documents({
                'role': 'doctor'
            })
            
            # Available doctors now
            current_day = datetime.now(timezone.utc).strftime('%A').lower()
            current_time = datetime.now(timezone.utc).strftime('%H:%M')
            
            available_doctors = current_db.users.find({
                'role': 'doctor',
                'is_available': True
            })
            
            for doctor in available_doctors:
                # Check if doctor has current availability
                current_availability = current_db.doctor_availability.find_one({
                    'doctor_id': doctor['user_id'],
                    'day_of_week': current_day,
                    'is_active': True,
                    'start_time': {'$lte': current_time},
                    'end_time': {'$gte': current_time}
                })
                
                if current_availability:
                    stats['available_doctors'] += 1
        
        return jsonify(stats)
        
    except Exception as e:
        logger.error(f"Error getting receptionist stats: {e}")
        return jsonify({'error': 'Failed to load statistics'}), 500
@app.route('/api/doctor/dashboard-stats')
@login_required
@role_required(['doctor'])
def doctor_dashboard_stats():
    """Get doctor-specific dashboard statistics"""
    try:
        current_db = get_db_safe()
        doctor_id = session['user_id']
        
        print(f"📊 Loading dashboard stats for doctor: {doctor_id}")
        
        stats = {
            'today_appointments': 0,
            'total_patients': 0,
            'completed_sessions': 0,
            'pending_followups': 0
        }
        
        if current_db is not None:
            # Today's date range
            today_start = datetime.now(timezone.utc).replace(hour=0, minute=0, second=0, microsecond=0)
            today_end = today_start + timedelta(days=1)
            
            # Today's appointments
            stats['today_appointments'] = current_db.appointments.count_documents({
                'therapist_id': doctor_id,
                'date': {'$gte': today_start, '$lt': today_end},
                'status': {'$in': ['scheduled', 'confirmed', 'in-progress']}
            })
            
            # Total unique patients
            stats['total_patients'] = len(current_db.appointments.distinct('patient_id', {
                'therapist_id': doctor_id
            }))
            
            # Completed sessions
            stats['completed_sessions'] = current_db.appointments.count_documents({
                'therapist_id': doctor_id,
                'status': 'completed'
            })
            
            # Pending follow-ups (scheduled future appointments)
            stats['pending_followups'] = current_db.appointments.count_documents({
                'therapist_id': doctor_id,
                'status': 'scheduled',
                'date': {'$gt': datetime.now(timezone.utc)}
            })
        
        print(f"✅ Dashboard stats loaded for doctor {doctor_id}: {stats}")
        return jsonify(stats)
        
    except Exception as e:
        print(f"❌ Error loading dashboard stats for doctor {session['user_id']}: {e}")
        return jsonify({'error': 'Failed to load dashboard statistics'}), 500

@app.route('/api/doctor/today-schedule')
@login_required
@role_required(['doctor'])
def doctor_today_schedule():
    """Get today's schedule for specific doctor"""
    try:
        current_db = get_db_safe()
        doctor_id = session['user_id']
        
        print(f"📅 Loading today's schedule for doctor: {doctor_id}")
        
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
        
        print(f"✅ Today's schedule loaded for doctor {doctor_id}: {len(appointments)} appointments")
        return jsonify(appointments)
        
    except Exception as e:
        print(f"❌ Error loading today's schedule for doctor {session['user_id']}: {e}")
        return jsonify({'error': 'Failed to load schedule'}), 500

@app.route('/api/doctor/appointments')
@login_required
@role_required(['doctor'])
def doctor_appointments():
    """Get all appointments for specific doctor with filtering"""
    try:
        current_db = get_db_safe()
        doctor_id = session['user_id']
        
        status_filter = request.args.get('status', 'all')
        limit = int(request.args.get('limit', 0))
        
        print(f"📋 Loading appointments for doctor: {doctor_id}, filter: {status_filter}")
        
        # Build query - ensure only this doctor's appointments
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
        
        print(f"✅ Appointments loaded for doctor {doctor_id}: {len(appointments)} appointments")
        return jsonify({'appointments': appointments})
        
    except Exception as e:
        print(f"❌ Error loading appointments for doctor {session['user_id']}: {e}")
        return jsonify({'error': 'Failed to load appointments'}), 500

@app.route('/api/doctor/patients')
@login_required
@role_required(['doctor'])
def doctor_patients():
    """Get all patients for the specific doctor"""
    try:
        current_db = get_db_safe()
        doctor_id = session['user_id']
        
        print(f"👥 Loading patients for doctor: {doctor_id}")
        
        patients = []
        
        if current_db is not None:
            # Get distinct patient IDs from this doctor's appointments
            patient_ids = current_db.appointments.distinct('patient_id', {
                'therapist_id': doctor_id
            })
            
            print(f"🔍 Found {len(patient_ids)} unique patients for doctor {doctor_id}")
            
            # Get patient details
            for patient_id in patient_ids:
                patient = current_db.users.find_one({
                    'user_id': patient_id,
                    'role': 'patient'
                })
                
                if patient:
                    # Get appointment stats for this patient with this doctor
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
        
        print(f"Patients loaded for doctor {doctor_id}: {len(patients)} patients")
        return jsonify(patients)
        
    except Exception as e:
        print(f"Error loading patients for doctor {session['user_id']}: {e}")
        return jsonify({'error': 'Failed to load patients'}), 500

# Add this route to make doctor profiles accessible to all authenticated users
@app.route('/api/doctor-profiles')
@login_required
def get_doctor_profiles():
    """Get all doctor profiles for patients and receptionists"""
    try:
        current_db = get_db_safe()
        
        doctors = []
        
        if current_db is not None:
            doctors_cursor = current_db.users.find({'role': 'doctor'})
            
            for doctor in doctors_cursor:
                # Get availability schedule
                availability = list(current_db.doctor_availability.find({
                    'doctor_id': doctor['user_id'],
                    'is_active': True
                }).sort('day_of_week', 1))
                
                # Format availability for display
                schedule = {}
                for slot in availability:
                    day = slot.get('day_of_week', '').capitalize()
                    schedule[day] = {
                        'start_time': slot.get('start_time'),
                        'end_time': slot.get('end_time'),
                        'max_appointments': slot.get('max_appointments', 3)
                    }
                
                doctor_data = {
                    'user_id': doctor['user_id'],
                    'name': f"Dr. {doctor.get('first_name', '')} {doctor.get('last_name', '')}",
                    'specialization': doctor.get('specialization', 'Therapy Specialist'),
                    'qualifications': doctor.get('qualifications', ''),
                    'experience': doctor.get('experience', 0),
                    'bio': doctor.get('bio', ''),
                    'consultation_fee': doctor.get('consultation_fee', 0),
                    'languages': doctor.get('languages', ''),
                    'therapy_type': doctor.get('therapy_type', 'general'),
                    'is_available': doctor.get('is_available', True),
                    'schedule': schedule,
                    'profile_photo': doctor.get('profile_photo', ''),
                    'contact_email': doctor.get('email', '')
                }
                
                doctors.append(doctor_data)
        
        return jsonify({'doctors': doctors})
        
    except Exception as e:
        logger.error(f"Error getting doctor profiles: {e}")
        return jsonify({'doctors': []})

@app.route('/api/doctor-profiles/complete')
@login_required
@role_required(['patient', 'receptionist', 'admin'])  # Add receptionist
def get_complete_doctor_profiles():
    """Get complete doctor profiles with schedules for doctor profiles page"""
    try:
        current_db = get_db_safe()
        
        doctors = []
        
        if current_db is not None:
            doctors_cursor = current_db.users.find({'role': 'doctor'})
            
            for doctor in doctors_cursor:
                # Get weekly availability schedule
                availability = list(current_db.doctor_availability.find({
                    'doctor_id': doctor['user_id'],
                    'is_active': True
                }).sort('day_of_week', 1))
                
                # Organize schedule by day
                weekly_schedule = {}
                days_order = ['monday', 'tuesday', 'wednesday', 'thursday', 'friday', 'saturday', 'sunday']
                
                for day in days_order:
                    day_slots = [slot for slot in availability if slot.get('day_of_week') == day]
                    if day_slots:
                        weekly_schedule[day.capitalize()] = [{
                            'start_time': slot.get('start_time'),
                            'end_time': slot.get('end_time'),
                            'max_appointments': slot.get('max_appointments', 3)
                        } for slot in day_slots]
                
                # Get today's appointments count
                today_start = datetime.now(timezone.utc).replace(hour=0, minute=0, second=0, microsecond=0)
                today_end = today_start + timedelta(days=1)
                
                today_appointments = current_db.appointments.count_documents({
                    'therapist_id': doctor['user_id'],
                    'date': {'$gte': today_start, '$lt': today_end},
                    'status': {'$in': ['scheduled', 'confirmed', 'in-progress']}
                })
                
                # Check current availability
                is_available_now = check_doctor_availability_now(doctor['user_id'], current_db)
                
                doctor_data = {
                    'user_id': doctor['user_id'],
                    'name': f"Dr. {doctor.get('first_name', '')} {doctor.get('last_name', '')}",
                    'specialization': doctor.get('specialization', 'Therapy Specialist'),
                    'qualifications': doctor.get('qualifications', ''),
                    'experience': doctor.get('experience', 0),
                    'bio': doctor.get('bio', ''),
                    'consultation_fee': doctor.get('consultation_fee', 0),
                    'languages': doctor.get('languages', ''),
                    'therapy_type': doctor.get('therapy_type', 'general'),
                    'email': doctor.get('email', ''),
                    'phone': doctor.get('phone', ''),
                    'is_available': doctor.get('is_available', True),
                    'is_available_now': is_available_now,
                    'weekly_schedule': weekly_schedule,
                    'today_appointments': today_appointments,
                    'profile_photo': doctor.get('profile_photo', '')
                }
                
                doctors.append(doctor_data)
        
        return jsonify({'doctors': doctors})
        
    except Exception as e:
        logger.error(f"Error getting complete doctor profiles: {e}")
        return jsonify({'doctors': []})

@app.route('/api/doctor/<doctor_id>/remind-schedule', methods=['POST'])
@login_required
@role_required(['receptionist', 'admin'])
def remind_doctor_schedule(doctor_id):
    """Send schedule reminder to doctor"""
    try:
        current_db = get_db_safe()
        
        if current_db is None:
            return jsonify({'success': False, 'message': 'Database not available'})
        
        # Get doctor details
        doctor = current_db.users.find_one({'user_id': doctor_id})
        if not doctor:
            return jsonify({'success': False, 'message': 'Doctor not found'})
        
        # Create notification for doctor
        create_notification(
            doctor_id,
            'Schedule Reminder',
            'Receptionist has requested you to review and update your weekly schedule if needed.',
            'warning'
        )
        
        logger.info(f"Schedule reminder sent to doctor {doctor_id}")
        return jsonify({'success': True, 'message': 'Reminder sent successfully'})
        
    except Exception as e:
        logger.error(f"Error sending schedule reminder: {e}")
        return jsonify({'success': False, 'message': 'Failed to send reminder'}), 500

# Enhanced availability management
@app.route('/api/doctor/schedule', methods=['GET', 'POST'])
@login_required
def manage_doctor_schedule():
    """Manage doctor schedule - accessible based on role"""
    try:
        current_db = get_db_safe()
        
        if request.method == 'GET':
            doctor_id = request.args.get('doctor_id')
            
            # If no doctor_id specified and user is doctor, use their own ID
            if not doctor_id and session['role'] == 'doctor':
                doctor_id = session['user_id']
            elif not doctor_id:
                return jsonify({'error': 'Doctor ID required'}), 400
            
            # Get doctor's weekly schedule
            availability = list(current_db.doctor_availability.find({
                'doctor_id': doctor_id,
                'is_active': True
            }).sort('day_of_week', 1))
            
            # Get doctor details
            doctor = current_db.users.find_one({'user_id': doctor_id})
            
            schedule_data = {
                'doctor_id': doctor_id,
                'doctor_name': f"Dr. {doctor.get('first_name', '')} {doctor.get('last_name', '')}" if doctor else 'Unknown Doctor',
                'specialization': doctor.get('specialization', '') if doctor else '',
                'weekly_schedule': {}
            }
            
            # Organize by day
            days_order = ['monday', 'tuesday', 'wednesday', 'thursday', 'friday', 'saturday', 'sunday']
            for day in days_order:
                day_slots = [slot for slot in availability if slot.get('day_of_week') == day]
                schedule_data['weekly_schedule'][day.capitalize()] = day_slots
            
            return jsonify(schedule_data)
            
        elif request.method == 'POST' and session['role'] == 'doctor':
            # Only doctors can update their own schedule
            data = request.get_json()
            doctor_id = session['user_id']
            
            if not data or 'schedule' not in data:
                return jsonify({'success': False, 'message': 'Schedule data required'})
            
            # Deactivate all existing slots
            current_db.doctor_availability.update_many(
                {'doctor_id': doctor_id},
                {'$set': {'is_active': False}}
            )
            
            # Create new slots
            new_slots = []
            for day_schedule in data['schedule']:
                slot_data = {
                    'doctor_id': doctor_id,
                    'day_of_week': day_schedule['day'].lower(),
                    'start_time': day_schedule['start_time'],
                    'end_time': day_schedule['end_time'],
                    'max_appointments': day_schedule.get('max_appointments', 3),
                    'is_active': True,
                    'created_at': datetime.utcnow(),
                    'updated_at': datetime.utcnow()
                }
                new_slots.append(slot_data)
            
            if new_slots:
                current_db.doctor_availability.insert_many(new_slots)
            
            # Notify receptionists
            receptionists = current_db.users.find({'role': 'receptionist'})
            for receptionist in receptionists:
                create_notification(
                    receptionist['user_id'],
                    'Doctor Schedule Updated',
                    f'Dr. {session.get("first_name")} {session.get("last_name")} has updated their weekly schedule.',
                    'info'
                )
            
            logger.info(f"Doctor {doctor_id} updated schedule")
            return jsonify({'success': True, 'message': 'Schedule updated successfully'})
        
        return jsonify({'success': False, 'message': 'Unauthorized'}), 403
        
    except Exception as e:
        logger.error(f"Error managing doctor schedule: {e}")
        return jsonify({'success': False, 'message': 'Failed to manage schedule'}), 500


def check_doctor_availability_now(doctor_id, current_db):
    """Check if doctor is available at current moment"""
    try:
        current_day = datetime.now(timezone.utc).strftime('%A').lower()
        current_time = datetime.now(timezone.utc).strftime('%H:%M')
        
        current_slot = current_db.doctor_availability.find_one({
            'doctor_id': doctor_id,
            'day_of_week': current_day,
            'is_active': True,
            'start_time': {'$lte': current_time},
            'end_time': {'$gte': current_time}
        })
        
        return current_slot is not None
    except Exception as e:
        logger.error(f"Error checking doctor availability: {e}")
        return False
    
@app.route('/api/doctor-schedules')
@login_required
@role_required(['receptionist', 'admin'])
def get_doctor_schedules():
    """Get all doctor schedules for receptionist dashboard"""
    try:
        current_db = get_db_safe()
        
        doctors = []
        
        if current_db is not None:
            doctors_cursor = current_db.users.find({'role': 'doctor'})
            
            for doctor in doctors_cursor:
                # Get weekly schedule
                availability = list(current_db.doctor_availability.find({
                    'doctor_id': doctor['user_id'],
                    'is_active': True
                }))
                
                # Organize by day
                weekly_schedule = {}
                days_order = ['monday', 'tuesday', 'wednesday', 'thursday', 'friday', 'saturday', 'sunday']
                for day in days_order:
                    day_slots = [slot for slot in availability if slot.get('day_of_week') == day]
                    weekly_schedule[day.capitalize()] = day_slots
                
                doctor_data = {
                    'user_id': doctor['user_id'],
                    'name': f"Dr. {doctor.get('first_name', '')} {doctor.get('last_name', '')}",
                    'specialization': doctor.get('specialization', 'Therapy Specialist'),
                    'email': doctor.get('email'),
                    'phone': doctor.get('phone', ''),
                    'is_available': doctor.get('is_available', True),
                    'weekly_schedule': weekly_schedule
                }
                
                doctors.append(doctor_data)
        
        return jsonify({'doctors': doctors})
        
    except Exception as e:
        logger.error(f"Error getting doctor schedules: {e}")
        return jsonify({'doctors': []})

@app.route('/api/receptionist/doctor-availability')
@login_required
@role_required(['receptionist', 'admin'])
def get_receptionist_doctor_availability():
    """Get comprehensive doctor availability data for receptionist"""
    try:
        current_db = get_db_safe()
        
        doctors = []
        
        if current_db is not None:
            # Get all doctors
            doctors_cursor = current_db.users.find({'role': 'doctor'})
            
            for doctor in doctors_cursor:
                doctor_id = doctor['user_id']
                
                # Get doctor's complete profile including schedule
                doctor_profile = current_db.users.find_one({'user_id': doctor_id})
                
                # Get weekly availability schedule
                availability = list(current_db.doctor_availability.find({
                    'doctor_id': doctor_id,
                    'is_active': True
                }).sort('day_of_week', 1))
                
                # Organize weekly schedule
                weekly_schedule = {}
                days_order = ['monday', 'tuesday', 'wednesday', 'thursday', 'friday', 'saturday', 'sunday']
                for day in days_order:
                    day_slots = [slot for slot in availability if slot.get('day_of_week') == day]
                    if day_slots:
                        weekly_schedule[day.capitalize()] = [{
                            'start_time': slot.get('start_time'),
                            'end_time': slot.get('end_time'),
                            'max_appointments': slot.get('max_appointments', 3)
                        } for slot in day_slots]
                
                # Get today's day and availability
                today = datetime.now(timezone.utc).strftime('%A').lower()
                today_availability = next((slot for slot in availability if slot.get('day_of_week') == today), None)
                
                # Get today's appointments
                today_start = datetime.now(timezone.utc).replace(hour=0, minute=0, second=0, microsecond=0)
                today_end = today_start + timedelta(days=1)
                
                today_appointments = current_db.appointments.count_documents({
                    'therapist_id': doctor_id,
                    'date': {'$gte': today_start, '$lt': today_end},
                    'status': {'$in': ['scheduled', 'confirmed', 'in-progress']}
                })
                
                # Check current availability
                is_available_now = False
                if today_availability:
                    current_time = datetime.now(timezone.utc).strftime('%H:%M')
                    if (today_availability['start_time'] <= current_time <= today_availability['end_time'] and 
                        doctor_profile.get('is_available', True)):
                        is_available_now = True
                
                # Build doctor data
                doctor_data = {
                    'user_id': doctor_id,
                    'name': f"Dr. {doctor.get('first_name', '')} {doctor.get('last_name', '')}",
                    'first_name': doctor.get('first_name', ''),
                    'last_name': doctor.get('last_name', ''),
                    'specialization': doctor.get('specialization', 'Therapy Specialist'),
                    'email': doctor.get('email', ''),
                    'phone': doctor.get('phone', ''),
                    'therapy_type': doctor.get('therapy_type', 'general'),
                    'is_available': doctor.get('is_available', True),
                    'is_available_now': is_available_now,
                    'today_availability': today_availability,
                    'today_appointments': today_appointments,
                    'weekly_schedule': weekly_schedule,
                    'next_available': calculate_next_available_slot(doctor_id, current_db),
                    'consultation_fee': doctor.get('consultation_fee', 0),
                    'experience': doctor.get('experience', 0),
                    'qualifications': doctor.get('qualifications', ''),
                    'status_updated_at': doctor.get('status_updated_at')
                }
                
                doctors.append(doctor_data)
        
        return jsonify({
            'success': True,
            'doctors': doctors,
            'last_updated': datetime.utcnow().isoformat()
        })
        
    except Exception as e:
        logger.error(f"Error getting doctor availability: {e}")
        return jsonify({
            'success': False,
            'doctors': [],
            'error': 'Failed to load doctor availability'
        }), 500

@app.route('/api/doctor/<doctor_id>/complete-schedule')
@login_required
@role_required(['receptionist', 'admin'])
def get_doctor_complete_schedule(doctor_id):
    """Get complete schedule for a specific doctor"""
    try:
        current_db = get_db_safe()
        
        if current_db is None:
            return jsonify({'error': 'Database not available'}), 500
        
        # Get doctor details
        doctor = current_db.users.find_one({'user_id': doctor_id})
        if not doctor:
            return jsonify({'error': 'Doctor not found'}), 404
        
        # Get weekly availability
        availability = list(current_db.doctor_availability.find({
            'doctor_id': doctor_id,
            'is_active': True
        }).sort('day_of_week', 1))
        
        # Get upcoming appointments (next 7 days)
        start_date = datetime.now(timezone.utc).replace(hour=0, minute=0, second=0, microsecond=0)
        end_date = start_date + timedelta(days=7)
        
        upcoming_appointments = list(current_db.appointments.find({
            'therapist_id': doctor_id,
            'date': {'$gte': start_date, '$lt': end_date},
            'status': {'$in': ['scheduled', 'confirmed']}
        }).sort('date', 1))
        
        # Organize schedule by day
        weekly_schedule = {}
        days_order = ['monday', 'tuesday', 'wednesday', 'thursday', 'friday', 'saturday', 'sunday']
        
        for day in days_order:
            day_slots = [slot for slot in availability if slot.get('day_of_week') == day]
            day_appointments = [appt for appt in upcoming_appointments 
                              if appt.get('date').strftime('%A').lower() == day]
            
            weekly_schedule[day.capitalize()] = {
                'availability': [{
                    'start_time': slot.get('start_time'),
                    'end_time': slot.get('end_time'),
                    'max_appointments': slot.get('max_appointments', 3)
                } for slot in day_slots],
                'appointments': [{
                    'appointment_id': appt.get('appointment_id'),
                    'patient_name': appt.get('patient_name', 'Unknown Patient'),
                    'time': appt.get('date').strftime('%H:%M'),
                    'therapy_type': appt.get('therapy_type', '').title(),
                    'status': appt.get('status', 'scheduled')
                } for appt in day_appointments]
            }
        
        schedule_data = {
            'doctor_id': doctor_id,
            'doctor_name': f"Dr. {doctor.get('first_name', '')} {doctor.get('last_name', '')}",
            'specialization': doctor.get('specialization', ''),
            'weekly_schedule': weekly_schedule,
            'is_available': doctor.get('is_available', True),
            'total_upcoming_appointments': len(upcoming_appointments)
        }
        
        return jsonify(schedule_data)
        
    except Exception as e:
        logger.error(f"Error getting doctor schedule: {e}")
        return jsonify({'error': 'Failed to load schedule'}), 500
def format_relative_time(timestamp):
    """Format timestamp as relative time"""
    if not timestamp:
        return "Never"
    
    now = datetime.now(timezone.utc)
    diff = now - timestamp
    
    if diff.days > 0:
        return f"{diff.days} day{'s' if diff.days > 1 else ''} ago"
    elif diff.seconds >= 3600:
        hours = diff.seconds // 3600
        return f"{hours} hour{'s' if hours > 1 else ''} ago"
    elif diff.seconds >= 60:
        minutes = diff.seconds // 60
        return f"{minutes} minute{'s' if minutes > 1 else ''} ago"
    else:
        return "Just now"
@app.route('/api/receptionist/available-doctors-now')
@login_required
@role_required(['receptionist', 'admin'])
def get_available_doctors_now():
    """Get doctors who are currently available"""
    try:
        current_db = get_db_safe()
        
        available_doctors = []
        
        if current_db is not None:
            # Get available doctors
            doctors_cursor = current_db.users.find({
                'role': 'doctor',
                'is_available': True
            })
            
            for doctor in doctors_cursor:
                # Check if doctor has availability for current day and time
                current_day = datetime.now(timezone.utc).strftime('%A').lower()
                current_time = datetime.now(timezone.utc).strftime('%H:%M')
                
                current_availability = current_db.doctor_availability.find_one({
                    'doctor_id': doctor['user_id'],
                    'day_of_week': current_day,
                    'is_active': True,
                    'start_time': {'$lte': current_time},
                    'end_time': {'$gte': current_time}
                })
                
                if current_availability:
                    doctor_data = {
                        'user_id': doctor['user_id'],
                        'name': f"Dr. {doctor.get('first_name', '')} {doctor.get('last_name', '')}",
                        'specialization': doctor.get('specialization', 'Therapy Specialist'),
                        'email': doctor.get('email')
                    }
                    
                    available_doctors.append(doctor_data)
        
        return jsonify({'doctors': available_doctors})
        
    except Exception as e:
        logger.error(f"Error getting available doctors: {e}")
        return jsonify({'doctors': []})
        
    except Exception as e:
        logger.error(f"Error getting available doctors: {e}")
        return jsonify({'doctors': []})
    
def calculate_next_available_slot(doctor_id, current_db):
    """Calculate next available time slot for a doctor"""
    try:
        if current_db is None:
            return "Not available"
            
        # Get current time and day
        now = datetime.now()
        current_day = now.strftime('%A').lower()
        current_time = now.strftime('%H:%M')
        
        # Get doctor's availability
        availability = list(current_db.doctor_availability.find({
            'doctor_id': doctor_id,
            'is_active': True
        }).sort('day_of_week', 1))
        
        if not availability:
            return "Not scheduled"
        
        # Days of week in order starting from today
        days_order = ['monday', 'tuesday', 'wednesday', 'thursday', 'friday', 'saturday', 'sunday']
        
        # Find current day index
        current_day_index = days_order.index(current_day) if current_day in days_order else 0
        
        # Check today first
        today_availability = next((slot for slot in availability if slot['day_of_week'] == current_day), None)
        
        if today_availability:
            # Check if available later today
            if current_time < today_availability['end_time']:
                if current_time < today_availability['start_time']:
                    return f"Today at {today_availability['start_time']}"
                else:
                    return "Available now"
        
        # Check next 7 days
        for i in range(1, 8):
            check_day_index = (current_day_index + i) % len(days_order)
            check_day = days_order[check_day_index]
            
            day_availability = next((slot for slot in availability if slot['day_of_week'] == check_day), None)
            
            if day_availability:
                day_name = check_day.capitalize()
                return f"{day_name} at {day_availability['start_time']}"
        
        return "Not available this week"
        
    except Exception as e:
        logger.error(f"Error calculating next available slot: {e}")
        return "Not available"

def is_doctor_available_now(doctor_id, current_db):
    """Check if doctor is available at current moment"""
    try:
        current_day = datetime.now().strftime("%A").lower()
        current_time = datetime.now()
        
        # Get today's availability
        today_availability = current_db.doctor_availability.find_one({
            "doctor_id": doctor_id,
            "day_of_week": current_day,
            "is_active": True
        })
        
        if not today_availability:
            return False
            
        # Parse time strings to time objects for comparison
        start_time_str = today_availability.get("start_time", "00:00")
        end_time_str = today_availability.get("end_time", "00:00")
        
        # Convert to time objects
        start_time = datetime.strptime(start_time_str, "%H:%M").time()
        end_time = datetime.strptime(end_time_str, "%H:%M").time()
        current_time_only = current_time.time()
        
        return start_time <= current_time_only <= end_time
        
    except Exception as e:
        logger.error(f"Error checking doctor availability: {e}")
        return False        

@app.route('/api/debug/doctor-availability')
@login_required
@role_required(['receptionist', 'admin'])
def debug_doctor_availability():
    """Debug endpoint to check doctor availability data"""
    try:
        current_db = get_db_safe()
        if current_db is None:
            return jsonify({"error": "Database not connected"})
        
        # Check collections
        collections = current_db.list_collection_names()
        
        # Check doctors
        doctors = list(current_db.users.find({"role": "doctor"}))
        doctor_ids = [d["user_id"] for d in doctors]
        
        # Check availability data
        availability_data = {}
        for doctor_id in doctor_ids:
            availability = list(current_db.doctor_availability.find({"doctor_id": doctor_id}))
            availability_data[doctor_id] = {
                "slots_count": len(availability),
                "slots": availability
            }
        
        return jsonify({
            "collections": collections,
            "total_doctors": len(doctors),
            "doctor_ids": doctor_ids,
            "availability_data": availability_data,
            "doctor_availability_collection_exists": "doctor_availability" in collections
        })
        
    except Exception as e:
        return jsonify({"error": str(e), "traceback": traceback.format_exc()})

@app.route('/receptionist/doctor-availability')
@login_required
@role_required(['receptionist', 'admin'])
def receptionist_doctor_availability():
    """Doctor availability management page for receptionists"""
    stats = get_dashboard_stats('receptionist', session['user_id'])
    return render_template('receptionist_doctor_availability.html', user=session, stats=stats)

@app.route('/debug/doctor-availability')
def debug_doctor_availability_page():  # Changed function name
    """Debug route to check doctor availability functionality"""
    try:
        current_db = get_db_safe()
        if current_db is None:
            return jsonify({'error': 'Database not connected'})
        
        # Test the doctor availability query
        doctors = list(current_db.users.find({'role': 'doctor'}))
        
        # Test doctor_availability collection
        availability_count = current_db.doctor_availability.count_documents({})
        
        return jsonify({
            'database_connected': True,
            'total_doctors': len(doctors),
            'availability_records': availability_count,
            'doctors': [{'user_id': d.get('user_id'), 'name': d.get('first_name') + ' ' + d.get('last_name')} for d in doctors]
        })
        
    except Exception as e:
        return jsonify({'error': str(e), 'traceback': traceback.format_exc()})

# app.py में security checks add करें

@app.route('/api/doctor/appointments/<appointment_id>')
@login_required
@role_required(['doctor'])
def doctor_appointment_detail(appointment_id):
    """Get detailed appointment information with doctor-specific security"""
    try:
        current_db = get_db_safe()
        doctor_id = session['user_id']
        
        print(f"👀 Loading appointment details: {appointment_id} for doctor: {doctor_id}")
        
        if current_db is None:
            return jsonify({'error': 'Database not available'}), 500
        
        # Get appointment details - with doctor-specific security check
        appointment = current_db.appointments.find_one({
            'appointment_id': appointment_id,
            'therapist_id': doctor_id  # Security: Only this doctor's appointments
        })
        
        if not appointment:
            print(f" Appointment {appointment_id} not found or unauthorized for doctor {doctor_id}")
            return jsonify({'error': 'Appointment not found or unauthorized'}), 404
        
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
            'doctor_name': f"Dr. {doctor.get('first_name', '')} {doctor.get('last_name', '')}" if doctor else 'Unknown Doctor',
            'therapist_id': appointment.get('therapist_id')  # Include for frontend verification
        }
        
        print(f"Appointment details loaded for doctor {doctor_id}")
        return jsonify(appointment_data)
        
    except Exception as e:
        print(f"Error loading appointment details for doctor {session['user_id']}: {e}")
        return jsonify({'error': 'Failed to load appointment details'}), 500

@app.route('/api/doctor/patients/<patient_id>')
@login_required
@role_required(['doctor'])
def doctor_patient_detail(patient_id):
    """Get detailed patient information with doctor-specific security"""
    try:
        current_db = get_db_safe()
        doctor_id = session['user_id']
        
        print(f"👤 Loading patient details: {patient_id} for doctor: {doctor_id}")
        
        if current_db is None:
            return jsonify({'error': 'Database not available'}), 500
        
        # Security: Check if this patient has appointments with this doctor
        has_appointments = current_db.appointments.find_one({
            'patient_id': patient_id,
            'therapist_id': doctor_id
        })
        
        if not has_appointments:
            print(f"❌ Patient {patient_id} not associated with doctor {doctor_id}")
            return jsonify({'error': 'Patient not found or unauthorized'}), 404
        
        # Get patient details
        patient = current_db.users.find_one({
            'user_id': patient_id,
            'role': 'patient'
        })
        
        if not patient:
            return jsonify({'error': 'Patient not found'}), 404
        
        # Get appointment history with this doctor only
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
            'last_visit': appointments[0].get('date').isoformat() if appointments else None,
            'appointment_history': [{
                'appointment_id': appt.get('appointment_id'),
                'date': appt.get('date').isoformat() if appt.get('date') else None,
                'therapy_type': appt.get('therapy_type', ''),
                'status': appt.get('status', ''),
                'notes': appt.get('notes', '')
            } for appt in appointments[:10]]  # Last 10 appointments
        }
        
        print(f"✅ Patient details loaded for doctor {doctor_id}")
        return jsonify(patient_data)
        
    except Exception as e:
        print(f"❌ Error loading patient details for doctor {session['user_id']}: {e}")
        return jsonify({'error': 'Failed to load patient details'}), 500

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


# Enhanced doctor profile update endpoint with schedule management
@app.route('/api/doctor/profile', methods=['POST'])
@login_required
@role_required(['doctor'])
def update_doctor_profile_complete():
    """Complete doctor profile update including schedule"""
    try:
        current_db = get_db_safe()
        doctor_id = session['user_id']
        data = request.get_json()
        
        if not data:
            return jsonify({'success': False, 'message': 'No data provided'})
        
        # Update basic profile information
        update_data = {}
        profile_fields = [
            'specialization', 'qualifications', 'experience', 'bio',
            'consultation_fee', 'languages', 'therapy_type', 'phone'
        ]
        
        for field in profile_fields:
            if field in data:
                update_data[field] = data[field]
        
        if update_data:
            update_data['updated_at'] = datetime.utcnow()
            
            result = current_db.users.update_one(
                {'user_id': doctor_id},
                {'$set': update_data}
            )
            
            if result.modified_count > 0:
                # Update session data
                if 'specialization' in update_data:
                    session['specialization'] = update_data['specialization']
                if 'therapy_type' in update_data:
                    session['therapy_type'] = update_data['therapy_type']
        
        # Handle weekly schedule if provided
        if 'weekly_schedule' in data:
            # Deactivate all existing slots
            current_db.doctor_availability.update_many(
                {'doctor_id': doctor_id},
                {'$set': {'is_active': False}}
            )
            
            # Create new schedule slots
            new_slots = []
            for day, slots in data['weekly_schedule'].items():
                if slots and len(slots) > 0:
                    for slot in slots:
                        if slot.get('start_time') and slot.get('end_time'):
                            slot_data = {
                                'doctor_id': doctor_id,
                                'day_of_week': day.lower(),
                                'start_time': slot['start_time'],
                                'end_time': slot['end_time'],
                                'max_appointments': slot.get('max_appointments', 3),
                                'is_active': True,
                                'created_at': datetime.utcnow(),
                                'updated_at': datetime.utcnow()
                            }
                            new_slots.append(slot_data)
            
            if new_slots:
                current_db.doctor_availability.insert_many(new_slots)
        
        # Notify all receptionists about profile update
        receptionists = current_db.users.find({'role': 'receptionist'})
        for receptionist in receptionists:
            create_notification(
                receptionist['user_id'],
                'Doctor Profile Updated',
                f'Dr. {session.get("first_name")} {session.get("last_name")} has updated their profile and schedule.',
                'info'
            )
        
        logger.info(f"Doctor {doctor_id} updated complete profile with schedule")
        return jsonify({'success': True, 'message': 'Profile and schedule updated successfully'})
        
    except Exception as e:
        logger.error(f"Error updating doctor profile: {e}")
        return jsonify({'success': False, 'message': 'Failed to update profile'}), 500
@app.route('/doctor-profiles')
@login_required
@role_required(['patient', 'receptionist', 'admin'])  # Add receptionist and admin
def doctor_profiles():
    """Doctor profiles page for patients and receptionists"""
    return render_template('doctor_profiles.html')

@app.route('/api/doctors/available-slots/<doctor_id>')
@login_required
@role_required(['patient'])
def get_doctor_available_slots(doctor_id):
    """Get available time slots for a specific doctor for patient booking"""
    try:
        current_db = get_db_safe()
        
        if current_db is None:
            return jsonify({'error': 'Database not available'}), 500
        
        # Get doctor details
        doctor = current_db.users.find_one({
            'user_id': doctor_id,
            'role': 'doctor'
        })
        
        if not doctor:
            return jsonify({'error': 'Doctor not found'}), 404
        
        # Get doctor's weekly schedule
        availability = list(current_db.doctor_availability.find({
            'doctor_id': doctor_id,
            'is_active': True
        }).sort('day_of_week', 1))
        
        # Get booked appointments for the next 7 days
        start_date = datetime.now(timezone.utc).replace(hour=0, minute=0, second=0, microsecond=0)
        end_date = start_date + timedelta(days=7)
        
        booked_appointments = list(current_db.appointments.find({
            'therapist_id': doctor_id,
            'date': {'$gte': start_date, '$lt': end_date},
            'status': {'$in': ['scheduled', 'confirmed']}
        }))
        
        # Generate available slots for next 7 days
        available_slots = {}
        
        for day_offset in range(7):
            current_date = start_date + timedelta(days=day_offset)
            day_name = current_date.strftime('%A').lower()
            
            # Find availability for this day
            day_availability = [slot for slot in availability if slot.get('day_of_week') == day_name]
            
            if day_availability:
                available_slots[current_date.strftime('%Y-%m-%d')] = []
                
                for slot in day_availability:
                    # Generate 30-minute slots within availability hours
                    start_time = datetime.strptime(slot['start_time'], '%H:%M')
                    end_time = datetime.strptime(slot['end_time'], '%H:%M')
                    
                    current_slot = start_time
                    while current_slot < end_time:
                        slot_time = current_slot.strftime('%H:%M')
                        slot_datetime = current_date.replace(
                            hour=current_slot.hour,
                            minute=current_slot.minute
                        )
                        
                        # Check if slot is not booked
                        is_booked = any(
                            appt['date'].strftime('%Y-%m-%d %H:%M') == slot_datetime.strftime('%Y-%m-%d %H:%M')
                            for appt in booked_appointments
                        )
                        
                        if not is_booked:
                            available_slots[current_date.strftime('%Y-%m-%d')].append({
                                'time': slot_time,
                                'datetime': slot_datetime.isoformat()
                            })
                        
                        current_slot += timedelta(minutes=30)
        
        doctor_info = {
            'doctor_id': doctor['user_id'],
            'name': f"Dr. {doctor.get('first_name', '')} {doctor.get('last_name', '')}",
            'specialization': doctor.get('specialization', ''),
            'consultation_fee': doctor.get('consultation_fee', 0),
            'weekly_schedule': {
                day.capitalize(): [{
                    'start_time': slot.get('start_time'),
                    'end_time': slot.get('end_time')
                } for slot in availability if slot.get('day_of_week') == day]
                for day in ['monday', 'tuesday', 'wednesday', 'thursday', 'friday', 'saturday', 'sunday']
                if any(slot.get('day_of_week') == day for slot in availability)
            }
        }
        
        return jsonify({
            'doctor': doctor_info,
            'available_slots': available_slots
        })
        
    except Exception as e:
        logger.error(f"Error getting available slots: {e}")
        return jsonify({'error': 'Failed to load available slots'}), 500


@app.route('/api/get-doctor-availability', methods=['GET'])
@login_required
@role_required(['doctor'])
def get_doctor_availability():
    doctor_id = session['user_id']

    current_db = get_db_safe()
    if current_db is None:
        return jsonify({'success': False, 'error': 'Database not connected'}), 500

    availability = list(current_db.doctor_availability.find({'doctor_id': doctor_id}))

    for item in availability:
        item['_id'] = str(item['_id'])

    return jsonify({'success': True, 'availability': availability})


@app.route('/api/receptionist/doctor-availability-data')
@login_required
@role_required(['receptionist'])
def get_doctor_availability_data():
    """Get comprehensive doctor availability data for receptionist - FIXED VERSION"""
    try:
        current_db = get_db_safe()
        if current_db is None:
            logger.error("Database not available for doctor availability data")
            return jsonify({
                "success": False, 
                "error": "Database not available",
                "doctors": []
            }), 500

        logger.info("Fetching doctor availability data...")

        # Get all doctors
        doctors = list(current_db.users.find({"role": "doctor"}))
        logger.info(f"Found {len(doctors)} doctors")
        
        output = []
        
        for doctor in doctors:
            try:
                doctor_id = doctor["user_id"]
                
                # Get doctor's availability
                availability = list(current_db.doctor_availability.find({
                    "doctor_id": doctor_id, 
                    "is_active": True
                }))
                
                logger.info(f"Doctor {doctor_id} has {len(availability)} availability slots")
                
                # Get today's day name
                today = datetime.now().strftime("%A").lower()
                today_availability = None
                
                # Find today's availability
                for slot in availability:
                    if slot.get('day_of_week') == today:
                        today_availability = {
                            'start_time': slot.get('start_time'),
                            'end_time': slot.get('end_time'),
                            'max_appointments': slot.get('max_appointments', 3)
                        }
                        break
                
                # Check current availability
                is_available_now = is_doctor_available_now(doctor_id, current_db)
                
                # Count today's appointments
                today_start = datetime.now().replace(hour=0, minute=0, second=0, microsecond=0)
                today_end = today_start + timedelta(days=1)
                
                todays_appointments = current_db.appointments.count_documents({
                    "therapist_id": doctor_id,
                    "date": {"$gte": today_start, "$lt": today_end},
                    "status": {"$in": ["scheduled", "confirmed", "in-progress"]}
                })
                
                # Organize weekly schedule
                weekly_schedule = {}
                days_order = ['monday', 'tuesday', 'wednesday', 'thursday', 'friday', 'saturday', 'sunday']
                
                for day in days_order:
                    day_slots = [slot for slot in availability if slot.get('day_of_week') == day]
                    if day_slots:
                        weekly_schedule[day.capitalize()] = [{
                            'start_time': slot.get('start_time'),
                            'end_time': slot.get('end_time'),
                            'max_appointments': slot.get('max_appointments', 3)
                        } for slot in day_slots]
                
                # Calculate next available slot
                next_available = calculate_next_available_slot(doctor_id, current_db)
                
                # Convert ObjectId to string for JSON serialization
                status_updated_at = doctor.get("status_updated_at")
                if status_updated_at:
                    if isinstance(status_updated_at, datetime):
                        status_updated_at = status_updated_at.isoformat()
                    else:
                        status_updated_at = str(status_updated_at)
                
                doctor_data = {
                    "user_id": doctor_id,
                    "name": f"Dr. {doctor.get('first_name', '')} {doctor.get('last_name', '')}",
                    "therapy_type": doctor.get("therapy_type", "General Therapy"),
                    "specialization": doctor.get("specialization", "Therapy Specialist"),
                    "experience": doctor.get("experience", 0),
                    "consultation_fee": doctor.get("consultation_fee", 0),
                    "phone": doctor.get("phone", ""),
                    "email": doctor.get("email", ""),
                    "is_available_now": is_available_now,
                    "is_available": doctor.get("is_available", True),
                    "status_updated_at": status_updated_at,
                    "today_appointments": todays_appointments,
                    "today_availability": today_availability,
                    "weekly_schedule": weekly_schedule,
                    "next_available": next_available
                }
                
                output.append(doctor_data)
                
            except Exception as doctor_error:
                logger.error(f"Error processing doctor {doctor.get('user_id', 'unknown')}: {doctor_error}")
                continue  # Continue with next doctor even if one fails

        logger.info(f"Successfully processed {len(output)} doctors")
        return jsonify({
            "success": True, 
            "doctors": output,
            "last_updated": datetime.utcnow().isoformat(),
            "total_doctors": len(output)
        })

    except Exception as e:
        logger.error(f"Critical error in get_doctor_availability_data: {e}")
        logger.error(traceback.format_exc())  # Add detailed traceback
        return jsonify({
            "success": False, 
            "error": "Failed to load doctor availability data",
            "doctors": [],
            "debug_info": str(e)
        }), 500
@app.route('/api/debug/doctor-availability-check')
@login_required
@role_required(['receptionist'])
def debug_doctor_availability_check():

    """Debug endpoint to check doctor availability data"""
    try:
        current_db = get_db_safe()
        if current_db is None:
            return jsonify({"error": "Database not connected"})
        
        # Check collections
        collections = current_db.list_collection_names()
        
        # Check doctors
        doctors = list(current_db.users.find({"role": "doctor"}))
        doctor_ids = [d["user_id"] for d in doctors]
        
        # Check availability data
        availability_data = {}
        for doctor_id in doctor_ids:
            availability = list(current_db.doctor_availability.find({"doctor_id": doctor_id}))
            availability_data[doctor_id] = {
                "slots_count": len(availability),
                "slots": availability
            }
        
        return jsonify({
            "collections": collections,
            "total_doctors": len(doctors),
            "doctor_ids": doctor_ids,
            "availability_data": availability_data,
            "doctor_availability_collection_exists": "doctor_availability" in collections
        })
        
    except Exception as e:
        return jsonify({"error": str(e), "traceback": traceback.format_exc()})
@app.route('/api/receptionist/doctors-management')
@login_required
@role_required(['receptionist', 'admin'])
def get_doctors_management_data():
    """Get complete doctor management data for receptionist"""
    try:
        current_db = get_db_safe()
        
        doctors = []
        
        if current_db is not None:
            doctors_cursor = current_db.users.find({'role': 'doctor'})
            
            for doctor in doctors_cursor:
                # Get weekly schedule
                availability = list(current_db.doctor_availability.find({
                    'doctor_id': doctor['user_id'],
                    'is_active': True
                }).sort('day_of_week', 1))
                
                # Get today's appointments
                today_start = datetime.now(timezone.utc).replace(hour=0, minute=0, second=0, microsecond=0)
                today_end = today_start + timedelta(days=1)
                
                today_appointments = list(current_db.appointments.find({
                    'therapist_id': doctor['user_id'],
                    'date': {'$gte': today_start, '$lt': today_end}
                }).sort('date', 1))
                
                # Get appointment statistics
                total_appointments = current_db.appointments.count_documents({
                    'therapist_id': doctor['user_id']
                })
                
                completed_appointments = current_db.appointments.count_documents({
                    'therapist_id': doctor['user_id'],
                    'status': 'completed'
                })
                
                # Organize weekly schedule
                weekly_schedule = {}
                for day in ['monday', 'tuesday', 'wednesday', 'thursday', 'friday', 'saturday', 'sunday']:
                    day_slots = [slot for slot in availability if slot.get('day_of_week') == day]
                    weekly_schedule[day.capitalize()] = day_slots
                
                doctor_data = {
                    'user_id': doctor['user_id'],
                    'name': f"Dr. {doctor.get('first_name', '')} {doctor.get('last_name', '')}",
                    'specialization': doctor.get('specialization', 'Therapy Specialist'),
                    'email': doctor.get('email'),
                    'phone': doctor.get('phone', ''),
                    'therapy_type': doctor.get('therapy_type', 'general'),
                    'is_available': doctor.get('is_available', True),
                    'consultation_fee': doctor.get('consultation_fee', 0),
                    'experience': doctor.get('experience', 0),
                    'qualifications': doctor.get('qualifications', ''),
                    'weekly_schedule': weekly_schedule,
                    'today_appointments': [{
                        'appointment_id': appt.get('appointment_id'),
                        'patient_name': appt.get('patient_name', 'Unknown'),
                        'time': appt.get('date').strftime('%H:%M') if appt.get('date') else 'N/A',
                        'therapy_type': appt.get('therapy_type', '').title(),
                        'status': appt.get('status', 'scheduled')
                    } for appt in today_appointments],
                    'stats': {
                        'total_appointments': total_appointments,
                        'completed_appointments': completed_appointments,
                        'today_count': len(today_appointments)
                    },
                    'next_available': calculate_next_available_slot(doctor['user_id'], current_db)
                }
                
                doctors.append(doctor_data)
        
        return jsonify({'doctors': doctors})
        
    except Exception as e:
        logger.error(f"Error getting doctors management data: {e}")
        return jsonify({'doctors': []})
    
@app.route('/api/doctor/complete-profile', methods=['GET', 'POST'])
@login_required
@role_required(['doctor'])
def doctor_complete_profile():
    """Get or update complete doctor profile with schedule"""
    try:
        current_db = get_db_safe()
        doctor_id = session['user_id']
        
        if request.method == 'GET':
            # Get doctor profile
            doctor = current_db.users.find_one({'user_id': doctor_id})
            if not doctor:
                return jsonify({'error': 'Doctor not found'}), 404
            
            # Get weekly availability schedule
            availability = list(current_db.doctor_availability.find({
                'doctor_id': doctor_id,
                'is_active': True
            }))
            
            # Organize schedule by day
            weekly_schedule = {}
            for slot in availability:
                day = slot.get('day_of_week', '').capitalize()
                if day not in weekly_schedule:
                    weekly_schedule[day] = []
                
                weekly_schedule[day].append({
                    'start_time': slot.get('start_time'),
                    'end_time': slot.get('end_time'),
                    'max_appointments': slot.get('max_appointments', 3)
                })
            
            profile_data = {
                'user_id': doctor['user_id'],
                'name': f"Dr. {doctor.get('first_name', '')} {doctor.get('last_name', '')}",
                'first_name': doctor.get('first_name'),
                'last_name': doctor.get('last_name'),
                'email': doctor.get('email'),
                'phone': doctor.get('phone', ''),
                'specialization': doctor.get('specialization', ''),
                'qualifications': doctor.get('qualifications', ''),
                'experience': doctor.get('experience', 0),
                'bio': doctor.get('bio', ''),
                'consultation_fee': doctor.get('consultation_fee', 0),
                'languages': doctor.get('languages', ''),
                'therapy_type': doctor.get('therapy_type', 'general'),
                'is_available': doctor.get('is_available', True),
                'weekly_schedule': weekly_schedule
            }
            
            return jsonify(profile_data)
            
        elif request.method == 'POST':
            # Update doctor profile and schedule
            data = request.get_json()
            
            # Update basic profile information
            update_data = {}
            profile_fields = [
                'specialization', 'qualifications', 'experience', 'bio',
                'consultation_fee', 'languages', 'therapy_type', 'phone'
            ]
            
            for field in profile_fields:
                if field in data:
                    update_data[field] = data[field]
            
            if update_data:
                update_data['updated_at'] = datetime.utcnow()
                current_db.users.update_one(
                    {'user_id': doctor_id},
                    {'$set': update_data}
                )
            
            # Handle weekly schedule if provided
            if 'weekly_schedule' in data:
                # Deactivate all existing slots
                current_db.doctor_availability.update_many(
                    {'doctor_id': doctor_id},
                    {'$set': {'is_active': False}}
                )
                
                # Create new schedule slots
                new_slots = []
                for day, slots in data['weekly_schedule'].items():
                    if slots and len(slots) > 0:
                        for slot in slots:
                            if slot.get('start_time') and slot.get('end_time'):
                                slot_data = {
                                    'doctor_id': doctor_id,
                                    'day_of_week': day.lower(),
                                    'start_time': slot['start_time'],
                                    'end_time': slot['end_time'],
                                    'max_appointments': slot.get('max_appointments', 3),
                                    'is_active': True,
                                    'created_at': datetime.utcnow(),
                                    'updated_at': datetime.utcnow()
                                }
                                new_slots.append(slot_data)
                
                if new_slots:
                    current_db.doctor_availability.insert_many(new_slots)
            
            # Notify receptionists
            receptionists = current_db.users.find({'role': 'receptionist'})
            for receptionist in receptionists:
                create_notification(
                    receptionist['user_id'],
                    'Doctor Profile Updated',
                    f'Dr. {session.get("first_name")} {session.get("last_name")} has updated their profile and schedule.',
                    'info'
                )
            
            logger.info(f"Doctor {doctor_id} updated complete profile")
            return jsonify({'success': True, 'message': 'Profile and schedule updated successfully'})
        
    except Exception as e:
        logger.error(f"Error in doctor complete profile: {e}")
        return jsonify({'success': False, 'message': 'Failed to process request'}), 500    
# Add to app.py for real-time features

from flask_socketio import SocketIO, emit

socketio = SocketIO(app, cors_allowed_origins="*")
# app.py में Socket.IO events add करें
@socketio.on('connect')
def handle_connect():
    if 'user_id' in session:
        join_room(session['user_id'])
        emit('connected', {'message': 'Connected to real-time updates'})
        
        # Join receptionists room for broadcast
        if session.get('role') in ['receptionist', 'admin']:
            join_room('receptionists')

@socketio.on('join_room')
def handle_join_room(data):
    room = data.get('room')
    if room:
        join_room(room)

def broadcast_doctor_status_update(doctor_id, update_data):
    """Broadcast doctor status update to all receptionists"""
    socketio.emit('doctor_status_updated', update_data, room='receptionists')
    
    # Also send to the specific doctor
    socketio.emit('doctor_status_updated', update_data, room=doctor_id)
# @socketio.on('connect')
# def handle_connect():
#     if 'user_id' in session:
#         join_room(session['user_id'])
#         emit('connected', {'message': 'Connected to real-time updates'})

# @socketio.on('join_room')
# def handle_join_room(data):
#     room = data.get('room')
#     if room:
#         join_room(room)

# def send_real_time_notification(user_id, notification_data):
#     socketio.emit('new_notification', notification_data, room=user_id)

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

def init_doctor_availability():
    """Initialize doctor availability schedules"""
    current_db = get_db_safe()
    if current_db is None:
        logger.warning("MongoDB not connected - cannot initialize doctor availability")
        return False
    
    try:
        # Check if doctor_availability collection exists
        if 'doctor_availability' not in current_db.list_collection_names():
            current_db.create_collection('doctor_availability')
            logger.info("Created doctor_availability collection")
        
        # Get all doctors
        doctors = current_db.users.find({'role': 'doctor'})
        
        # Default availability schedule (9 AM - 5 PM on weekdays)
        default_schedule = [
            {'day_of_week': 'monday', 'start_time': '09:00', 'end_time': '17:00', 'max_appointments': 8},
            {'day_of_week': 'tuesday', 'start_time': '09:00', 'end_time': '17:00', 'max_appointments': 8},
            {'day_of_week': 'wednesday', 'start_time': '09:00', 'end_time': '17:00', 'max_appointments': 8},
            {'day_of_week': 'thursday', 'start_time': '09:00', 'end_time': '17:00', 'max_appointments': 8},
            {'day_of_week': 'friday', 'start_time': '09:00', 'end_time': '17:00', 'max_appointments': 8},
            {'day_of_week': 'saturday', 'start_time': '10:00', 'end_time': '14:00', 'max_appointments': 4},
        ]
        
        availability_created = 0
        for doctor in doctors:
            doctor_id = doctor['user_id']
            
            # Check if doctor already has availability
            existing_availability = current_db.doctor_availability.find_one({'doctor_id': doctor_id})
            
            if not existing_availability:
                # Create default availability for this doctor
                for day_schedule in default_schedule:
                    availability_doc = {
                        'doctor_id': doctor_id,
                        'day_of_week': day_schedule['day_of_week'],
                        'start_time': day_schedule['start_time'],
                        'end_time': day_schedule['end_time'],
                        'max_appointments': day_schedule['max_appointments'],
                        'is_active': True,
                        'created_at': datetime.utcnow(),
                        'updated_at': datetime.utcnow()
                    }
                    current_db.doctor_availability.insert_one(availability_doc)
                    availability_created += 1
                
                logger.info(f"Created default availability for doctor: {doctor_id}")
        
        logger.info(f"Doctor availability initialization completed! Created {availability_created} availability slots")
        return True
        
    except Exception as e:
        logger.error(f"Doctor availability initialization error: {e}")
        return False

@app.route('/api/receptionist/doctor/<doctor_id>/available-slots/<date>')
@login_required
@role_required(['receptionist', 'admin'])
def get_doctor_available_slots_receptionist(doctor_id, date):
    """Get available time slots for a specific doctor on a specific date"""
    try:
        current_db = get_db_safe()
        
        if current_db is None:
            return jsonify({'error': 'Database not available'}), 500
        
        # Parse the date
        try:
            target_date = datetime.fromisoformat(date.replace('Z', '+00:00')).date()
        except ValueError:
            return jsonify({'error': 'Invalid date format'}), 400
        
        # Get doctor's availability for this day of week
        day_of_week = target_date.strftime('%A').lower()
        
        availability = current_db.doctor_availability.find_one({
            'doctor_id': doctor_id,
            'day_of_week': day_of_week,
            'is_active': True
        })
        
        if not availability:
            return jsonify({'available_slots': [], 'message': 'Doctor not available on this day'})
        
        # Get existing appointments for this doctor on this date
        start_of_day = datetime.combine(target_date, datetime.min.time()).replace(tzinfo=timezone.utc)
        end_of_day = start_of_day + timedelta(days=1)
        
        existing_appointments = list(current_db.appointments.find({
            'therapist_id': doctor_id,
            'date': {'$gte': start_of_day, '$lt': end_of_day},
            'status': {'$in': ['scheduled', 'confirmed', 'in-progress']}
        }))
        
        # Generate available time slots
        available_slots = generate_time_slots(
            availability['start_time'],
            availability['end_time'],
            existing_appointments,
            availability.get('max_appointments', 3)
        )
        
        # Get doctor details
        doctor = current_db.users.find_one({'user_id': doctor_id})
        
        return jsonify({
            'available_slots': available_slots,
            'doctor_name': f"Dr. {doctor.get('first_name', '')} {doctor.get('last_name', '')}" if doctor else 'Unknown Doctor',
            'specialization': doctor.get('specialization', ''),
            'day_schedule': {
                'start_time': availability['start_time'],
                'end_time': availability['end_time']
            }
        })
        
    except Exception as e:
        logger.error(f"Error getting doctor available slots: {e}")
        return jsonify({'error': 'Failed to load available slots'}), 500

def generate_time_slots(start_time_str, end_time_str, existing_appointments, max_appointments_per_slot=3):
    """Generate available time slots considering existing appointments"""
    try:
        # Parse time strings
        start_time = datetime.strptime(start_time_str, '%H:%M').time()
        end_time = datetime.strptime(end_time_str, '%H:%M').time()
        
        # Create slots (30-minute intervals)
        slots = []
        current_time = datetime.combine(datetime.today(), start_time)
        end_datetime = datetime.combine(datetime.today(), end_time)
        
        while current_time < end_datetime:
            slot_end = current_time + timedelta(minutes=30)
            
            # Count existing appointments in this time slot
            slot_appointments = 0
            for appointment in existing_appointments:
                if appointment.get('date'):
                    appointment_time = appointment['date'].time()
                    if current_time.time() <= appointment_time < slot_end.time():
                        slot_appointments += 1
            
            # If slot has availability, add it
            if slot_appointments < max_appointments_per_slot:
                slots.append({
                    'start_time': current_time.strftime('%H:%M'),
                    'end_time': slot_end.strftime('%H:%M'),
                    'available_slots': max_appointments_per_slot - slot_appointments
                })
            
            current_time = slot_end
        
        return slots
        
    except Exception as e:
        logger.error(f"Error generating time slots: {e}")
        return []

@app.route('/api/receptionist/confirm-appointment-with-slot', methods=['POST'])
@login_required
@role_required(['receptionist', 'admin'])
def confirm_appointment_with_slot():
    """Confirm appointment with specific time slot selection"""
    try:
        data = request.get_json()
        appointment_id = data.get('appointment_id')
        selected_slot = data.get('selected_slot')
        selected_date = data.get('selected_date')
        
        if not appointment_id or not selected_slot or not selected_date:
            return jsonify({'success': False, 'error': 'Appointment ID, slot, and date are required'}), 400
        
        current_db = get_db_safe()
        
        if current_db is None:
            return jsonify({'success': True, 'message': 'Appointment confirmed (demo mode)'})
        
        # Get appointment details
        appointment = current_db.appointments.find_one({'appointment_id': appointment_id})
        if not appointment:
            return jsonify({'success': False, 'error': 'Appointment not found'}), 404
        
        # Parse date and time
        try:
            # Combine date and start time
            slot_datetime_str = f"{selected_date}T{selected_slot['start_time']}:00"
            scheduled_datetime = datetime.fromisoformat(slot_datetime_str.replace('Z', '+00:00'))
        except ValueError as e:
            return jsonify({'success': False, 'error': 'Invalid date/time format'}), 400
        
        # Update appointment with confirmed time
        update_data = {
            'status': 'confirmed',
            'date': scheduled_datetime,
            'confirmed_by': session['user_id'],
            'confirmed_at': datetime.utcnow(),
            'updated_at': datetime.utcnow(),
            'time_slot': selected_slot
        }
        
        result = current_db.appointments.update_one(
            {'appointment_id': appointment_id},
            {'$set': update_data}
        )
        
        if result.modified_count == 0:
            return jsonify({'success': False, 'error': 'Failed to update appointment'}), 400
        
        # Get patient and doctor details for notifications
        patient = current_db.users.find_one({'user_id': appointment.get('patient_id')})
        doctor = current_db.users.find_one({'user_id': appointment.get('therapist_id')})
        
        # Format date for display
        formatted_date = scheduled_datetime.strftime('%d %b %Y at %I:%M %p')
        
        # Send email notifications
        if patient:
            send_appointment_confirmation_email(
                patient['email'],
                f"{patient.get('first_name', '')} {patient.get('last_name', '')}",
                formatted_date,
                appointment.get('therapy_type', '').title(),
                f"Dr. {doctor.get('first_name', '')} {doctor.get('last_name', '')}" if doctor else 'Doctor'
            )
            
            create_notification(
                patient['user_id'],
                'Appointment Confirmed! 🎉',
                f'Your {appointment.get("therapy_type", "therapy")} appointment has been confirmed for {formatted_date}.',
                'success'
            )
        
        # Notify doctor
        if doctor:
            send_doctor_notification_email(
                doctor['email'],
                f"{doctor.get('first_name', '')} {doctor.get('last_name', '')}",
                f"{patient.get('first_name', '')} {patient.get('last_name', '')}" if patient else 'Patient',
                formatted_date,
                appointment.get('therapy_type', '').title()
            )
            
            create_notification(
                doctor['user_id'],
                'New Appointment Confirmed',
                f'New appointment confirmed with {patient.get("first_name", "Patient") if patient else "Patient"} for {appointment.get("therapy_type")} on {formatted_date}.',
                'info'
            )
        
        logger.info(f"✅ Appointment {appointment_id} confirmed with time slot by {session['user_id']}")
        
        return jsonify({
            'success': True,
            'message': 'Appointment confirmed successfully!',
            'appointment_id': appointment_id,
            'scheduled_time': formatted_date
        })
        
    except Exception as e:
        logger.error(f"Error confirming appointment with slot: {e}")
        return jsonify({'success': False, 'error': 'Failed to confirm appointment'}), 500

# Real-time Doctor Availability APIs
@app.route('/api/doctor/real-time-status', methods=['POST'])
@login_required
@role_required(['doctor'])
def update_doctor_real_time_status():
    """Update doctor's real-time availability status"""
    try:
        current_db = get_db_safe()
        doctor_id = session['user_id']
        data = request.get_json()
        
        is_available = data.get('is_available', True)
        status_message = data.get('status_message', '')
        
        # Update doctor status
        update_data = {
            'is_available': is_available,
            'status_message': status_message,
            'status_updated_at': datetime.utcnow(),
            'updated_at': datetime.utcnow()
        }
        
        result = current_db.users.update_one(
            {'user_id': doctor_id},
            {'$set': update_data}
        )
        
        if result.modified_count > 0:
            # Notify all receptionists
            receptionists = current_db.users.find({'role': 'receptionist'})
            for receptionist in receptionists:
                create_notification(
                    receptionist['user_id'],
                    'Doctor Status Changed',
                    f'Dr. {session.get("first_name")} {session.get("last_name")} is now {"available" if is_available else "busy"}. {status_message}',
                    'info' if is_available else 'warning'
                )
            
            # Broadcast real-time update
            socketio.emit('doctor_status_updated', {
                'doctor_id': doctor_id,
                'doctor_name': f"Dr. {session.get('first_name')} {session.get('last_name')}",
                'is_available': is_available,
                'status_message': status_message,
                'updated_at': datetime.utcnow().isoformat()
            }, broadcast=True)
            
            return jsonify({
                'success': True, 
                'message': f'Status updated to {"available" if is_available else "busy"}',
                'is_available': is_available
            })
        else:
            return jsonify({'error': 'Failed to update status'}), 400
            
    except Exception as e:
        logger.error(f"Error updating doctor real-time status: {e}")
        return jsonify({'error': 'Failed to update status'}), 500

@app.route('/api/receptionist/real-time-doctor-availability')
@login_required
@role_required(['receptionist', 'admin'])
def get_real_time_doctor_availability():
    """Get real-time doctor availability data with live updates"""
    try:
        current_db = get_db_safe()
        if current_db is None:
            return jsonify({
                "success": False, 
                "error": "Database not available",
                "doctors": []
            }), 500

        doctors = list(current_db.users.find({"role": "doctor"}))
        output = []
        
        for doctor in doctors:
            try:
                doctor_id = doctor["user_id"]
                
                # Get current availability status
                is_available = doctor.get("is_available", True)
                status_message = doctor.get("status_message", "")
                status_updated_at = doctor.get("status_updated_at")
                
                # Get today's schedule
                today = datetime.now().strftime("%A").lower()
                today_availability = current_db.doctor_availability.find_one({
                    "doctor_id": doctor_id,
                    "day_of_week": today,
                    "is_active": True
                })
                
                # Check if doctor is currently in their scheduled time
                is_available_now = False
                if today_availability and is_available:
                    current_time = datetime.now().strftime("%H:%M")
                    start_time = today_availability.get("start_time", "00:00")
                    end_time = today_availability.get("end_time", "23:59")
                    is_available_now = start_time <= current_time <= end_time
                
                # Count today's appointments
                today_start = datetime.now().replace(hour=0, minute=0, second=0, microsecond=0)
                today_end = today_start + timedelta(days=1)
                
                todays_appointments = current_db.appointments.count_documents({
                    "therapist_id": doctor_id,
                    "date": {"$gte": today_start, "$lt": today_end},
                    "status": {"$in": ["scheduled", "confirmed", "in-progress"]}
                })
                
                # Get weekly schedule
                availability = list(current_db.doctor_availability.find({
                    "doctor_id": doctor_id, 
                    "is_active": True
                }))
                
                weekly_schedule = {}
                days_order = ['monday', 'tuesday', 'wednesday', 'thursday', 'friday', 'saturday', 'sunday']
                for day in days_order:
                    day_slots = [slot for slot in availability if slot.get('day_of_week') == day]
                    if day_slots:
                        weekly_schedule[day.capitalize()] = [{
                            'start_time': slot.get('start_time'),
                            'end_time': slot.get('end_time'),
                            'max_appointments': slot.get('max_appointments', 3)
                        } for slot in day_slots]
                
                doctor_data = {
                    "user_id": doctor_id,
                    "name": f"Dr. {doctor.get('first_name', '')} {doctor.get('last_name', '')}",
                    "therapy_type": doctor.get("therapy_type", "General Therapy"),
                    "specialization": doctor.get("specialization", "Therapy Specialist"),
                    "experience": doctor.get("experience", 0),
                    "consultation_fee": doctor.get("consultation_fee", 0),
                    "phone": doctor.get("phone", ""),
                    "email": doctor.get("email", ""),
                    
                    # Real-time status fields
                    "is_available": is_available,
                    "is_available_now": is_available_now and is_available,
                    "status_message": status_message,
                    "status_updated_at": status_updated_at.isoformat() if status_updated_at else None,
                    
                    "today_appointments": todays_appointments,
                    "today_availability": today_availability,
                    "weekly_schedule": weekly_schedule,
                    "next_available": calculate_next_available_slot(doctor_id, current_db)
                }
                
                output.append(doctor_data)
                
            except Exception as doctor_error:
                logger.error(f"Error processing doctor {doctor.get('user_id', 'unknown')}: {doctor_error}")
                continue

        return jsonify({
            "success": True, 
            "doctors": output,
            "last_updated": datetime.utcnow().isoformat(),
            "total_doctors": len(output)
        })

    except Exception as e:
        logger.error(f"Error in real-time doctor availability: {e}")
        return jsonify({
            "success": False, 
            "error": "Failed to load doctor availability data",
            "doctors": []
        }), 500


# Call this after database initialization
if db_connected:
    init_doctor_availability()


# Add to app.py after SocketIO initialization
@socketio.on('doctor_availability_update')
def handle_doctor_availability_update(data):
    # Broadcast to all receptionists and relevant patients
    emit('availability_updated', data, broadcast=True, namespace='/')

# Call this when a doctor updates their availability
def notify_availability_update(doctor_id):
    socketio.emit('availability_updated', {
        'doctor_id': doctor_id,
        'timestamp': datetime.utcnow().isoformat(),
        'message': 'Doctor availability updated'
    }, broadcast=True, namespace='/')    


@app.errorhandler(404)
def not_found_error(error):
    return jsonify({'error': 'Resource not found'}), 404

@app.errorhandler(500)
def internal_error(error):
    logger.error(f'Server Error: {error}')
    return jsonify({'error': 'Internal server error'}), 500

@app.errorhandler(Exception)
def handle_exception(error):
    logger.error(f'Unhandled Exception: {error}')
    return jsonify({'error': 'An unexpected error occurred'}), 500

if __name__ == '__main__':    
    app.run(host='0.0.0.0', port=5000, debug=True)