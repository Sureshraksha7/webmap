from flask import Flask, request, jsonify
from flask_cors import CORS
import requests
import json
import os
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from flask_jwt_extended import create_access_token, jwt_required, get_jwt_identity, JWTManager, get_jwt
from datetime import datetime, timezone, timedelta
import re
import logging
from logging.handlers import RotatingFileHandler
import sys
from dotenv import load_dotenv, find_dotenv

# Load environment variables from a .env file if present (won't override existing env vars)
load_dotenv(dotenv_path=find_dotenv(), override=False)

# Configure Flask app with writable instance path for Vercel
if os.environ.get('VERCEL'):
    # On Vercel, use /tmp which is writable
    app = Flask(__name__, instance_path='/tmp/flask_instance')
else:
    # Local development uses default instance path
    app = Flask(__name__)

CORS(app)

# --- Logging Configuration ---
# Create logs directory if it doesn't exist (skip on Vercel)
log_dir = os.path.join(os.path.dirname(__file__), '..', 'logs')
if not os.environ.get('VERCEL'):  # Don't create logs directory on Vercel
    os.makedirs(log_dir, exist_ok=True)

# Configure logging format
log_format = logging.Formatter(
    '%(asctime)s - %(name)s - %(levelname)s - [%(filename)s:%(lineno)d] - %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)

# Set up root logger (only if not already configured)
root_logger = logging.getLogger()
if not root_logger.handlers:  # Prevent duplicate handlers on reload
    root_logger.setLevel(logging.INFO)

    # Console handler (stdout)
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setLevel(logging.INFO)
    console_handler.setFormatter(log_format)
    root_logger.addHandler(console_handler)

    # File handler only for local development (not on Vercel)
    if not os.environ.get('VERCEL') and os.path.exists(log_dir):
        log_file = os.path.join(log_dir, 'app.log')
        file_handler = RotatingFileHandler(
            log_file,
            maxBytes=10 * 1024 * 1024,  # 10MB
            backupCount=5
        )
        file_handler.setLevel(logging.INFO)
        file_handler.setFormatter(log_format)
        root_logger.addHandler(file_handler)

        # Error log file (separate file for errors)
        error_log_file = os.path.join(log_dir, 'errors.log')
        error_handler = RotatingFileHandler(
            error_log_file,
            maxBytes=10 * 1024 * 1024,  # 10MB
            backupCount=5
        )
        error_handler.setLevel(logging.ERROR)
        error_handler.setFormatter(log_format)
        root_logger.addHandler(error_handler)

# Get logger for this module
logger = logging.getLogger(__name__)

# Request logging middleware
@app.before_request
def log_request_info():
    """Log incoming requests"""
    logger.info(f"Request: {request.method} {request.path}")
    logger.info(f"Remote Address: {request.remote_addr}")
    if request.is_json:
        try:
            body = request.get_json()
            safe_body = {
                k: '***' if k in ['password', 'old_password', 'new_password'] else v
                for k, v in body.items()
            } if isinstance(body, dict) else body
            logger.debug(f"Request Body: {json.dumps(safe_body, indent=2)}")
        except:
            pass
    elif request.form:
        logger.debug(f"Form Data: {dict(request.form)}")

@app.after_request
def log_response_info(response):
    """Log outgoing responses"""
    logger.info(f"Response: {response.status_code} for {request.method} {request.path}")
    return response

# Error logging
from werkzeug.exceptions import NotFound, MethodNotAllowed, BadRequest, Unauthorized, Forbidden

@app.errorhandler(404)
def handle_not_found(e):
    logger.warning(f"404 Not Found: {request.method} {request.path}")
    return jsonify({"error": "Endpoint not found"}), 404

@app.errorhandler(405)
def handle_method_not_allowed(e):
    logger.warning(f"405 Method Not Allowed: {request.method} {request.path}")
    return jsonify({"error": "Method not allowed"}), 405

@app.errorhandler(400)
def handle_bad_request(e):
    logger.warning(f"400 Bad Request: {request.method} {request.path} - {str(e)}")
    return jsonify({"error": str(e)}), 400

@app.errorhandler(401)
def handle_unauthorized(e):
    logger.warning(f"401 Unauthorized: {request.method} {request.path}")
    return jsonify({"error": "Unauthorized"}), 401

@app.errorhandler(403)
def handle_forbidden(e):
    logger.warning(f"403 Forbidden: {request.method} {request.path}")
    return jsonify({"error": "Forbidden"}), 403

@app.errorhandler(Exception)
def handle_exception(e):
    import traceback
    error_trace = traceback.format_exc()
    logger.error(f"Exception occurred: {str(e)}\n{error_trace}")

    if os.environ.get('VERCEL') or os.environ.get('FLASK_ENV') != 'development':
        return jsonify({"error": "An internal error occurred"}), 500
    else:
        return jsonify({"error": str(e), "traceback": error_trace}), 500

# --- Database and Auth Configuration ---
_raw_db_url = os.environ.get("DATABASE_URL", "")
logger.info(f"Raw DATABASE_URL received (first 30 chars): {repr(_raw_db_url[:30])}")

_db_url = _raw_db_url.strip().strip('"').strip("'").strip()

logger.info(f"After cleaning DATABASE_URL (first 30 chars): {repr(_db_url[:30])}")
logger.info(f"DATABASE_URL length: {len(_db_url)}")
logger.info(f"DATABASE_URL is empty: {not _db_url}")

if not _db_url or _db_url in ('""', "''", ''):
    if os.environ.get('VERCEL'):
        logger.error("❌ DATABASE_URL environment variable is missing or empty on Vercel!")
        logger.error(f"Raw value was: {repr(_raw_db_url[:50])}")
        logger.error("Please set DATABASE_URL in Vercel Dashboard:")
        raise ValueError("DATABASE_URL environment variable is required on Vercel.")
    else:
        _db_url = "sqlite:///users.db"
        logger.info("Using local SQLite database for development")

if _db_url.startswith("postgres://"):
    _db_url = _db_url.replace("postgres://", "postgresql://", 1)
    logger.info("Converted postgres:// URL to postgresql:// for SQLAlchemy")

if not _db_url.startswith(("postgresql://", "sqlite://")):
    logger.error("❌ Invalid DATABASE_URL format!")
    raise ValueError("Invalid DATABASE_URL format.")

app.config['SQLALCHEMY_DATABASE_URI'] = _db_url
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

logger.info(f"✅ Database configured successfully: {_db_url.split('@')[0] if '@' in _db_url else 'SQLite'}")

if os.environ.get('WERKZEUG_RUN_MAIN') == 'true' or os.environ.get('WERKZEUG_RUN_MAIN') is None:
    logger.info("=" * 60)
    logger.info("Flask application starting...")
    logger.info(f"Log directory: {log_dir}")
    logger.info("=" * 60)

app.config['JWT_SECRET_KEY'] = os.environ.get('JWT_SECRET_KEY', 'your-super-secret-key-change-this')
app.config["JWT_BLACKLIST_ENABLED"] = True
app.config["JWT_BLACKLIST_TOKEN_CHECKS"] = ["access"]
app.config["JWT_ACCESS_TOKEN_EXPIRES"] = timedelta(hours=1)

db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
jwt = JWTManager(app)

# --- Google API Config ---
GOOGLE_API_KEY = os.environ.get("GOOGLE_API_KEY", "")

_requested_gemini_model = os.environ.get("GEMINI_MODEL", "gemini-2.5-flash").strip()
_gemini_model_aliases = {
    "gemini-2.5-flash": "gemini-2.0-flash",
    "gemini 2.5 flash": "gemini-2.0-flash",
    "gemini-2.5-flash-exp": "gemini-2.0-flash",
    "gemini-1.5-flash": "gemini-1.5-flash",
    "gemini-1.5-pro": "gemini-1.5-pro",
    "gemini-2.0-flash": "gemini-2.0-flash",
    "gemini-2.0-pro": "gemini-2.0-pro",
    "gemini-2.5-pro": "gemini-2.5-pro"
}

GEMINI_MODEL = _gemini_model_aliases.get(_requested_gemini_model.lower(), _requested_gemini_model)
API_URL_GEMINI = f"https://generativelanguage.googleapis.com/v1/models/{GEMINI_MODEL}:generateContent?key={GOOGLE_API_KEY}"

OPENAI_API_KEY = os.environ.get("OPENAI_API_KEY", "")
API_URL_OPENAI = "https://api.openai.com/v1/chat/completions"

# --- Database Models ---
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    phone = db.Column(db.String(20), nullable=True)
    password_hash = db.Column(db.String(128), nullable=False)
    structures = db.relationship('Structure', backref='user', lazy=True, cascade="all, delete-orphan")

    def __repr__(self):
        return f'<User {self.email}>'

class Structure(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    company_name = db.Column(db.String(100), nullable=False)
    category = db.Column(db.String(100), nullable=False)
    json_data = db.Column(db.Text, nullable=False)
    created_at = db.Column(db.DateTime, nullable=False, default=lambda: datetime.now(timezone.utc))
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    model_used = db.Column(db.String(50), nullable=True, default='gemini')

    def to_dict(self):
        structure_json = json.loads(self.json_data)
        num_pages = len(structure_json)

        return {
            "id": self.id,
            "company_name": self.company_name,
            "category": self.category,
            "structure": structure_json,
            "created_at": self.created_at.isoformat(),
            "user_id": self.user_id,
            "num_pages": num_pages,
            "model_used": self.model_used
        }

class TokenBlacklist(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    jti = db.Column(db.String(36), nullable=False, unique=True)
    created_at = db.Column(db.DateTime, nullable=False, default=lambda: datetime.now(timezone.utc))

@jwt.token_in_blocklist_loader
def check_if_token_in_blacklist(jwt_header, jwt_payload):
    jti = jwt_payload["jti"]
    token = TokenBlacklist.query.filter_by(jti=jti).first()
    return token is not None

# --- Generator Utility Function ---
def generate_content_with_model(model_choice, company_name, category, num_pages, description, current_structure=None, refinement_prompt=None):
    json_schema = {
        "type": "ARRAY",
        "items": {
            "type": "OBJECT",
            "properties": {
                "menu": {"type": "STRING"},
                "icon": {"type": "STRING"},
                "sections": {
                    "type": "ARRAY",
                    "items": {
                        "type": "OBJECT",
                        "properties": {
                            "section": {"type": "STRING"},
                            "subsections": {
                                "type": "ARRAY",
                                "items": {
                                    "type": "OBJECT",
                                    "properties": {
                                        "name": {"type": "STRING"},
                                        "description": {"type": "STRING"}
                                    },
                                    "required": ["name", "description"]
                                },
                                "minItems": 2
                            }
                        },
                        "required": ["section", "subsections"]
                    }
                }
            },
            "required": ["menu", "icon", "sections"]
        }
    }

    if refinement_prompt and current_structure is not None:
        current_structure_json = json.dumps(current_structure, indent=2)
        prompt = (
            f"You are a website structure refinement assistant. Modify the provided JSON structure "
            f"for '{company_name}'. Current structure:\n{current_structure_json}\n\n"
            f"User request:\n'{refinement_prompt}'.\n"
            f"Return ONLY the modified JSON array."
        )
    else:
        context_sentence = f"The specific context and product details are: '{description}'. " if description else ""
        prompt = (
            f"Generate a 3-level website structure for '{company_name}' ({category}). {context_sentence}"
            f"Generate EXACTLY {num_pages} menu items. Each section must have at least 2 subsections with non-empty descriptions. "
            f"Return ONLY a JSON array."
        )

    logger.info(f"Calling {model_choice.upper()} API for company: {company_name}")

    if model_choice == 'openai':
        headers = {
            "Content-Type": "application/json",
            "Authorization": f"Bearer {OPENAI_API_KEY}"
        }
        system_content = "You are a JSON generator. Follow the schema exactly."
        if refinement_prompt:
            system_content = "You refine JSON structures while following the schema strictly."

        payload = {
            "model": "gpt-4o-mini",
            "messages": [
                {"role": "system", "content": system_content},
                {"role": "user", "content": prompt}
            ],
            "response_format": {"type": "json_object"},
            "temperature": 0.5
        }

        response = requests.post(API_URL_OPENAI, headers=headers, data=json.dumps(payload))

        if response.status_code != 200:
            raise Exception(f"OpenAI API Error ({response.status_code}): {response.text}")

        result = response.json()
        json_text = result['choices'][0]['message']['content']

    else:
        payload = {
            "contents": [
                {
                    "role": "user",
                    "parts": [{"text": prompt}]
                }
            ],
            "generationConfig": {
                "temperature": 0.4,
                "maxOutputTokens": 2048
            }
        }

        headers = {"Content-Type": "application/json"}

        response = requests.post(API_URL_GEMINI, headers=headers, data=json.dumps(payload))

        if response.status_code != 200:
            raise Exception(f"Gemini API Error ({response.status_code}): {response.text}")

        result = response.json()
        json_text = result['candidates'][0]['content']['parts'][0]['text']

    return json_text

# --- Generator Routes ---
@app.route('/generate', methods=['POST'])
@jwt_required()
def generate_structure():
    user_id_str = get_jwt_identity()
    current_user_id = int(user_id_str)

    try:
        data = request.get_json()
        company_name = data.get('company_name', 'Company')
        category = data.get('category', 'General')
        num_pages = data.get('num_pages', 5)
        description = data.get('description', '')
        model_choice = data.get('model', 'gemini')

        raw_json_text = generate_content_with_model(
            model_choice=model_choice,
            company_name=company_name,
            category=category,
            num_pages=num_pages,
            description=description
        )

        match = re.search(r'\[.*\]', raw_json_text, re.DOTALL)
        cleaned_json_text = match.group(0).strip() if match else raw_json_text.strip()

        try:
            validated_json = json.loads(cleaned_json_text)
            cleaned_json_text = json.dumps(validated_json)
        except json.JSONDecodeError as e:
            return jsonify({
                "error": "The AI model returned malformed data. Try generating fewer pages."
            }), 422

        new_structure = Structure(
            company_name=company_name,
            category=category,
            json_data=cleaned_json_text,
            user_id=current_user_id,
            model_used=model_choice
        )

        db.session.add(new_structure)
        db.session.commit()

        return jsonify({
            "message": "Structure generated successfully",
            "structure": json.loads(cleaned_json_text)
        })

    except Exception as e:
        logger.error(str(e))
        return jsonify({"error": str(e)}), 500
