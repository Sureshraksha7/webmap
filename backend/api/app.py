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
            maxBytes=10*1024*1024,  # 10MB
            backupCount=5
        )
        file_handler.setLevel(logging.INFO)
        file_handler.setFormatter(log_format)
        root_logger.addHandler(file_handler)
        
        # Error log file (separate file for errors)
        error_log_file = os.path.join(log_dir, 'errors.log')
        error_handler = RotatingFileHandler(
            error_log_file,
            maxBytes=10*1024*1024,  # 10MB
            backupCount=5
        )
        error_handler.setLevel(logging.ERROR)
        error_handler.setFormatter(log_format)
        root_logger.addHandler(error_handler)

# Get logger for this module
logger = logging.getLogger(__name__)

# Request logging middleware (omitted for brevity)

@app.before_request
def log_request_info():
    """Log incoming requests"""
    logger.info(f"Request: {request.method} {request.path}")
    if request.is_json:
        try:
            body = request.get_json()
            safe_body = {k: '***' if k in ['password', 'old_password', 'new_password'] else v 
                         for k, v in body.items()} if isinstance(body, dict) else body
            logger.debug(f"Request Body: {json.dumps(safe_body, indent=2)}")
        except:
            pass

@app.after_request
def log_response_info(response):
    """Log outgoing responses"""
    logger.info(f"Response: {response.status_code} for {request.method} {request.path}")
    return response

# Error handling routes (omitted for brevity)

@app.errorhandler(404)
def handle_not_found(e):
    logger.warning(f"404 Not Found: {request.method} {request.path}")
    return jsonify({"error": "Endpoint not found"}), 404

@app.errorhandler(Exception)
def handle_exception(e):
    import traceback
    logger.error(f"Exception occurred: {str(e)}\n{traceback.format_exc()}")
    return jsonify({"error": "An internal error occurred"}), 500

# --- Database and Auth Configuration ---
# (Environment variable loading logic omitted for brevity)
_db_url = os.environ.get("DATABASE_URL", "sqlite:///users.db")
if _db_url.startswith("postgres://"):
    _db_url = _db_url.replace("postgres://", "postgresql://", 1)

app.config['SQLALCHEMY_DATABASE_URI'] = _db_url
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['JWT_SECRET_KEY'] = os.environ.get('JWT_SECRET_KEY', 'your-super-secret-key-change-this')
app.config["JWT_BLACKLIST_ENABLED"] = True
app.config["JWT_BLACKLIST_TOKEN_CHECKS"] = ["access"] 
app.config["JWT_ACCESS_TOKEN_EXPIRES"] = timedelta(hours=1)

db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
jwt = JWTManager(app)
# --- End of Config ---


# --- Google API Config ---
GOOGLE_API_KEY = os.environ.get("GOOGLE_API_KEY", "")
OPENAI_API_KEY = os.environ.get("OPENAI_API_KEY", "")

# Model mapping function for cleaner API calls
def get_gemini_model_config(model_choice):
    model_map = {
        'gemini': 'gemini-2.5-flash',
        'gemini-2.5-pro': 'gemini-2.5-pro',
        'gemini-2.5-flash-preview-09-2025': 'gemini-2.5-flash', # Alias to stable
    }
    api_model = model_map.get(model_choice, 'gemini-2.5-flash')
    # Use the v1 endpoint which is current
    return f"https://generativelanguage.googleapis.com/v1/models/{api_model}:generateContent?key={GOOGLE_API_KEY}"

API_URL_OPENAI = "https://api.openai.com/v1/chat/completions"


# --- Database Models (Unchanged) ---
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False) 
    email = db.Column(db.String(120), unique=True, nullable=False)
    phone = db.Column(db.String(20), nullable=True)
    password_hash = db.Column(db.String(128), nullable=False)
    structures = db.relationship('Structure', backref='user', lazy=True, cascade="all, delete-orphan")

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
# --- End of Models ---


# --- Generator Utility Function (UPDATED PROMPT) ---
def generate_content_with_model(model_choice, company_name, category, num_pages, description, current_structure=None, refinement_prompt=None):
    
    # Define the core 3-Level JSON Schema (Omitted for brevity, assumed correct)
    json_schema = {
        "type": "ARRAY",
        "items": {
            "type": "OBJECT",
            "properties": {
                "menu": {"type": "STRING", "description": "Main menu item name (Level 1)"},
                "icon": {"type": "STRING", "description": "Font Awesome 5 class (e.g., 'fas fa-home')"},
                "sections": {
                    "type": "ARRAY",
                    "items": {
                        "type": "OBJECT",
                        "properties": {
                            "section": {"type": "STRING", "description": "Section page name (Level 2)"},
                            "subsections": {
                                "type": "ARRAY",
                                "items": {
                                    "type": "OBJECT",
                                    "properties": {
                                        "name": {"type": "STRING", "description": "Name of the subsection (L3)"},
                                        "description": {"type": "STRING", "description": "1-2 sentence content description for this subsection. MUST NOT BE EMPTY."}
                                    },
                                    "required": ["name", "description"]
                                },
                                "minItems": 2,
                                "description": "NON-EMPTY array of subsection objects (Level 3)"
                            }
                        },
                        "required": ["section", "subsections"]
                    }
                }
            },
            "required": ["menu", "icon", "sections"]
        }
    }
    
    # --- 1. DETERMINE PROMPT TYPE: Initial Generation or Refinement ---
    if refinement_prompt and current_structure is not None:
        # REFINEMENT MODE (Unchanged logic)
        current_structure_json = json.dumps(current_structure, indent=2)
        prompt = (f"You are a website structure refinement assistant. Your task is to MODIFY the provided JSON structure "
                  f"for '{company_name}' based on the user's explicit request. "
                  f"The current structure is:\n\n{current_structure_json}\n\n"
                  f"--- User Refinement Request ---\n"
                  f"'{refinement_prompt}'.\n"
                  f"--- Task ---\n"
                  f"Make the necessary changes. Maintain the 3-level (Menu > Section > Subsections) format and the JSON schema exactly. "
                  f"If the request is complex, try to make the most logical update. Return ONLY the final, modified JSON array.")
    
    else:
        # INITIAL GENERATION MODE (Prompt remains robust)
        context_sentence = f"The specific context and product details are: '{description}'. " if description and description.strip() else ""
        
        prompt = (
            f"Generate a 3-level website structure for '{company_name}' ({category}). {context_sentence}"
            f"The structure MUST be 3 levels deep: Menu > Section > Subsections. "
            f"You MUST generate EXACTLY {num_pages} 'menu' items. Do not generate more or fewer. "
            f"For each 'menu' item, provide a Font Awesome 5 'icon' class. "
            f"CRITICALLY: Every 'section' MUST have at least 2 'subsections'. "
            f"Each 'subsection' MUST be an object with a 'name' (string) and a 'description' (string, 1-2 sentences). "
            f"The 'description' MUST NOT be empty. It MUST provide a brief summary of the content for that subsection. "
            f"Return ONLY a JSON array matching this exact schema."
        )


    # --- 2. API Call Logic ---
    logger.info(f"Calling {model_choice.upper()} API for company: {company_name}, category: {category}")
    if 'openai' in model_choice:
        # OpenAI API Call Logic (omitted for brevity)
        pass # ... your existing OpenAI logic
        
    else: # Default to gemini (including gemini-2.5-pro)
        # --- Gemini API Call Logic ---
        api_url_gemini = get_gemini_model_config(model_choice)
        logger.debug("Using Gemini API")
        payload = {
            "contents": [
                {
                    "role": "user",
                    "parts": [{"text": prompt}]
                }
            ],
            "generationConfig": {
                "temperature": 0.4,
                "maxOutputTokens": 4096, # Increased token limit for large structures (up from 2048)
                "responseMimeType": "application/json", # Enforce structured JSON output
            }
        }
        headers = {"Content-Type": "application/json"}
        logger.debug(f"Gemini API request payload prepared")
        response = requests.post(api_url_gemini, headers=headers, data=json.dumps(payload))

        if response.status_code != 200:
            logger.error(f"Gemini API Error ({response.status_code}): {response.text}")
            raise Exception(f"Gemini API Error ({response.status_code}): {response.text}")

        result = response.json()
        
        # Check if structured output failed before accessing parts
        if 'candidates' not in result or not result['candidates'][0]['content']['parts']:
            raise Exception("Gemini returned empty or incomplete structured output (possible max_output_tokens issue).")
            
        json_text = result['candidates'][0]['content']['parts'][0]['text']
        logger.info(f"Gemini API call successful, response length: {len(json_text)} chars")
    
    return json_text
# --- End of Generator Utility Function ---


# --- Generator Routes (Modified for Robust JSON Handling) ---

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
        
        logger.info(f"User {current_user_id} generating structure for {company_name} ({category}), {num_pages} pages, model: {model_choice}")

        raw_json_text = generate_content_with_model(
            model_choice=model_choice, company_name=company_name, category=category, 
            num_pages=num_pages, description=description, current_structure=None, refinement_prompt=None
        )
        
        # 1. Aggressively extract the main JSON array
        match = re.search(r'\[.*\]', raw_json_text, re.DOTALL)
        cleaned_json_text = match.group(0).strip() if match else raw_json_text.strip()
            
        # 2. VALIDATION AND RE-DUMP LOGIC
        try:
            validated_json = json.loads(cleaned_json_text)
            # Re-dump to guarantee perfect formatting
            cleaned_json_text = json.dumps(validated_json)
            logger.info("Successfully validated and re-dumped AI generated JSON.")

        except json.JSONDecodeError as e:
            logger.error(f"FATAL JSON DECODE ERROR: {e}. Raw text start: {cleaned_json_text[:500]}")
            db.session.rollback()
            return jsonify({
                "error": "The AI model returned severely malformed data. Try generating 5-7 pages and expanding with the chat refinement feature."
            }), 422
        
        # 3. Save to Database
        new_structure = Structure(
            company_name=company_name, category=category, json_data=cleaned_json_text, 
            user_id=current_user_id, model_used=model_choice
        )
        db.session.add(new_structure)
        db.session.commit()
        
        logger.info(f"Structure created successfully: ID {new_structure.id} for user {current_user_id}")
        return jsonify(new_structure.to_dict()), 201 

    except Exception as e:
        db.session.rollback()
        logger.error(f"Error generating structure for user {current_user_id}: {str(e)}", exc_info=True)
        return jsonify({"error": str(e)}), 500

# --- NEW: Refine Structure Route (Modified for Robust JSON Handling) ---
@app.route('/structures/refine/<int:structure_id>', methods=['POST'])
@jwt_required()
def refine_structure(structure_id):
    user_id_str = get_jwt_identity()
    current_user_id = int(user_id_str)
    structure = Structure.query.get(structure_id)
    if not structure: return jsonify({"error": "Structure not found"}), 404
    if structure.user_id != current_user_id: return jsonify({"error": "Unauthorized"}), 403 

    try:
        data = request.get_json()
        current_structure = data.get('current_structure'); refinement_prompt = data.get('refinement_prompt'); company_name = data.get('company_name', structure.company_name)
        model_choice = structure.model_used

        if not current_structure or not refinement_prompt: return jsonify({"error": "Missing current_structure or refinement_prompt"}), 400

        refined_json_text = generate_content_with_model(
            model_choice=model_choice, company_name=company_name, category=structure.category, 
            num_pages=0, description="", current_structure=current_structure, refinement_prompt=refinement_prompt
        )

        match = re.search(r'\[.*\]', refined_json_text, re.DOTALL)
        cleaned_json_text = match.group(0).strip() if match else refined_json_text.strip()
        
        # JSON VALIDATION FOR REFINEMENT
        try:
            validated_json = json.loads(cleaned_json_text)
            cleaned_json_text = json.dumps(validated_json)
        except json.JSONDecodeError:
             return jsonify({"error": "Refinement failed. AI returned malformed data. Try a simpler prompt or fewer pages."}), 422

        structure.json_data = cleaned_json_text
        structure.company_name = company_name 
        db.session.commit()
        return jsonify(structure.to_dict()), 200

    except Exception as e:
        db.session.rollback()
        return jsonify({"error": str(e)}), 500

# --- Auth Routes (omitted for brevity, they remain unchanged) ---
@app.route('/register', methods=['POST'])
def register():
    data = request.get_json(); email = data.get('email'); password = data.get('password'); name = data.get('name'); phone = data.get('phone') 
    # ... logic ...
    return jsonify({"message": f"User {email} registered successfully"}), 201

@app.route('/login', methods=['POST'])
def login():
    data = request.get_json(); email = data.get('email'); password = data.get('password')
    # ... logic ...
    return jsonify(access_token="..."), 200

@app.route('/profile', methods=['GET', 'PUT'])
@jwt_required()
def profile():
    # ... logic ...
    return jsonify({"message": "Profile updated successfully"}), 200

@app.route('/logout', methods=['POST'])
@jwt_required()
def logout():
    # ... logic ...
    return jsonify({"message": "Successfully logged out"}), 200


if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    # Use port 5001 to avoid conflict with macOS AirPlay Receiver on port 5000
    app.run(debug=True, host='0.0.0.0', port=5001)
