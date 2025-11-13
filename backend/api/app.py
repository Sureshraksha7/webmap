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
from dotenv import load_dotenv
load_dotenv()

app = Flask(__name__)
CORS(app)
# --- Database and Auth Configuration ---
# Prefer managed DB via DATABASE_URL; fall back to local SQLite for dev
_db_url = os.environ.get("DATABASE_URL", "sqlite:///users.db")
if _db_url.startswith("postgres://"):
    _db_url = _db_url.replace("postgres://", "postgresql://", 1)

app.config['SQLALCHEMY_DATABASE_URI'] = _db_url
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# IMPORTANT: Change this to a random, secret string in production!
app.config['JWT_SECRET_KEY'] = os.environ.get('JWT_SECRET_KEY', 'your-super-secret-key-change-this')
app.config["JWT_BLACKLIST_ENABLED"] = True
app.config["JWT_BLACKLIST_TOKEN_CHECKS"] = ["access"] 
app.config["JWT_ACCESS_TOKEN_EXPIRES"] = timedelta(hours=1) # Set token expiry

db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
jwt = JWTManager(app)
# --- End of Config ---


# --- Google API Config ---
# Note: It's safer to load this from an environment variable
# --- Google API Config ---
# Load API key from environment and use a stable model
GOOGLE_API_KEY = os.environ.get("GOOGLE_API_KEY", "")
GEMINI_MODEL = os.environ.get("GEMINI_MODEL", "gemini-1.5-flash")
API_URL_GEMINI = f"https://generativelanguage.googleapis.com/v1beta/models/{GEMINI_MODEL}:generateContent"

# --- OpenAI API Config (NEW) ---
# IMPORTANT: This key is now integrated
OPENAI_API_KEY = os.environ.get("OPENAI_API_KEY", "")
API_URL_OPENAI = "https://api.openai.com/v1/chat/completions"


# --- Database Models ---
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False) 
    email = db.Column(db.String(120), unique=True, nullable=False)
    # --- NEW: Added phone field ---
    phone = db.Column(db.String(20), nullable=True) # Stored as string, nullable
    password_hash = db.Column(db.String(128), nullable=False)
    # Relationship to link User to their Structures
    structures = db.relationship('Structure', backref='user', lazy=True, cascade="all, delete-orphan")

    def __repr__(self):
        return f'<User {self.email}>'

class Structure(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    company_name = db.Column(db.String(100), nullable=False)
    category = db.Column(db.String(100), nullable=False)
    # We save the JSON structure as a string in the DB
    json_data = db.Column(db.Text, nullable=False) 
    created_at = db.Column(db.DateTime, nullable=False, default=lambda: datetime.now(timezone.utc))
    # Foreign Key to link this structure to a User
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    
    # CRITICAL FIX: ADDED model_used COLUMN DEFINITION
    model_used = db.Column(db.String(50), nullable=True, default='gemini') 

    def to_dict(self):
        # Helper function to convert structure to a dictionary
        
        # First, load the structure from the JSON text
        structure_json = json.loads(self.json_data)
        
        # Calculate the number of main menu items (Level 1)
        num_pages = len(structure_json)
        
        return {
            "id": self.id,
            "company_name": self.company_name,
            "category": self.category,
            "structure": structure_json, # Use the variable we already loaded
            "created_at": self.created_at.isoformat(),
            "user_id": self.user_id,
            "num_pages": num_pages,
            "model_used": self.model_used # Expose the model used
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


# --- Generator Utility Function (UPDATED for Refinement) ---
def generate_content_with_model(model_choice, company_name, category, num_pages, description, current_structure=None, refinement_prompt=None):
    
    # Define the core 3-Level JSON Schema
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
        # **REFINEMENT MODE**
        
        # Add the current structure to the prompt for context
        current_structure_json = json.dumps(current_structure, indent=2)
        
        prompt = (
            f"You are a website structure refinement assistant. Your task is to MODIFY the provided JSON structure "
            f"for '{company_name}' based on the user's explicit request. "
            f"The current structure is:\n\n{current_structure_json}\n\n"
            f"--- User Refinement Request ---\n"
            f"'{refinement_prompt}'.\n"
            f"--- Task ---\n"
            f"Make the necessary changes. Maintain the 3-level (Menu > Section > Subsections) format and the JSON schema exactly. "
            f"If the request is complex, try to make the most logical update. Return ONLY the final, modified JSON array."
        )
        
        # For refinement, we don't enforce num_pages
    
    else:
        # **INITIAL GENERATION MODE**
        context_sentence = ""
        if description and description.strip():
            context_sentence = f"The specific context and product details are: '{description}'. "
        
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
    if model_choice == 'openai':
        # --- OpenAI API Call Logic ---
        headers = {
            "Content-Type": "application/json",
            "Authorization": f"Bearer {OPENAI_API_KEY}"
        }
        # System content slightly different for refinement vs initial generation
        system_content = "You are a JSON structure generator. You MUST follow the user's schema exactly. CRITICALLY: 'subsections' arrays must NOT be empty and must contain at least 2 objects, each with a 'name' and a non-empty 'description'. You MUST return ONLY the raw JSON array."
        if refinement_prompt:
            system_content = "You are a website structure refinement assistant. You MUST modify the provided JSON structure based on the request and return the complete, revised JSON array that strictly adheres to the schema (Menu > Section > Subsections, subsections must have a 'name' and non-empty 'description')."
            
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
        
    else: # Default to gemini
        # --- Gemini API Call Logic ---
        payload = { 
            "contents": [{"parts": [{"text": prompt}]}], 
            "generationConfig": { 
                "responseMimeType": "application/json", 
                "responseSchema": json_schema # Use the updated schema
            } 
        }
        headers = {"Content-Type": "application/json"}
        response = requests.post(API_URL_GEMINI, headers=headers, data=json.dumps(payload))

        if response.status_code != 200:
            raise Exception(f"Gemini API Error ({response.status_code}): {response.text}")

        result = response.json()
        json_text = result['candidates'][0]['content']['parts'][0]['text']
    
    return json_text
# --- End of Generator Utility Function ---


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

        # Call the unified generation function for initial generation
        raw_json_text = generate_content_with_model(
            model_choice=model_choice,
            company_name=company_name, 
            category=category, 
            num_pages=num_pages, 
            description=description,
            current_structure=None, # Not refinement
            refinement_prompt=None  # Not refinement
        )
        
        # --- CRITICAL FIX: Aggressively extract and clean the JSON string ---
        match = re.search(r'\[.*\]', raw_json_text, re.DOTALL)
        
        if match:
            cleaned_json_text = match.group(0).strip()
        else:
            cleaned_json_text = raw_json_text.strip()
            
        # --- Save to Database ---
        new_structure = Structure(
            company_name=company_name,
            category=category,
            json_data=cleaned_json_text, # Save the CLEANED JSON string
            user_id=current_user_id, # Use the integer ID
            model_used=model_choice  # Save the model used
        )
        db.session.add(new_structure)
        db.session.commit()

        # Return the newly created structure
        return jsonify(new_structure.to_dict()), 201 

    except Exception as e:
        db.session.rollback()
        return jsonify({"error": str(e)}), 500

# --- NEW: Refine Structure Route for Chatbot ---
@app.route('/structures/refine/<int:structure_id>', methods=['POST'])
@jwt_required()
def refine_structure(structure_id):
    user_id_str = get_jwt_identity()
    current_user_id = int(user_id_str)

    structure = Structure.query.get(structure_id)

    if not structure:
        return jsonify({"error": "Structure not found"}), 404
        
    if structure.user_id != current_user_id: 
        return jsonify({"error": "Unauthorized"}), 403 

    try:
        data = request.get_json()
        current_structure = data.get('current_structure')
        refinement_prompt = data.get('refinement_prompt')
        company_name = data.get('company_name', structure.company_name)
        model_choice = structure.model_used # Use the model that generated the original structure

        if not current_structure or not refinement_prompt:
             return jsonify({"error": "Missing current_structure or refinement_prompt"}), 400

        # Call the unified generation function for refinement
        refined_json_text = generate_content_with_model(
            model_choice=model_choice,
            company_name=company_name,
            category=structure.category, # Pass category for context, even if not strictly needed
            num_pages=0, # Not used in refinement mode
            description="", # Not used in refinement mode
            current_structure=current_structure,
            refinement_prompt=refinement_prompt
        )

        # Clean the returned JSON string
        match = re.search(r'\[.*\]', refined_json_text, re.DOTALL)
        if match:
            cleaned_json_text = match.group(0).strip()
        else:
            cleaned_json_text = refined_json_text.strip()

        # Update the database record
        structure.json_data = cleaned_json_text
        structure.company_name = company_name # Update company name if the user changed it via chat
        db.session.commit()

        # Return the newly updated structure data
        return jsonify(structure.to_dict()), 200

    except Exception as e:
        db.session.rollback()
        return jsonify({"error": str(e)}), 500

@app.route('/structures', methods=['GET'])
@jwt_required()
def get_structures():
    user_id_str = get_jwt_identity()
    current_user_id = int(user_id_str) 
    user = User.query.get(current_user_id) 
    
    if not user:
        return jsonify({"error": "User not found"}), 404

    structures = [s.to_dict() for s in user.structures]
    
    return jsonify(structures), 200

# ---
# === handle_structure (GET, PUT, DELETE) ===
# ---
@app.route('/structures/<int:structure_id>', methods=['GET', 'PUT', 'DELETE'])
@jwt_required()
def handle_structure(structure_id):
    user_id_str = get_jwt_identity()
    current_user_id = int(user_id_str) 
    
    structure = Structure.query.get(structure_id)
    
    if not structure:
        return jsonify({"error": "Structure not found"}), 404
        
    if structure.user_id != current_user_id: 
        return jsonify({"error": "Unauthorized"}), 403 

    if request.method == 'GET':
        return jsonify(structure.to_dict()), 200
        
    if request.method == 'PUT':
        try:
            data = request.get_json()
            
            if 'company_name' in data:
                structure.company_name = data['company_name']
                
            if 'structure' in data:
                structure.json_data = json.dumps(data['structure'])
                
            db.session.commit()
            return jsonify({"message": "Structure updated successfully"}), 200
        except Exception as e:
            db.session.rollback()
            return jsonify({"error": str(e)}), 500

    if request.method == 'DELETE':
        try:
            db.session.delete(structure)
            db.session.commit()
            return jsonify({"message": "Structure deleted successfully"}), 200
        except Exception as e:
            db.session.rollback()
            return jsonify({"error": str(e)}), 500
# --- End of Generator Routes ---


# --- Auth Routes (Unchanged) ---
@app.route('/register', methods=['POST'])
def register():
    data = request.get_json()
    email = data.get('email')
    password = data.get('password')
    name = data.get('name') 
    # --- NEW: Get phone ---
    phone = data.get('phone') 
    
    if not email or not password or not name:
        return jsonify({"error": "Name, email, and password are required"}), 400
    
    existing_user = User.query.filter_by(email=email).first()
    
    if existing_user:
        return jsonify({"error": "Email already registered"}), 400
    
    hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
    # --- NEW: Add phone to new user ---
    new_user = User(name=name, email=email, phone=phone, password_hash=hashed_password)
    
    try:
        db.session.add(new_user)
        db.session.commit()
        return jsonify({"message": f"User {email} registered successfully"}), 201
    except Exception as e:
        db.session.rollback()
        return jsonify({"error": str(e)}), 500

@app.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    email = data.get('email')
    password = data.get('password')
    
    if not email or not password:
        return jsonify({"error": "Email and password are required"}), 400
    
    user = User.query.filter_by(email=email).first()
    
    if user and bcrypt.check_password_hash(user.password_hash, password):
        access_token = create_access_token(identity=str(user.id)) 
        return jsonify(access_token=access_token), 200
    else:
        return jsonify({"error": "Invalid credentials"}), 401

@app.route('/profile', methods=['GET', 'PUT'])
@jwt_required()
def profile():
    user_id_str = get_jwt_identity() 
    user = User.query.get(int(user_id_str)) 
    
    if not user:
        return jsonify({"error": "User not found"}), 404

    if request.method == 'GET':
        return jsonify({
            "id": user.id,
            "name": user.name,
            "email": user.email,
            "phone": user.phone or "" # --- NEW: Return phone
        }), 200

    if request.method == 'PUT':
        data = request.get_json()
        
        if 'name' in data:
            user.name = data['name']
        
        # --- NEW: Add phone update ---
        if 'phone' in data:
            user.phone = data['phone']
            
        if 'email' in data and data['email'] != user.email:
            existing_user = User.query.filter_by(email=data['email']).first()
            if existing_user:
                return jsonify({"error": "Email already in use"}), 400
            user.email = data['email']
            
        try:
            db.session.commit()
            return jsonify({"message": "Profile updated successfully"}), 200
        except Exception as e:
            db.session.rollback()
            return jsonify({"error": str(e)}), 500

# --- NEW: Secure Password Change Endpoint ---
@app.route('/change-password', methods=['POST'])
@jwt_required()
def change_password():
    user_id_str = get_jwt_identity()
    user = User.query.get(int(user_id_str))
    
    if not user:
        return jsonify({"error": "User not found"}), 404
        
    data = request.get_json()
    old_password = data.get('old_password')
    new_password = data.get('new_password')
    
    if not old_password or not new_password:
        return jsonify({"error": "Old and new passwords are required"}), 400
        
    # 1. Verify old password
    if not bcrypt.check_password_hash(user.password_hash, old_password):
        return jsonify({"error": "Invalid old password"}), 401
        
    # 2. Set new password
    hashed_password = bcrypt.generate_password_hash(new_password).decode('utf-8')
    user.password_hash = hashed_password
    
    try:
        db.session.commit()
        return jsonify({"message": "Password updated successfully"}), 200
    except Exception as e:
        db.session.rollback()
        return jsonify({"error": str(e)}), 500
# --- End of New Endpoint ---

@app.route('/logout', methods=['POST'])
@jwt_required()
def logout():
    try:
        jti = get_jwt()["jti"]
        blacklisted_token = TokenBlacklist(jti=jti)
        db.session.add(blacklisted_token)
        db.session.commit()
        return jsonify({"message": "Successfully logged out"}), 200
    except Exception as e:
        db.session.rollback()
        return jsonify({"error": str(e)}), 500


if __name__ == '__main__':
    # Creates the database tables if they don't exist
    with app.app_context():
        db.create_all()
    app.run(debug=True)