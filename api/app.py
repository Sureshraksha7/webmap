"""
Vercel entry point - imports the Flask app from backend/api/app.py
"""
import sys
import os

# Get the absolute path to backend/api
current_dir = os.path.dirname(os.path.abspath(__file__))
backend_api_path = os.path.join(current_dir, '..', 'backend', 'api')
backend_api_path = os.path.abspath(backend_api_path)

# Add backend/api to Python path
if backend_api_path not in sys.path:
    sys.path.insert(0, backend_api_path)

# Import the Flask app
try:
    from app import app
except ImportError as e:
    # Fallback: try direct import
    import importlib.util
    spec = importlib.util.spec_from_file_location("app", os.path.join(backend_api_path, "app.py"))
    app_module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(app_module)
    app = app_module.app

# Export for Vercel
__all__ = ['app']

