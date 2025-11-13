"""
Vercel entry point - imports the Flask app from backend/api/app.py
"""
import sys
import os

# Add backend/api to Python path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'backend', 'api'))

# Import the Flask app
from app import app

# Export for Vercel
__all__ = ['app']

