# Vercel Deployment Guide

This guide will help you deploy your WebMap application to Vercel.

## Prerequisites

1. A Vercel account (sign up at https://vercel.com)
2. Vercel CLI installed: `npm i -g vercel`
3. A PostgreSQL database (Vercel Postgres or external provider like Neon, Supabase, etc.)

## Step 1: Set Up PostgreSQL Database

Vercel serverless functions don't support SQLite. You need a PostgreSQL database:

### Option A: Vercel Postgres (Recommended)
1. Go to your Vercel dashboard
2. Create a new Postgres database
3. Copy the connection string

### Option B: External Provider (Neon, Supabase, etc.)
1. Create a database on your preferred provider
2. Get the connection string (format: `postgresql://user:password@host:port/database`)

## Step 2: Configure Environment Variables

Set these environment variables in Vercel:

1. Go to your project settings → Environment Variables
2. Add the following:

```
DATABASE_URL=postgresql://user:password@host:port/database
JWT_SECRET_KEY=your-super-secret-key-change-this-to-random-string
GOOGLE_API_KEY=your-google-api-key (optional, if using Gemini)
OPENAI_API_KEY=your-openai-api-key (optional, if using OpenAI)
GEMINI_MODEL=gemini-1.5-flash (optional)
```

**Important**: Generate a strong random string for `JWT_SECRET_KEY`:
```bash
python3 -c "import secrets; print(secrets.token_urlsafe(32))"
```

## Step 3: Update Frontend API URLs

Before deploying, update all frontend files to use your Vercel domain:

1. After deployment, Vercel will give you a URL like `https://your-project.vercel.app`
2. Update `API_URL` in all frontend HTML files:
   - `frontend/index.html`
   - `frontend/dashboard.html`
   - `frontend/create.html`
   - `frontend/profile.html`
   - `frontend/flowchart.html`

Change from:
```javascript
const API_URL = 'http://localhost:5001';
```

To:
```javascript
const API_URL = 'https://your-project.vercel.app';
```

Or use a relative URL (recommended):
```javascript
const API_URL = window.location.origin;
```

## Step 4: Deploy to Vercel

### Method 1: Using Vercel CLI

```bash
# Install Vercel CLI (if not already installed)
npm i -g vercel

# Login to Vercel
vercel login

# Deploy (from project root)
cd /Users/kushalgowda/Desktop/webmap
vercel

# Follow the prompts:
# - Set up and deploy? Yes
# - Which scope? (select your account)
# - Link to existing project? No
# - Project name? webmap (or your preferred name)
# - Directory? ./
# - Override settings? No

# For production deployment
vercel --prod
```

### Method 2: Using GitHub Integration

1. Push your code to GitHub
2. Go to https://vercel.com/new
3. Import your GitHub repository
4. Configure:
   - Framework Preset: Other
   - Root Directory: ./
   - Build Command: (leave empty)
   - Output Directory: (leave empty)
5. Add environment variables (from Step 2)
6. Deploy

## Step 5: Initialize Database Tables

After deployment, you need to create the database tables. You can do this by:

### Option A: Using Vercel CLI
```bash
# Run a one-time script to create tables
vercel env pull .env.local
python3 backend/api/setup_db.py
```

### Option B: Create an API endpoint (temporary)
Add this to `app.py` temporarily:
```python
@app.route('/init-db', methods=['POST'])
def init_db():
    with app.app_context():
        db.create_all()
    return jsonify({"message": "Database initialized"}), 200
```

Call it once: `POST https://your-project.vercel.app/init-db`
Then remove the endpoint for security.

## Step 6: Verify Deployment

1. Visit your Vercel URL: `https://your-project.vercel.app`
2. Test registration: Create a new account
3. Test login: Sign in with your credentials
4. Check Vercel function logs for any errors

## Troubleshooting

### Database Connection Issues
- Verify `DATABASE_URL` is set correctly in Vercel environment variables
- Check that your database allows connections from Vercel IPs
- Ensure the connection string uses `postgresql://` not `postgres://`

### Function Timeout
- Increase `maxDuration` in `vercel.json` (max 60s for Pro plan)
- Optimize API calls (Gemini/OpenAI) to be faster

### CORS Issues
- CORS is already configured in `app.py` with `CORS(app)`
- If issues persist, check the frontend API URL is correct

### Logs
- View function logs in Vercel dashboard → Functions → Logs
- Check for Python errors or import issues

## File Structure for Vercel

```
webmap/
├── vercel.json          # Vercel configuration
├── requirements.txt     # Python dependencies
├── .gitignore          # Git ignore rules
├── .vercelignore       # Vercel ignore rules
├── backend/
│   └── api/
│       └── app.py      # Flask application (Vercel function)
└── frontend/
    └── *.html          # Static frontend files
```

## Important Notes

1. **Database**: Must use PostgreSQL (not SQLite) on Vercel
2. **File System**: Vercel functions are read-only except `/tmp`
3. **Logs**: Use console logging (stdout) - file logging won't work
4. **Cold Starts**: First request may be slow (~1-2s)
5. **Environment Variables**: Set in Vercel dashboard, not in code

## Post-Deployment Checklist

- [ ] Environment variables set in Vercel
- [ ] Database tables initialized
- [ ] Frontend API URLs updated
- [ ] Test registration flow
- [ ] Test login flow
- [ ] Test structure generation
- [ ] Remove any temporary endpoints
- [ ] Set up custom domain (optional)

## Support

For issues:
- Check Vercel function logs
- Review Vercel documentation: https://vercel.com/docs
- Check Python runtime docs: https://vercel.com/docs/functions/serverless-functions/runtimes/python

