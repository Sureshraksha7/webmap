# Deploy to Vercel - Step by Step

You're now on the `vercel-app` branch with all deployment files ready!

## Step 1: Push Branch to GitHub (if using GitHub)

```bash
# Push the vercel-app branch
git push origin vercel-app
```

## Step 2: Install Vercel CLI

```bash
npm i -g vercel
```

## Step 3: Login to Vercel

```bash
vercel login
```

## Step 4: Deploy from Current Branch

```bash
# Make sure you're in the project directory
cd /Users/kushalgowda/Desktop/webmap

# Deploy to Vercel
vercel

# Follow the prompts:
# - Set up and deploy? Yes
# - Which scope? (select your account)
# - Link to existing project? No (first time) or Yes (if updating)
# - Project name? webmap (or your preferred name)
# - Directory? ./
# - Override settings? No
```

## Step 5: Set Environment Variables

After deployment, go to Vercel Dashboard:
1. Open your project: https://vercel.com/dashboard
2. Go to **Settings** → **Environment Variables**
3. Add these variables:

### Required:
- **DATABASE_URL**: Your PostgreSQL connection string
  - Format: `postgresql://user:password@host:port/database`
  - Get from: Vercel Postgres, Neon, or Supabase

- **JWT_SECRET_KEY**: Generate a secure random string
  ```bash
  python3 -c "import secrets; print(secrets.token_urlsafe(32))"
  ```

### Optional (for AI features):
- **GOOGLE_API_KEY**: Your Google API key (for Gemini)
- **OPENAI_API_KEY**: Your OpenAI API key
- **GEMINI_MODEL**: `gemini-1.5-flash` (default)

## Step 6: Update Frontend API URLs

After deployment, you'll get a URL like: `https://your-project.vercel.app`

### Option A: Use Relative URLs (Recommended - Already Done!)
The frontend files are already configured to use:
```javascript
const API_URL = window.location.origin;
```
This automatically uses your Vercel domain! ✅

### Option B: Manual Update (if needed)
If you need to hardcode the URL, update these files:
- `frontend/index.html`
- `frontend/dashboard.html`
- `frontend/create.html`
- `frontend/profile.html`
- `frontend/flowchart.html`

Change:
```javascript
const API_URL = 'http://localhost:5001';
```
To:
```javascript
const API_URL = 'https://your-project.vercel.app';
```

## Step 7: Initialize Database

After first deployment, create database tables:

### Method 1: Using Vercel CLI
```bash
# Pull environment variables
vercel env pull .env.local

# Run setup script (if available)
python3 backend/api/setup_db.py
```

### Method 2: Temporary Endpoint (Quick)
Add this to `backend/api/app.py` temporarily:

```python
@app.route('/init-db', methods=['POST'])
def init_db():
    with app.app_context():
        db.create_all()
    return jsonify({"message": "Database initialized"}), 200
```

Then call it once:
```bash
curl -X POST https://your-project.vercel.app/init-db
```

**Important**: Remove this endpoint after initialization for security!

## Step 8: Deploy to Production

```bash
vercel --prod
```

## Step 9: Verify Deployment

1. Visit your Vercel URL: `https://your-project.vercel.app`
2. Test registration: Create a new account
3. Test login: Sign in
4. Test structure generation

## Troubleshooting

### Database Connection Issues
- Verify `DATABASE_URL` is correct in Vercel dashboard
- Ensure database allows connections from Vercel IPs
- Check connection string uses `postgresql://` not `postgres://`

### Function Errors
- Check Vercel dashboard → Functions → Logs
- Verify all environment variables are set
- Check `requirements.txt` has all dependencies

### CORS Issues
- CORS is already configured in `app.py`
- Verify frontend API URL matches your Vercel domain

## Current Branch Status

You're on: `vercel-app` branch ✅

Files ready for deployment:
- ✅ `vercel.json` - Vercel configuration
- ✅ `.gitignore` - Git ignore rules
- ✅ `.vercelignore` - Vercel ignore rules
- ✅ `backend/api/app.py` - Updated for Vercel
- ✅ `frontend/*.html` - Updated API URLs
- ✅ `requirements.txt` - Python dependencies

## Next Steps

1. **Push to GitHub** (if using GitHub integration):
   ```bash
   git push origin vercel-app
   ```

2. **Deploy via CLI**:
   ```bash
   vercel
   ```

3. **Or deploy via GitHub**:
   - Push branch to GitHub
   - Connect repo to Vercel
   - Vercel will auto-deploy

## Quick Commands Reference

```bash
# Check current branch
git branch --show-current

# View deployment files
ls -la vercel.json .gitignore .vercelignore

# Deploy to Vercel
vercel

# Deploy to production
vercel --prod

# View logs
vercel logs

# Check environment variables
vercel env ls
```

---

**Ready to deploy!** 🚀

Run `vercel` to start deployment!

