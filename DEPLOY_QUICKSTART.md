# Quick Start: Deploy to Vercel

## 1. Install Vercel CLI
```bash
npm i -g vercel
```

## 2. Set Up Database
Get a PostgreSQL connection string from:
- Vercel Postgres (recommended)
- Neon (neon.tech)
- Supabase (supabase.com)

## 3. Deploy
```bash
cd /Users/kushalgowda/Desktop/webmap
vercel login
vercel
```

## 4. Set Environment Variables in Vercel Dashboard
Go to: Project Settings → Environment Variables

Add:
- `DATABASE_URL` = your PostgreSQL connection string
- `JWT_SECRET_KEY` = generate with: `python3 -c "import secrets; print(secrets.token_urlsafe(32))"`
- `GOOGLE_API_KEY` = (optional)
- `OPENAI_API_KEY` = (optional)

## 5. Update Frontend API URLs
After deployment, get your Vercel URL and update all frontend files:

**Option A: Use relative URLs (recommended)**
Replace in all HTML files:
```javascript
const API_URL = window.location.origin;
```

**Option B: Use your Vercel domain**
```javascript
const API_URL = 'https://your-project.vercel.app';
```

Files to update:
- `frontend/index.html`
- `frontend/dashboard.html`
- `frontend/create.html`
- `frontend/profile.html`
- `frontend/flowchart.html`

## 6. Initialize Database
After first deployment, create tables by calling:
```bash
# Get environment variables
vercel env pull .env.local

# Run setup (if you have setup_db.py)
python3 backend/api/setup_db.py
```

Or create a temporary endpoint in `app.py`:
```python
@app.route('/init-db', methods=['POST'])
def init_db():
    with app.app_context():
        db.create_all()
    return jsonify({"message": "Database initialized"}), 200
```

Call: `POST https://your-project.vercel.app/init-db` once, then remove it.

## 7. Deploy to Production
```bash
vercel --prod
```

## Important Notes
- ✅ Database must be PostgreSQL (not SQLite)
- ✅ All environment variables must be set in Vercel dashboard
- ✅ Frontend API URLs must point to your Vercel domain
- ✅ Database tables must be initialized after first deployment

For detailed instructions, see `VERCEL_DEPLOYMENT.md`

