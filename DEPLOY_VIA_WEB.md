# Deploy to Vercel via Web Interface (No CLI Required!)

Since Node.js/npm is not installed, you can deploy directly through Vercel's web interface.

## Step 1: Push Branch to GitHub

If you have a GitHub repository:

```bash
# Check if you have a remote repository
git remote -v

# If you have a remote, push the vercel-app branch
git push origin vercel-app

# If you don't have a remote, create one on GitHub first, then:
git remote add origin https://github.com/YOUR_USERNAME/YOUR_REPO.git
git push -u origin vercel-app
```

## Step 2: Deploy via Vercel Web Interface

1. **Go to Vercel**: https://vercel.com/new
2. **Sign in** with your GitHub account (or create an account)
3. **Import Git Repository**:
   - Click "Import Git Repository"
   - Select your repository
   - Click "Import"
4. **Configure Project**:
   - **Framework Preset**: Other
   - **Root Directory**: `./` (leave as is)
   - **Build Command**: (leave empty)
   - **Output Directory**: (leave empty)
   - **Install Command**: (leave empty)
5. **Select Branch**: Choose `vercel-app` branch
6. **Environment Variables**: Click "Environment Variables" and add:
   - `DATABASE_URL` = Your PostgreSQL connection string
   - `JWT_SECRET_KEY` = Generate: `python3 -c "import secrets; print(secrets.token_urlsafe(32))"`
   - `GOOGLE_API_KEY` = (optional)
   - `OPENAI_API_KEY` = (optional)
7. **Deploy**: Click "Deploy"

## Step 3: After Deployment

1. **Get your Vercel URL**: You'll get a URL like `https://your-project.vercel.app`
2. **Initialize Database**: 
   - Add a temporary endpoint to create tables (see VERCEL_DEPLOYMENT.md)
   - Or use Vercel CLI later if you install Node.js
3. **Test**: Visit your URL and test the application

## Alternative: Install Node.js First

If you prefer using CLI:

### On macOS:
1. Download Node.js from: https://nodejs.org/
2. Install the .pkg file
3. Or use Homebrew:
   ```bash
   brew install node
   ```

### Then:
```bash
npm i -g vercel
vercel login
cd /Users/kushalgowda/Desktop/webmap
vercel
```

## Quick Reference

**Web Deployment**: https://vercel.com/new
**CLI Deployment**: Requires Node.js/npm installed first

Choose the method that works best for you!

