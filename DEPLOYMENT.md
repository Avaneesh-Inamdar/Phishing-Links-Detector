# 🚀 Deployment Guide

This guide covers how to deploy the Phishing Detection System securely in different environments.

## 🔐 Environment Variables Setup

### Local Development
1. Copy `.env.example` to `.env`
2. Add your actual API keys to `.env`
3. Never commit `.env` to version control

### Production Deployment

#### Option 1: Heroku
```bash
# Set environment variables in Heroku
heroku config:set HYBRID_ANALYSIS_API_KEY=your_api_key_here
heroku config:set FLASK_ENV=production
heroku config:set SECRET_KEY=your_production_secret_key
```

#### Option 2: Docker
```dockerfile
# In your Dockerfile
ENV HYBRID_ANALYSIS_API_KEY=${HYBRID_ANALYSIS_API_KEY}
ENV FLASK_ENV=production
```

#### Option 3: Linux Server
```bash
# Add to /etc/environment or ~/.bashrc
export HYBRID_ANALYSIS_API_KEY="your_api_key_here"
export FLASK_ENV="production"
```

#### Option 4: Cloud Platforms (AWS, GCP, Azure)
- Use their respective secret management services
- AWS: Systems Manager Parameter Store or Secrets Manager
- GCP: Secret Manager
- Azure: Key Vault

## 🛡️ Security Checklist

### Before Deployment:
- [ ] Remove any hardcoded API keys
- [ ] Verify `.env` is in `.gitignore`
- [ ] Set strong `SECRET_KEY` for production
- [ ] Enable HTTPS in production
- [ ] Set `FLASK_ENV=production`
- [ ] Review all environment variables

### Production Security:
- [ ] Use a reverse proxy (nginx, Apache)
- [ ] Implement rate limiting
- [ ] Add input validation and sanitization
- [ ] Enable logging and monitoring
- [ ] Regular security updates

## 🔄 CI/CD Pipeline

### GitHub Actions Example:
```yaml
name: Deploy
on:
  push:
    branches: [main]

jobs:
  deploy:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v2
      - name: Deploy to production
        env:
          HYBRID_ANALYSIS_API_KEY: ${{ secrets.HYBRID_ANALYSIS_API_KEY }}
        run: |
          # Your deployment commands here
```

### Environment Secrets in GitHub:
1. Go to repository Settings → Secrets and variables → Actions
2. Add `HYBRID_ANALYSIS_API_KEY` as a repository secret
3. Use `${{ secrets.HYBRID_ANALYSIS_API_KEY }}` in workflows

## 📋 Pre-deployment Checklist

- [ ] Train and test the model
- [ ] Verify all dependencies are in `requirements.txt`
- [ ] Test with both `hybrid` and `model_only` modes
- [ ] Check error handling for missing API keys
- [ ] Verify the app works without `.env` file (fallback mode)
- [ ] Test with invalid/expired API keys
- [ ] Performance test with multiple concurrent requests

## 🚨 Troubleshooting

### Common Deployment Issues:

1. **"API key not found" in production:**
   - Verify environment variable is set correctly
   - Check variable name spelling
   - Ensure the deployment platform loaded the variables

2. **App crashes on startup:**
   - Check all required dependencies are installed
   - Verify Python version compatibility
   - Check file permissions

3. **Model not found errors:**
   - Ensure model files are included in deployment
   - Check file paths are correct for the deployment environment
   - Verify model training completed successfully

## 📞 Support

If you encounter deployment issues:
1. Check the logs for specific error messages
2. Verify all environment variables are set
3. Test locally first with the same configuration
4. Check the troubleshooting section in README.md