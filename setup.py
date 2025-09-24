#!/usr/bin/env python3
"""
Setup script for the Phishing Detection System.
Run this script to set up the development environment.
"""

import os
import sys
import subprocess
import shutil

def run_command(command, description):
    """Run a shell command and handle errors."""
    print(f"📦 {description}...")
    try:
        result = subprocess.run(command, shell=True, check=True, capture_output=True, text=True)
        print(f"✅ {description} completed successfully")
        return True
    except subprocess.CalledProcessError as e:
        print(f"❌ {description} failed: {e}")
        print(f"Error output: {e.stderr}")
        return False

def setup_environment():
    """Set up the development environment."""
    print("🚀 Setting up Phishing Detection System Development Environment")
    print("👥 Team ZeroPhish - Walchand College of Engineering, Sangli")
    print("=" * 70)
    
    # Check Python version
    python_version = sys.version_info
    if python_version.major < 3 or (python_version.major == 3 and python_version.minor < 8):
        print("❌ Python 3.8 or higher is required")
        return False
    
    print(f"✅ Python {python_version.major}.{python_version.minor}.{python_version.micro} detected")
    
    # Install requirements
    if not run_command("pip install -r requirements.txt", "Installing Python dependencies"):
        return False
    
    # Check if .env file exists
    if not os.path.exists('.env'):
        print("📝 Creating .env file from template...")
        if os.path.exists('.env.example'):
            shutil.copy('.env.example', '.env')
            print("✅ .env file created from .env.example")
            print("⚠️  Please edit .env file and add your API keys!")
        else:
            print("❌ .env.example file not found")
            return False
    else:
        print("✅ .env file already exists")
    
    # Check if models directory exists
    if not os.path.exists('models'):
        print("📁 Creating models directory...")
        os.makedirs('models')
        print("✅ Models directory created")
        print("ℹ️  Run 'python -m ml.train' to train the model")
    else:
        print("✅ Models directory exists")
    
    print("\n🎉 Setup completed successfully!")
    print("\n📋 Next steps:")
    print("1. Edit .env file and add your Hybrid Analysis API key")
    print("2. Train the model: python -m ml.train")
    print("3. Run the application: python app.py")
    print("4. Access the app at: http://localhost:5000")
    
    return True

if __name__ == "__main__":
    success = setup_environment()
    sys.exit(0 if success else 1)