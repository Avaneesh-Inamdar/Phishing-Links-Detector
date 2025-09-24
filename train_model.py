#!/usr/bin/env python3
"""
Simple script to train the phishing detection model.
Run this script to train and save the model before using the web app.
"""

import sys
import os

# Add current directory to path
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from ml.train import main

if __name__ == "__main__":
    print("🚀 Starting Phishing URL Detection Model Training")
    print("=" * 60)
    main()
    print("=" * 60)
    print("✅ Training completed! You can now run the web app with: python app.py")