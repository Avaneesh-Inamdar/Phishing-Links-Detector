#!/usr/bin/env python3
"""
Test script to verify the hybrid mode is working correctly.
"""

import sys
import os

# Add current directory to path
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from ml.predict import PhishingPredictor

def test_hybrid_mode():
    """Test the hybrid mode predictions."""
    print("🧪 Testing Hybrid Mode Predictions")
    print("=" * 50)
    
    # Initialize predictor
    predictor = PhishingPredictor()
    
    # Test URLs
    test_urls = [
        "https://www.google.com",
        "https://www.facebook.com", 
        "http://192.168.1.1/admin/login.php",
        "http://secure-paypal-update.tk/login",
        "https://www.g00gle.com/signin"
    ]
    
    print("\nTesting Hybrid Mode:")
    print("-" * 50)
    
    for url in test_urls:
        try:
            result = predictor.predict_url_hybrid(url)
            if result is None:
                print(f"❌ ERROR: predict_url_hybrid returned None for {url}")
            else:
                result_str, confidence = result
                print(f"✅ URL: {url}")
                print(f"   Result: {result_str} (Confidence: {confidence:.1f}%)")
                print("-" * 30)
                
        except Exception as e:
            print(f"❌ Error testing {url}: {e}")
            print("-" * 30)

if __name__ == "__main__":
    test_hybrid_mode()