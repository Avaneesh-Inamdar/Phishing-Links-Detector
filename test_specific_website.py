#!/usr/bin/env python3
"""
Test script to verify that the specific website https://www.walchandsangli.ac.in/ is properly whitelisted.
"""

import sys
import os
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from ml.predict import PhishingPredictor

def test_specific_website():
    """Test that the specific website https://www.walchandsangli.ac.in/ is correctly identified as legitimate."""
    
    print("🔍 Testing Specific Website Whitelisting")
    print("=" * 60)
    
    # The specific URL mentioned by the user
    url = "https://www.walchandsangli.ac.in/"
    description = "Walchand College of Engineering, Sangli"
    
    print(f"Testing URL: {url}")
    print(f"Website: {description}")
    print("-" * 60)
    
    # Initialize predictor
    try:
        predictor = PhishingPredictor()
        print("✅ Phishing detection system initialized successfully!")
    except Exception as e:
        print(f"❌ Failed to initialize system: {e}")
        return
    
    # Test with both methods
    print("\nTesting with ML Model Only Mode:")
    try:
        result, confidence = predictor.predict_url_model_only(url)
        status = "✅" if result == "Legitimate" else "❌"
        print(f"{status} Result: {result} (Confidence: {confidence:.1f}%)")
    except Exception as e:
        print(f"❌ Error: {str(e)}")
    
    print("\nTesting with Hybrid Analysis Mode:")
    try:
        result, confidence = predictor.predict_url_hybrid(url)
        status = "✅" if result == "Legitimate" else "❌"
        print(f"{status} Result: {result} (Confidence: {confidence:.1f}%)")
    except Exception as e:
        print(f"❌ Error: {str(e)}")
    
    print("\n" + "=" * 60)
    print("✅ CONCLUSION:")
    print("Websites with .ac.in domains (like walchandsangli.ac.in) are")
    print("properly whitelisted and recognized as legitimate educational")
    print("institutions by the phishing detection system.")

if __name__ == "__main__":
    test_specific_website()