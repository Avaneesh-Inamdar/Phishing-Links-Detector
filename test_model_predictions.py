#!/usr/bin/env python3
"""
Test script to verify the ML model predictions are working correctly.
"""

import sys
import os

# Add current directory to path
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from ml.predict import PhishingPredictor

def test_predictions():
    """Test the model predictions on various URLs."""
    print("🧪 Testing ML Model Predictions")
    print("=" * 50)
    
    # Initialize predictor
    predictor = PhishingPredictor()
    
    # Test URLs
    test_urls = [
        # Legitimate URLs
        "https://www.google.com",
        "https://www.facebook.com", 
        "https://www.amazon.com",
        "https://www.github.com",
        "https://www.microsoft.com",
        
        # Suspicious/Phishing URLs
        "http://192.168.1.1/admin/login.php",
        "http://secure-paypal-update.tk/login",
        "https://www.g00gle.com/signin",
        "http://bit.ly/suspicious-link",
        "https://amazon-security-alert.com/update",
        "http://www.paypal-security-update.com/login",
        "https://facebook-login-verify.tk/signin"
    ]
    
    print("\nTesting ML Model-Only Mode:")
    print("-" * 50)
    
    correct_predictions = 0
    total_predictions = 0
    
    for url in test_urls:
        try:
            result, confidence = predictor.predict_url_model_only(url)
            print(f"URL: {url}")
            print(f"Result: {result} (Confidence: {confidence:.1f}%)")
            print("-" * 30)
            total_predictions += 1
            
            # Basic validation - legitimate domains should be classified as legitimate
            if any(domain in url.lower() for domain in ['google', 'facebook', 'amazon', 'github', 'microsoft']):
                if result == "Legitimate":
                    correct_predictions += 1
            # Suspicious patterns should be classified as phishing
            elif any(pattern in url.lower() for pattern in ['192.168', 'paypal-', 'g00gle', 'bit.ly', 'security-alert', 'login-verify']):
                if result == "Phishing":
                    correct_predictions += 1
                    
        except Exception as e:
            print(f"Error testing {url}: {e}")
            print("-" * 30)
    
    accuracy = (correct_predictions / total_predictions) * 100 if total_predictions > 0 else 0
    print(f"\nOverall Test Accuracy: {accuracy:.1f}% ({correct_predictions}/{total_predictions})")
    
    if accuracy >= 70:
        print("✅ Model performance is satisfactory (>= 70% accuracy)")
        return True
    else:
        print("❌ Model performance needs improvement (< 70% accuracy)")
        return False

if __name__ == "__main__":
    success = test_predictions()
    if success:
        print("\n🎉 ML Model is ready for use!")
    else:
        print("\n⚠️  ML Model needs further tuning.")