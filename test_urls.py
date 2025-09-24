"""
Test script for phishing URL detection with mode selection.
"""

import os
import sys

# Add the current directory to Python path
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from ml.predict import PhishingPredictor

def test_urls():
    """Test the phishing detection with sample URLs in both modes."""
    print("Testing Phishing URL Detection with Mode Selection")
    print("=" * 60)
    
    # Initialize predictor
    try:
        predictor = PhishingPredictor()
        print("✅ Model loaded successfully!")
        
        if predictor.hybrid_analysis:
            print("✅ Hybrid Analysis API integration enabled!")
        else:
            print("⚠️  Hybrid Analysis API integration not enabled (missing API key)")
    except Exception as e:
        print(f"❌ Failed to load model: {e}")
        return
    
    # Test URLs
    test_urls = [
        "https://www.google.com",
        "https://github.com",
        "https://www.microsoft.com",
        "http://example-phishing-site.com",
        "https://paypal.com.security.account.update.example.com"
    ]
    
    print("\nTesting in MODEL_ONLY mode:")
    print("-" * 40)
    predictor.set_mode('model_only')
    
    for url in test_urls:
        try:
            print(f"URL: {url}")
            result, confidence = predictor.predict_url(url)
            print(f"Result: {result} (Confidence: {confidence:.2f}%)")
            print("-" * 40)
        except Exception as e:
            print(f"Error analyzing {url}: {e}")
    
    print("\nTesting in HYBRID mode:")
    print("-" * 40)
    predictor.set_mode('hybrid')
    
    for url in test_urls:
        try:
            print(f"URL: {url}")
            result, confidence = predictor.predict_url(url)
            print(f"Result: {result} (Confidence: {confidence:.2f}%)")
            print("-" * 40)
        except Exception as e:
            print(f"Error analyzing {url}: {e}")

if __name__ == "__main__":
    test_urls()