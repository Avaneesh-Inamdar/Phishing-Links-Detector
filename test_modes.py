"""
Test script to verify both modes are working correctly.
"""

import os
import sys

# Add the current directory to Python path
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from ml.predict import PhishingPredictor

def test_modes():
    """Test both modes of the phishing detector."""
    print("Testing Phishing URL Detection Modes")
    print("=" * 40)
    
    # Initialize predictor
    try:
        predictor = PhishingPredictor()
        print("✅ Model loaded successfully!")
        
        if predictor.hybrid_analysis:
            print("✅ Hybrid Analysis API integration enabled!")
        else:
            print("⚠️  Hybrid Analysis API integration not enabled")
    except Exception as e:
        print(f"❌ Failed to load model: {e}")
        return
    
    # Test URLs
    test_urls = [
        "https://www.google.com",
        "https://github.com",
        "http://example-phishing-site.com"
    ]
    
    print("\nTesting in MODEL_ONLY mode:")
    print("-" * 30)
    predictor.set_mode('model_only')
    
    for url in test_urls:
        try:
            print(f"URL: {url}")
            result, confidence = predictor.predict_url(url)
            print(f"Result: {result} (Confidence: {confidence:.2f}%)")
            print()
        except Exception as e:
            print(f"Error analyzing {url}: {e}")
    
    print("\nTesting in HYBRID mode:")
    print("-" * 30)
    predictor.set_mode('hybrid')
    
    for url in test_urls:
        try:
            print(f"URL: {url}")
            result, confidence = predictor.predict_url(url)
            print(f"Result: {result} (Confidence: {confidence:.2f}%)")
            print()
        except Exception as e:
            print(f"Error analyzing {url}: {e}")

if __name__ == "__main__":
    test_modes()