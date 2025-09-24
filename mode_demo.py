"""
Demo script showing the difference between model_only and hybrid modes.
"""

import os
import sys

# Add the current directory to Python path
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from ml.predict import PhishingPredictor

def demo_modes():
    """Demo showing the difference between model_only and hybrid modes."""
    print("Mode Selection Demo")
    print("=" * 40)
    
    # Initialize predictor
    try:
        predictor = PhishingPredictor()
        print("\n✅ Model loaded successfully!")
        
        if predictor.hybrid_analysis:
            print("✅ Hybrid Analysis API integration enabled!")
        else:
            print("⚠️  Hybrid Analysis API integration not enabled.")
            print("To enable Hybrid Analysis, set the HYBRID_ANALYSIS_API_KEY environment variable.")
    except Exception as e:
        print(f"❌ Failed to load model: {e}")
        return
    
    print("\n" + "=" * 40)
    print("MODE COMPARISON")
    print("=" * 40)
    
    # Test URL that might benefit from Hybrid Analysis
    test_url = "http://suspicious-site-with-random-chars-12345.com/login"
    
    print(f"\nTesting URL: {test_url}")
    print("-" * 40)
    
    # Test in model_only mode
    print("\n1. MODEL_ONLY MODE:")
    predictor.set_mode('model_only')
    result, confidence = predictor.predict_url(test_url)
    print(f"   Result: {result} (Confidence: {confidence:.2f}%)")
    print("   → Uses only your trained ML model")
    print("   → No external API calls")
    print("   → Faster but potentially less accurate for uncertain cases")
    
    # Test in hybrid mode
    print("\n2. HYBRID MODE:")
    predictor.set_mode('hybrid')
    result, confidence = predictor.predict_url(test_url)
    print(f"   Result: {result} (Confidence: {confidence:.2f}%)")
    if predictor.hybrid_analysis:
        print("   → Uses your trained ML model first")
        print("   → If confidence is low, uses Hybrid Analysis for confirmation")
        print("   → More accurate but slower due to external API calls")
    else:
        print("   → Would use Hybrid Analysis if API key was provided")
        print("   → Currently falls back to ML model only")

    print("\n" + "=" * 40)
    print("WHEN TO USE EACH MODE")
    print("=" * 40)
    
    print("\nMODEL_ONLY MODE:")
    print("  ✅ Faster predictions (no external API calls)")
    print("  ✅ Works offline")
    print("  ✅ No dependency on external services")
    print("  ✅ Good for high-confidence predictions")
    print("  ❌ May miss new phishing techniques")
    print("  ❌ Lower accuracy for uncertain cases")
    
    print("\nHYBRID MODE:")
    print("  ✅ Higher accuracy for uncertain cases")
    print("  ✅ Detects new phishing techniques")
    print("  ✅ Uses professional malware analysis")
    print("  ✅ Good for critical security decisions")
    print("  ❌ Requires internet connection")
    print("  ❌ Slower due to external API calls")
    print("  ❌ Depends on external service availability")

if __name__ == "__main__":
    demo_modes()