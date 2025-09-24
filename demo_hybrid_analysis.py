"""
Demo script showing when Hybrid Analysis is used vs. when ML model is used.
"""

import os
import sys

# Add the current directory to Python path
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from ml.predict import PhishingPredictor

def demo_hybrid_analysis():
    """Demo showing when each system is used."""
    print("Hybrid Analysis Integration Demo")
    print("=" * 40)
    
    # Initialize predictor
    try:
        predictor = PhishingPredictor()
        print("\n✅ Model loaded successfully!")
        
        if predictor.hybrid_analysis:
            print("✅ Hybrid Analysis API integration enabled!")
            print("The system will use both ML model and Hybrid Analysis for detection.")
        else:
            print("⚠️  Hybrid Analysis API integration not enabled.")
            print("The system will use only the ML model for detection.")
            print("To enable Hybrid Analysis, set the HYBRID_ANALYSIS_API_KEY environment variable.")
    except Exception as e:
        print(f"❌ Failed to load model: {e}")
        return
    
    print("\n" + "=" * 40)
    print("DEMONSTRATION SCENARIOS")
    print("=" * 40)
    
    # Scenario 1: Known legitimate domain (rule-based)
    print("\n1. Known Legitimate Domain:")
    print("   URL: https://www.google.com")
    result, confidence = predictor.predict_url("https://www.google.com")
    print(f"   Result: {result} (Confidence: {confidence:.2f}%)")
    print("   → Uses rule-based detection (no ML or Hybrid Analysis needed)")
    
    # Scenario 2: High confidence ML prediction
    print("\n2. High Confidence ML Prediction:")
    print("   URL: https://github.com/username/repo")
    result, confidence = predictor.predict_url("https://github.com/username/repo")
    print(f"   Result: {result} (Confidence: {confidence:.2f}%)")
    if predictor.hybrid_analysis:
        print("   → Uses ML model result (high confidence, Hybrid Analysis not needed)")
    else:
        print("   → Uses ML model result")
    
    # Scenario 3: Low confidence ML prediction (triggers Hybrid Analysis)
    print("\n3. Low Confidence ML Prediction:")
    print("   URL: http://suspicious-site-with-random-chars-12345.com/login")
    result, confidence = predictor.predict_url("http://suspicious-site-with-random-chars-12345.com/login")
    print(f"   Result: {result} (Confidence: {confidence:.2f}%)")
    if predictor.hybrid_analysis:
        print("   → Uses ML model first, then Hybrid Analysis for confirmation")
    else:
        print("   → Uses ML model only (Hybrid Analysis not available)")
    
    # Scenario 4: Clear phishing pattern
    print("\n4. Clear Phishing Pattern:")
    print("   URL: https://paypal.com.security.account.update.example.com")
    result, confidence = predictor.predict_url("https://paypal.com.security.account.update.example.com")
    print(f"   Result: {result} (Confidence: {confidence:.2f}%)")
    if predictor.hybrid_analysis:
        print("   → May use Hybrid Analysis for additional verification")
    else:
        print("   → Uses ML model features")

if __name__ == "__main__":
    demo_hybrid_analysis()