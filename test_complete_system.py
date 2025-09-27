#!/usr/bin/env python3
"""
Complete system test to verify both ML model and hybrid modes are working correctly.
"""

import sys
import os

# Add current directory to path
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from ml.predict import PhishingPredictor

def test_complete_system():
    """Test both ML model and hybrid modes."""
    print("🧪 Complete System Test - ML Model + Hybrid Analysis")
    print("=" * 60)
    
    # Initialize predictor
    predictor = PhishingPredictor()
    
    # Test URLs with expected results
    test_cases = [
        # Legitimate URLs (should be classified as Legitimate)
        ("https://www.google.com", "Legitimate"),
        ("https://www.facebook.com", "Legitimate"), 
        ("https://www.amazon.com", "Legitimate"),
        ("https://www.github.com", "Legitimate"),
        ("https://www.microsoft.com", "Legitimate"),
        
        # Phishing URLs (should be classified as Phishing)
        ("http://192.168.1.1/admin/login.php", "Phishing"),
        ("http://secure-paypal-update.tk/login", "Phishing"),
        ("https://www.g00gle.com/signin", "Phishing"),
        ("http://bit.ly/suspicious-link", "Phishing"),
        ("https://amazon-security-alert.com/update", "Phishing"),
    ]
    
    print("\n🤖 Testing ML Model Mode:")
    print("-" * 40)
    
    ml_correct = 0
    ml_total = 0
    
    for url, expected in test_cases:
        try:
            result, confidence = predictor.predict_url_model_only(url)
            is_correct = result == expected
            status = "✅" if is_correct else "❌"
            
            print(f"{status} {url[:50]:<50} | Expected: {expected:<10} | Got: {result:<10} | Conf: {confidence:.1f}%")
            
            if is_correct:
                ml_correct += 1
            ml_total += 1
            
        except Exception as e:
            print(f"❌ ERROR: {url[:50]:<50} | Error: {str(e)}")
            ml_total += 1
    
    ml_accuracy = (ml_correct / ml_total) * 100 if ml_total > 0 else 0
    print(f"\nML Model Accuracy: {ml_accuracy:.1f}% ({ml_correct}/{ml_total})")
    
    print("\n🌐 Testing Hybrid Analysis Mode:")
    print("-" * 40)
    
    hybrid_correct = 0
    hybrid_total = 0
    
    for url, expected in test_cases:
        try:
            result, confidence = predictor.predict_url_hybrid(url)
            is_correct = result == expected
            status = "✅" if is_correct else "❌"
            
            print(f"{status} {url[:50]:<50} | Expected: {expected:<10} | Got: {result:<10} | Conf: {confidence:.1f}%")
            
            if is_correct:
                hybrid_correct += 1
            hybrid_total += 1
            
        except Exception as e:
            print(f"❌ ERROR: {url[:50]:<50} | Error: {str(e)}")
            hybrid_total += 1
    
    hybrid_accuracy = (hybrid_correct / hybrid_total) * 100 if hybrid_total > 0 else 0
    print(f"\nHybrid Analysis Accuracy: {hybrid_accuracy:.1f}% ({hybrid_correct}/{hybrid_total})")
    
    print("\n" + "=" * 60)
    print("📊 FINAL RESULTS:")
    print(f"   • ML Model Accuracy: {ml_accuracy:.1f}%")
    print(f"   • Hybrid Analysis Accuracy: {hybrid_accuracy:.1f}%")
    
    # Check if both modes meet the 70% accuracy requirement
    ml_pass = ml_accuracy >= 70
    hybrid_pass = hybrid_accuracy >= 70
    
    if ml_pass and hybrid_pass:
        print("✅ SYSTEM READY: Both modes achieve >70% accuracy!")
        return True
    else:
        if not ml_pass:
            print(f"❌ ML Model needs improvement: {ml_accuracy:.1f}% < 70%")
        if not hybrid_pass:
            print(f"❌ Hybrid Analysis needs improvement: {hybrid_accuracy:.1f}% < 70%")
        return False

if __name__ == "__main__":
    success = test_complete_system()
    if success:
        print("\n🎉 Phishing Detection System is fully operational!")
        print("   Both ML model and Hybrid Analysis modes are working correctly.")
    else:
        print("\n⚠️  System needs further tuning before deployment.")