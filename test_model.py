#!/usr/bin/env python3
"""
Simple test script to verify the phishing detection model is working correctly.
"""

import sys
import os

# Add current directory to path
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from ml.predict import PhishingPredictor

def test_model():
    """Test the model with various URLs."""
    print("🧪 Testing Phishing URL Detection Model")
    print("=" * 50)
    
    try:
        predictor = PhishingPredictor()
        
        # Test cases
        test_urls = [
            # Global legitimate sites
            ("https://www.google.com", "Should be Legitimate"),
            ("https://www.facebook.com", "Should be Legitimate"),
            ("https://www.amazon.com", "Should be Legitimate"),
            ("https://www.github.com", "Should be Legitimate"),
            ("https://www.firefox.com", "Should be Legitimate"),
            ("https://www.mozilla.org", "Should be Legitimate"),
            ("https://www.paypal.com", "Should be Legitimate"),
            
            # Indian E-commerce & Services
            ("https://www.swiggy.com", "Should be Legitimate"),
            ("https://www.zomato.com", "Should be Legitimate"),
            ("https://www.blinkit.com", "Should be Legitimate"),
            ("https://www.flipkart.com", "Should be Legitimate"),
            ("https://www.myntra.com", "Should be Legitimate"),
            ("https://www.paytm.com", "Should be Legitimate"),
            ("https://www.phonepe.com", "Should be Legitimate"),
            
            # Banking websites
            ("https://www.sbi.co.in", "Should be Legitimate"),
            ("https://www.hdfcbank.com", "Should be Legitimate"),
            ("https://www.icicibank.com", "Should be Legitimate"),
            ("https://www.axisbank.com", "Should be Legitimate"),
            ("https://www.chase.com", "Should be Legitimate"),
            ("https://www.wellsfargo.com", "Should be Legitimate"),
            
            # Government websites
            ("https://www.india.gov.in", "Should be Legitimate"),
            ("https://www.incometax.gov.in", "Should be Legitimate"),
            ("https://www.uidai.gov.in", "Should be Legitimate"),
            ("https://www.irctc.co.in", "Should be Legitimate"),
            ("https://www.usa.gov", "Should be Legitimate"),
            ("https://www.irs.gov", "Should be Legitimate"),
            
            # Educational institutions
            ("https://www.mit.edu", "Should be Legitimate"),
            ("https://www.harvard.edu", "Should be Legitimate"),
            ("https://www.iitb.ac.in", "Should be Legitimate"),
            
            # Phishing examples
            ("http://192.168.1.1/admin/login.php", "Should be Phishing"),
            ("http://secure-paypal-update.tk/login", "Should be Phishing"),
            ("https://www.g00gle.com/signin", "Should be Phishing"),
            ("http://bit.ly/suspicious-link", "Should be Phishing"),
            ("https://amazon-security-alert.com/update", "Should be Phishing"),
            ("https://paypal-verification-required.com", "Should be Phishing"),
            ("https://swiggy-offers-fake.com", "Should be Phishing"),
            ("https://sbi-bank-security-alert.com", "Should be Phishing"),
            ("https://fake-government-portal.com", "Should be Phishing")
        ]
        
        correct = 0
        total = len(test_urls)
        
        for url, expected_note in test_urls:
            try:
                result, confidence = predictor.predict_url(url)
                
                # Determine if prediction is likely correct
                is_correct = (
                    ("Legitimate" in expected_note and result == "Legitimate") or
                    ("Phishing" in expected_note and result == "Phishing")
                )
                
                if is_correct:
                    correct += 1
                    status = "✅"
                else:
                    status = "❌"
                
                print(f"{status} {url[:50]:<50} | {result:<10} | {confidence:.1f}% | {expected_note}")
                
            except Exception as e:
                print(f"❌ {url[:50]:<50} | ERROR: {str(e)}")
        
        accuracy = (correct / total) * 100
        print("\n" + "=" * 50)
        print(f"Test Results: {correct}/{total} correct ({accuracy:.1f}%)")
        
        if accuracy >= 70:
            print("✅ Model passed basic functionality test!")
        else:
            print("⚠️  Model needs improvement.")
            
    except Exception as e:
        print(f"❌ Error loading model: {e}")
        print("Make sure you've trained the model first: python train_model.py")

if __name__ == "__main__":
    test_model()