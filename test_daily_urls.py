#!/usr/bin/env python3
"""
Comprehensive test of the phishing detection system with day-to-day URLs.
This script tests the system with common legitimate and suspicious URLs.
"""

import sys
import os
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from ml.predict import PhishingPredictor

def test_daily_urls():
    """Test the system with common day-to-day URLs."""
    
    print("🔍 Phishing Detection System - Daily URL Test")
    print("👥 Team ZeroPhish - Walchand College of Engineering, Sangli")
    print("=" * 60)
    
    # Initialize predictor
    try:
        predictor = PhishingPredictor(mode='hybrid')
        print("✅ System initialized successfully!")
    except Exception as e:
        print(f"❌ Failed to initialize system: {e}")
        return
    
    print()
    
    # Test categories
    test_categories = {
        "🌐 Social Media & Communication": [
            "https://facebook.com",
            "https://instagram.com", 
            "https://twitter.com",
            "https://linkedin.com",
            "https://youtube.com",
            "https://whatsapp.com",
            "https://telegram.org"
        ],
        
        "🔍 Search Engines": [
            "https://google.com",
            "https://bing.com",
            "https://yahoo.com",
            "https://duckduckgo.com"
        ],
        
        "🛒 E-commerce": [
            "https://amazon.com",
            "https://flipkart.com",
            "https://myntra.com",
            "https://ebay.com",
            "https://alibaba.com"
        ],
        
        "🏦 Banking & Finance": [
            "https://sbi.co.in",
            "https://hdfcbank.com",
            "https://icicibank.com",
            "https://paytm.com",
            "https://phonepe.com"
        ],
        
        "📰 News & Media": [
            "https://cnn.com",
            "https://bbc.com",
            "https://timesofindia.com",
            "https://ndtv.com"
        ],
        
        "💻 Technology": [
            "https://microsoft.com",
            "https://apple.com",
            "https://github.com",
            "https://stackoverflow.com",
            "https://oracle.com"
        ],
        
        "🎓 Education & Learning": [
            "https://coursera.org",
            "https://udemy.com",
            "https://khanacademy.org",
            "https://edx.org"
        ],
        
        "🏛️ Government": [
            "https://india.gov.in",
            "https://mygov.in",
            "https://uidai.gov.in"
        ]
    }
    
    # Test legitimate URLs
    total_tests = 0
    passed_tests = 0
    
    for category, urls in test_categories.items():
        print(f"\n{category}")
        print("-" * 40)
        
        for url in urls:
            total_tests += 1
            try:
                result, confidence = predictor.predict_url(url)
                
                if result == "Legitimate":
                    status = "✅"
                    passed_tests += 1
                else:
                    status = "❌"
                
                print(f"{status} {url:<30} → {result} ({confidence:.1f}%)")
                
            except Exception as e:
                print(f"❌ {url:<30} → Error: {str(e)}")
    
    # Test suspicious URLs
    print(f"\n🚨 Suspicious/Phishing URLs (Should be detected)")
    print("-" * 40)
    
    suspicious_urls = [
        "https://secure-paypal-verify.tk/login",
        "https://amazon-security-update.ml/verify", 
        "https://facebook-security.ga/confirm",
        "https://google-account-verify.cf/login",
        "https://microsoft-update.pw/security",
        "http://192.168.1.100/login",
        "https://phishing-test.com/fake",
        "https://fake-bank.click/login"
    ]
    
    suspicious_detected = 0
    
    for url in suspicious_urls:
        total_tests += 1
        try:
            result, confidence = predictor.predict_url(url)
            
            if result == "Phishing":
                status = "🚨"
                passed_tests += 1
                suspicious_detected += 1
            else:
                status = "⚠️"
            
            print(f"{status} {url:<35} → {result} ({confidence:.1f}%)")
            
        except Exception as e:
            print(f"❌ {url:<35} → Error: {str(e)}")
    
    # Summary
    print(f"\n📊 Test Summary")
    print("=" * 30)
    print(f"Total Tests: {total_tests}")
    print(f"Passed: {passed_tests}")
    print(f"Failed: {total_tests - passed_tests}")
    print(f"Success Rate: {(passed_tests/total_tests)*100:.1f}%")
    print(f"Suspicious URLs Detected: {suspicious_detected}/{len(suspicious_urls)}")
    
    if passed_tests == total_tests:
        print("\n🎉 All tests passed! The system is working correctly.")
    elif (passed_tests/total_tests) >= 0.9:
        print(f"\n✅ System is working well ({(passed_tests/total_tests)*100:.1f}% success rate)")
    else:
        print(f"\n⚠️ System needs improvement ({(passed_tests/total_tests)*100:.1f}% success rate)")
    
    # API Status
    if hasattr(predictor, 'hybrid_analysis') and predictor.hybrid_analysis:
        print("🔗 Hybrid Analysis API: Connected")
    else:
        print("🔗 Hybrid Analysis API: Not connected (using ML model only)")

if __name__ == "__main__":
    test_daily_urls()