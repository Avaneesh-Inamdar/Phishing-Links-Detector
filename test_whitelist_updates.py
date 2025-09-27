#!/usr/bin/env python3
"""
Test script to verify that the whitelist updates are working correctly.
"""

import sys
import os
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from ml.predict import PhishingPredictor

def test_whitelist_updates():
    """Test the updated whitelist with government, educational, and e-commerce domains."""
    
    print("🔍 Testing Whitelist Updates")
    print("=" * 50)
    
    # Initialize predictor
    try:
        predictor = PhishingPredictor()
        print("✅ System initialized successfully!")
    except Exception as e:
        print(f"❌ Failed to initialize system: {e}")
        return
    
    print()
    
    # Test URLs for government, educational, and e-commerce domains
    test_urls = [
        # Government domains
        ("https://timesofindia.indiatimes.com", "Government"),
        ("https://ndtv.com", "Government"),
        ("https://thehindu.com", "Government"),
        ("https://indianexpress.com", "Government"),
        ("https://bbc.com", "Government"),
        ("https://cnn.com", "Government"),
        ("https://reuters.com", "Government"),
        
        # Educational domains
        ("https://coursera.org", "Educational"),
        ("https://udemy.com", "Educational"),
        ("https://khanacademy.org", "Educational"),
        ("https://edx.org", "Educational"),
        ("https://swayam.gov.in", "Educational"),
        ("https://nptel.ac.in", "Educational"),
        ("https://ignou.ac.in", "Educational"),
        ("https://nios.ac.in", "Educational"),
        
        # E-commerce domains
        ("https://flipkart.com", "E-commerce"),
        ("https://myntra.com", "E-commerce"),
        ("https://ajio.com", "E-commerce"),
        ("https://snapdeal.com", "E-commerce"),
        ("https://olx.in", "E-commerce"),
        ("https://quikr.com", "E-commerce"),
        ("https://paytmmall.com", "E-commerce"),
        ("https://shopsy.in", "E-commerce"),
        ("https://meesho.com", "E-commerce"),
        ("https://dealshare.in", "E-commerce"),
        ("https://bulkmro.com", "E-commerce"),
        ("https://shopclues.com", "E-commerce"),
        ("https://pepperfry.com", "E-commerce")
    ]
    
    # Test all URLs
    total_tests = 0
    passed_tests = 0
    
    print("Testing URLs:")
    print("-" * 50)
    
    for url, category in test_urls:
        total_tests += 1
        try:
            result, confidence = predictor.predict_url_model_only(url)
            
            if result == "Legitimate":
                status = "✅"
                passed_tests += 1
            else:
                status = "❌"
            
            print(f"{status} {category:<15} | {url:<30} → {result} ({confidence:.1f}%)")
            
        except Exception as e:
            print(f"❌ {category:<15} | {url:<30} → Error: {str(e)}")
    
    # Summary
    print(f"\n📊 Test Summary")
    print("=" * 40)
    print(f"Total Tests: {total_tests}")
    print(f"Passed: {passed_tests}")
    print(f"Failed: {total_tests - passed_tests}")
    print(f"Success Rate: {(passed_tests/total_tests)*100:.1f}%")
    
    if passed_tests == total_tests:
        print("\n🎉 Perfect! All websites correctly identified as legitimate!")
    elif (passed_tests/total_tests) >= 0.95:
        print(f"\n✅ Excellent! System working very well ({(passed_tests/total_tests)*100:.1f}% success rate)")
    else:
        print(f"\n⚠️ System needs improvement ({(passed_tests/total_tests)*100:.1f}% success rate)")

if __name__ == "__main__":
    test_whitelist_updates()