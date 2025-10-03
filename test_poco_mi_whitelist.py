#!/usr/bin/env python3
"""
Test script to verify that the new POCO and MI domains are correctly whitelisted.
"""

import sys
import os
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from ml.predict import PhishingPredictor
import tldextract

def test_poco_mi_whitelist():
    """Test that POCO and MI domains are correctly identified as legitimate."""
    
    print("🔍 Testing POCO and MI Domain Whitelisting")
    print("=" * 50)
    
    # Initialize predictor
    try:
        predictor = PhishingPredictor()
        print("✅ System initialized successfully!")
    except Exception as e:
        print(f"❌ Failed to initialize system: {e}")
        return
    
    print()
    
    # Test URLs for POCO and MI domains
    test_urls = [
        ("https://www.mi.com/global/poco/", "POCO (Xiaomi brand)"),
        ("https://mi.com", "MI (Xiaomi)"),
        ("https://www.mi.com", "MI (Xiaomi)"),
        ("https://poco.com", "POCO"),
        ("https://www.poco.com", "POCO"),
    ]
    
    # Test all URLs
    total_tests = 0
    passed_tests = 0
    
    print("Testing URLs:")
    print("-" * 50)
    
    for url, category in test_urls:
        total_tests += 1
        try:
            # Test with ML model mode
            result, confidence = predictor.predict_url_model_only(url)
            
            if result == "Legitimate":
                status = "✅"
                passed_tests += 1
            else:
                status = "❌"
            
            print(f"{status} {category:<20} | {url:<30} → {result} ({confidence:.1f}%)")
            
        except Exception as e:
            print(f"❌ {category:<20} | {url:<30} → Error: {str(e)}")
    
    # Summary
    print(f"\n📊 Test Summary")
    print("=" * 40)
    print(f"Total Tests: {total_tests}")
    print(f"Passed: {passed_tests}")
    print(f"Failed: {total_tests - passed_tests}")
    print(f"Success Rate: {(passed_tests/total_tests)*100:.1f}%")
    
    if passed_tests == total_tests:
        print("\n🎉 Perfect! All POCO and MI domains correctly identified as legitimate!")
    elif (passed_tests/total_tests) >= 0.95:
        print(f"\n✅ Excellent! System working very well ({(passed_tests/total_tests)*100:.1f}% success rate)")
    else:
        print(f"\n⚠️ System needs improvement ({(passed_tests/total_tests)*100:.1f}% success rate)")

if __name__ == "__main__":
    test_poco_mi_whitelist()