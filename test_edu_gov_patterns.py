#!/usr/bin/env python3
"""
Test script to verify that .edu and .gov.in domains are properly handled by the whitelist.
"""

import sys
import os
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from ml.predict import PhishingPredictor
import tldextract

def test_domain_patterns():
    """Test domain pattern matching for .edu and .gov.in domains."""
    
    print("🔍 Testing .edu and .gov.in Domain Pattern Matching")
    print("=" * 60)
    
    # Test URLs with .edu and .gov.in domains
    test_urls = [
        ("https://harvard.edu", ".edu Domain"),
        ("https://mit.edu", ".edu Domain"),
        ("https://stanford.edu", ".edu Domain"),
        ("https://example.edu", ".edu Domain"),
        ("https://india.gov.in", ".gov.in Domain"),
        ("https://mygov.gov.in", ".gov.in Domain"),
        ("https://incometax.gov.in", ".gov.in Domain"),
        ("https://example.gov.in", ".gov.in Domain"),
        ("https://education.nic.in", ".nic.in Domain"),
        ("https://example.nic.in", ".nic.in Domain")
    ]
    
    # Test domain extraction
    print("Domain Extraction Results:")
    print("-" * 40)
    for url, category in test_urls:
        extracted = tldextract.extract(url)
        full_domain = f"{extracted.domain}.{extracted.suffix}".lower()
        print(f"{category:<15} | {url:<25} -> {full_domain}")
    
    print("\nWhitelist Testing:")
    print("-" * 40)
    
    # Initialize predictor
    try:
        predictor = PhishingPredictor()
        print("✅ System initialized successfully!")
    except Exception as e:
        print(f"❌ Failed to initialize system: {e}")
        return
    
    # Test whitelist recognition
    total_tests = 0
    passed_tests = 0
    
    for url, category in test_urls:
        total_tests += 1
        try:
            result, confidence = predictor.predict_url_model_only(url)
            
            if result == "Legitimate":
                status = "✅"
                passed_tests += 1
            else:
                status = "❌"
            
            print(f"{status} {category:<15} | {url:<25} → {result} ({confidence:.1f}%)")
            
        except Exception as e:
            print(f"❌ {category:<15} | {url:<25} → Error: {str(e)}")
    
    # Summary
    print(f"\n📊 Test Summary")
    print("=" * 40)
    print(f"Total Tests: {total_tests}")
    print(f"Passed: {passed_tests}")
    print(f"Failed: {total_tests - passed_tests}")
    print(f"Success Rate: {(passed_tests/total_tests)*100:.1f}%")
    
    if passed_tests == total_tests:
        print("\n🎉 Perfect! All .edu and .gov.in domains correctly identified as legitimate!")
    elif (passed_tests/total_tests) >= 0.9:
        print(f"\n✅ Excellent! System working well ({(passed_tests/total_tests)*100:.1f}% success rate)")
    else:
        print(f"\n⚠️ System needs improvement ({(passed_tests/total_tests)*100:.1f}% success rate)")

if __name__ == "__main__":
    test_domain_patterns()