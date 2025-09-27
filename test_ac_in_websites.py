#!/usr/bin/env python3
"""
Test script to verify that .ac.in educational websites are properly whitelisted.
"""

import sys
import os
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from ml.predict import PhishingPredictor
import tldextract

def test_ac_in_websites():
    """Test that .ac.in websites are correctly identified as legitimate."""
    
    print("🔍 Testing .ac.in Educational Websites Whitelisting")
    print("=" * 60)
    
    # Test URLs with .ac.in domains
    test_urls = [
        ("https://www.walchandsangli.ac.in/", "Walchand College of Engineering"),
        ("https://iitb.ac.in/", "IIT Bombay"),
        ("https://iitm.ac.in/", "IIT Madras"),
        ("https://iisc.ac.in/", "IISc Bangalore"),
        ("https://jnu.ac.in/", "Jawaharlal Nehru University"),
        ("https://du.ac.in/", "Delhi University"),
        ("https://example.ac.in/", "Generic .ac.in domain")
    ]
    
    # Test domain extraction and pattern matching
    print("Domain Analysis:")
    print("-" * 50)
    
    educational_patterns = [
        '.edu', '.ac.in', '.edu.in', '.ernet.in', '.res.in', '.ac.uk', '.edu.au',
        'iit', 'nit', 'iiit', 'iim', 'iisc', 'bits', 'vit', 'university', 'college',
        'school', 'institute', 'academy', 'campus'
    ]
    
    for url, description in test_urls:
        extracted = tldextract.extract(url.lower())
        full_domain = f"{extracted.domain}.{extracted.suffix}".lower()
        
        # Check if it matches educational patterns
        is_educational = any(pattern in full_domain for pattern in educational_patterns)
        
        print(f"{description:<35} | {full_domain:<25} | Educational: {is_educational}")
    
    print("\nWhitelist Testing:")
    print("-" * 50)
    
    # Initialize predictor
    try:
        predictor = PhishingPredictor()
        print("✅ Phishing detection system initialized successfully!")
    except Exception as e:
        print(f"❌ Failed to initialize system: {e}")
        return
    
    # Test whitelist recognition
    total_tests = 0
    passed_tests = 0
    
    for url, description in test_urls:
        total_tests += 1
        try:
            # Test with Hybrid mode (which has pattern matching)
            result, confidence = predictor.predict_url_hybrid(url)
            
            if result == "Legitimate":
                status = "✅"
                passed_tests += 1
            else:
                status = "❌"
            
            print(f"{status} {description:<30} → {result} ({confidence:.1f}%)")
            
        except Exception as e:
            print(f"❌ {description:<30} → Error: {str(e)}")
    
    # Summary
    print(f"\n📊 Test Summary")
    print("=" * 40)
    print(f"Total Tests: {total_tests}")
    print(f"Passed: {passed_tests}")
    print(f"Failed: {total_tests - passed_tests}")
    print(f"Success Rate: {(passed_tests/total_tests)*100:.1f}%")
    
    if passed_tests == total_tests:
        print("\n🎉 Perfect! All .ac.in educational websites correctly identified as legitimate!")
        print("✅ The system is already properly configured to whitelist .ac.in domains.")
    elif (passed_tests/total_tests) >= 0.9:
        print(f"\n✅ Excellent! System working well ({(passed_tests/total_tests)*100:.1f}% success rate)")
    else:
        print(f"\n⚠️ System needs improvement ({(passed_tests/total_tests)*100:.1f}% success rate)")

if __name__ == "__main__":
    test_ac_in_websites()