#!/usr/bin/env python3
"""
Test script to verify that AI websites work with Hybrid Analysis mode.
"""

import sys
import os
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from ml.predict import PhishingPredictor

def test_ai_websites_hybrid():
    """Test that AI websites are correctly identified as legitimate in Hybrid mode."""
    
    print("🔍 Testing AI Website Whitelisting (Hybrid Mode)")
    print("=" * 50)
    
    # Initialize predictor
    try:
        predictor = PhishingPredictor()
        print("✅ System initialized successfully!")
    except Exception as e:
        print(f"❌ Failed to initialize system: {e}")
        return
    
    print()
    
    # Test a few key AI URLs in Hybrid mode
    test_urls = [
        ("https://chatgpt.com", "AI Platform"),
        ("https://perplexity.ai", "AI Search"),
        ("https://claude.ai", "AI Assistant"),
        ("https://gemini.google.com", "AI Platform"),
    ]
    
    # Test all URLs
    total_tests = 0
    passed_tests = 0
    
    print("Testing AI Websites (Hybrid Mode):")
    print("-" * 50)
    
    for url, category in test_urls:
        total_tests += 1
        try:
            # Test with Hybrid mode
            result, confidence = predictor.predict_url_hybrid(url)
            
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
        print("\n🎉 Perfect! All AI websites correctly identified as legitimate in Hybrid mode!")
    else:
        print(f"\n⚠️ AI website detection needs improvement ({(passed_tests/total_tests)*100:.1f}% success rate)")

if __name__ == "__main__":
    test_ai_websites_hybrid()