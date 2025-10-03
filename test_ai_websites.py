#!/usr/bin/env python3
"""
Test script to verify that AI websites are correctly whitelisted.
"""

import sys
import os
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from ml.predict import PhishingPredictor

def test_ai_websites():
    """Test that AI websites are correctly identified as legitimate."""
    
    print("🔍 Testing AI Website Whitelisting")
    print("=" * 50)
    
    # Initialize predictor
    try:
        predictor = PhishingPredictor()
        print("✅ System initialized successfully!")
    except Exception as e:
        print(f"❌ Failed to initialize system: {e}")
        return
    
    print()
    
    # Test URLs for AI platforms
    test_urls = [
        ("https://chatgpt.com", "AI Platform"),
        ("https://openai.com", "AI Company"),
        ("https://perplexity.ai", "AI Search"),
        ("https://claude.ai", "AI Assistant"),
        ("https://anthropic.com", "AI Company"),
        ("https://gemini.google.com", "AI Platform"),
        ("https://bard.google.com", "AI Assistant"),
        ("https://copilot.microsoft.com", "AI Assistant"),
        ("https://bing.com", "AI Search"),
        ("https://huggingface.co", "AI Community"),
        ("https://kaggle.com", "AI Community"),
        ("https://deepseek.com", "AI Platform"),
        ("https://mistral.ai", "AI Company"),
        ("https://meta.ai", "AI Platform"),
        ("https://poe.com", "AI Platform"),
        ("https://you.com", "AI Search"),
        ("https://phind.com", "AI Search"),
        ("https://forefront.ai", "AI Platform"),
        ("https://character.ai", "AI Platform"),
        ("https://writesonic.com", "AI Writing"),
        ("https://jasper.ai", "AI Writing"),
        ("https://grammarly.com", "AI Writing"),
        ("https://quillbot.com", "AI Writing"),
        ("https://notion.so", "AI Productivity"),
        ("https://obsidian.md", "AI Productivity"),
        ("https://replit.com", "AI Coding"),
        ("https://wolframalpha.com", "AI Computation"),
        ("https://photomath.com", "AI Education"),
    ]
    
    # Test all URLs
    total_tests = 0
    passed_tests = 0
    
    print("Testing AI Websites:")
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
        print("\n🎉 Perfect! All AI websites correctly identified as legitimate!")
    elif (passed_tests/total_tests) >= 0.95:
        print(f"\n✅ Excellent! AI website detection working very well ({(passed_tests/total_tests)*100:.1f}% success rate)")
    else:
        print(f"\n⚠️ AI website detection needs improvement ({(passed_tests/total_tests)*100:.1f}% success rate)")

if __name__ == "__main__":
    test_ai_websites()