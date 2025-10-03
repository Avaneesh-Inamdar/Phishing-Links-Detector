#!/usr/bin/env python3
"""
Verification script to ensure whitelist consistency across all files.
"""

import sys
import os
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

def check_whitelist_consistency():
    """Check that 'mi' and 'poco' are in all whitelist files."""
    
    print("🔍 Verifying Whitelist Consistency")
    print("=" * 40)
    
    # Check main predict.py
    try:
        from ml.predict import PhishingPredictor
        predictor = PhishingPredictor()
        
        # Check if 'mi' and 'poco' are in the legitimate domains
        # We'll test this by trying to predict URLs with these domains
        test_urls = [
            ("https://mi.com", "mi.com"),
            ("https://poco.com", "poco.com")
        ]
        
        all_passed = True
        for url, domain in test_urls:
            try:
                result, confidence = predictor.predict_url_model_only(url)
                if result == "Legitimate" and confidence >= 90:
                    print(f"✅ {domain} correctly identified as legitimate")
                else:
                    print(f"❌ {domain} not correctly identified. Result: {result}, Confidence: {confidence}")
                    all_passed = False
            except Exception as e:
                print(f"❌ Error testing {domain}: {e}")
                all_passed = False
        
        if all_passed:
            print("\n✅ All domains correctly whitelisted in main predictor!")
        else:
            print("\n❌ Some domains not correctly whitelisted in main predictor!")
            
    except Exception as e:
        print(f"❌ Error loading main predictor: {e}")
    
    # Check check_whitelist.py
    try:
        import tldextract
        from check_whitelist import legitimate_domains
        
        required_domains = ['mi', 'poco']
        all_found = True
        
        for domain in required_domains:
            if domain in legitimate_domains:
                print(f"✅ {domain} found in check_whitelist.py")
            else:
                print(f"❌ {domain} NOT found in check_whitelist.py")
                all_found = False
                
        if all_found:
            print("\n✅ All domains correctly added to check_whitelist.py!")
        else:
            print("\n❌ Some domains missing from check_whitelist.py!")
            
    except Exception as e:
        print(f"❌ Error checking check_whitelist.py: {e}")

if __name__ == "__main__":
    check_whitelist_consistency()