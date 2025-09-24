#!/usr/bin/env python3
"""
Comprehensive test of the enhanced phishing detection system.
Tests all major categories: Banks, E-commerce, Government, Day-to-day websites.
"""

import sys
import os
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from ml.predict import PhishingPredictor

def test_comprehensive_whitelist():
    """Test the enhanced whitelist with comprehensive coverage."""
    
    print("🔍 Enhanced Phishing Detection System - Comprehensive Test")
    print("👥 Team ZeroPhish - Walchand College of Engineering, Sangli")
    print("=" * 70)
    
    # Initialize predictor
    try:
        predictor = PhishingPredictor(mode='hybrid')
        print("✅ System initialized successfully!")
    except Exception as e:
        print(f"❌ Failed to initialize system: {e}")
        return
    
    print()
    
    # Comprehensive test categories
    test_categories = {
        "🏦 Major Banks (India)": [
            "https://sbi.co.in",
            "https://hdfcbank.com",
            "https://icicibank.com",
            "https://axisbank.com",
            "https://kotakbank.com",
            "https://pnb.co.in",
            "https://bankofbaroda.in"
        ],
        
        "🏦 Major Banks (Global)": [
            "https://chase.com",
            "https://wellsfargo.com",
            "https://bankofamerica.com",
            "https://citibank.com",
            "https://hsbc.com",
            "https://barclays.com",
            "https://santander.com"
        ],
        
        "🛒 E-commerce (Global)": [
            "https://amazon.com",
            "https://ebay.com",
            "https://walmart.com",
            "https://target.com",
            "https://bestbuy.com",
            "https://alibaba.com",
            "https://shopify.com"
        ],
        
        "🛒 E-commerce (India)": [
            "https://flipkart.com",
            "https://myntra.com",
            "https://bigbasket.com",
            "https://swiggy.com",
            "https://zomato.com",
            "https://bookmyshow.com",
            "https://makemytrip.com"
        ],
        
        "🏛️ Government (India)": [
            "https://india.gov.in",
            "https://mygov.in",
            "https://uidai.gov.in",
            "https://incometax.gov.in",
            "https://epfo.gov.in",
            "https://irctc.co.in"
        ],
        
        "🏛️ Government (Global)": [
            "https://irs.gov",
            "https://ssa.gov",
            "https://usps.com",
            "https://gov.uk",
            "https://canada.ca"
        ],
        
        "💳 Payment Services": [
            "https://paypal.com",
            "https://stripe.com",
            "https://paytm.com",
            "https://phonepe.com",
            "https://razorpay.com",
            "https://visa.com",
            "https://mastercard.com"
        ],
        
        "💻 Tech Giants": [
            "https://google.com",
            "https://microsoft.com",
            "https://apple.com",
            "https://amazon.com",
            "https://facebook.com",
            "https://oracle.com",
            "https://ibm.com",
            "https://nvidia.com",
            "https://tesla.com"
        ],
        
        "🌐 Social Media": [
            "https://facebook.com",
            "https://instagram.com",
            "https://twitter.com",
            "https://linkedin.com",
            "https://youtube.com",
            "https://tiktok.com",
            "https://snapchat.com"
        ],
        
        "📰 News & Media": [
            "https://cnn.com",
            "https://bbc.com",
            "https://nytimes.com",
            "https://timesofindia.com",
            "https://hindustantimes.com",
            "https://ndtv.com"
        ],
        
        "🎓 Education": [
            "https://coursera.org",
            "https://udemy.com",
            "https://khanacademy.org",
            "https://mit.edu",
            "https://harvard.edu",
            "https://stanford.edu"
        ],
        
        "✈️ Airlines & Travel": [
            "https://delta.com",
            "https://united.com",
            "https://american.com",
            "https://airindia.in",
            "https://indigo.in",
            "https://booking.com",
            "https://expedia.com"
        ],
        
        "🎮 Gaming & Entertainment": [
            "https://steam.com",
            "https://netflix.com",
            "https://spotify.com",
            "https://twitch.tv",
            "https://eminem.com",
            "https://taylorswift.com"
        ],
        
        "🏥 Healthcare": [
            "https://who.int",
            "https://cdc.gov",
            "https://mayoclinic.org",
            "https://apollo247.com",
            "https://practo.com",
            "https://1mg.com"
        ],
        
        "📱 Telecom": [
            "https://jio.com",
            "https://airtel.in",
            "https://verizon.com",
            "https://att.com",
            "https://tmobile.com"
        ]
    }
    
    # Test all categories
    total_tests = 0
    passed_tests = 0
    
    for category, urls in test_categories.items():
        print(f"\n{category}")
        print("-" * 50)
        
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
    
    # Summary
    print(f"\n📊 Comprehensive Test Summary")
    print("=" * 40)
    print(f"Total Tests: {total_tests}")
    print(f"Passed: {passed_tests}")
    print(f"Failed: {total_tests - passed_tests}")
    print(f"Success Rate: {(passed_tests/total_tests)*100:.1f}%")
    
    if passed_tests == total_tests:
        print("\n🎉 Perfect! All legitimate websites correctly identified!")
        print("✅ Banks, E-commerce, Government, and Day-to-day websites are all flagged as legitimate.")
    elif (passed_tests/total_tests) >= 0.95:
        print(f"\n✅ Excellent! System working very well ({(passed_tests/total_tests)*100:.1f}% success rate)")
    else:
        print(f"\n⚠️ System needs improvement ({(passed_tests/total_tests)*100:.1f}% success rate)")
    
    print(f"\n🛡️ Enhanced Whitelist Coverage:")
    print(f"   • {len([url for urls in test_categories.values() for url in urls if 'bank' in url.lower() or any(bank in url.lower() for bank in ['sbi', 'hdfc', 'icici', 'chase', 'wells'])])} Banking websites")
    print(f"   • {len([url for urls in test_categories.values() for url in urls if any(ecom in url.lower() for ecom in ['amazon', 'flipkart', 'walmart', 'target', 'shop'])])} E-commerce websites")
    print(f"   • {len([url for urls in test_categories.values() for url in urls if '.gov' in url or 'gov.' in url])} Government websites")
    print(f"   • {total_tests} Total legitimate websites tested")

if __name__ == "__main__":
    test_comprehensive_whitelist()