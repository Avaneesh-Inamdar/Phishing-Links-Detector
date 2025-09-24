"""
Test script to verify Hybrid Analysis API is working correctly.
"""

import os
import sys

# Add the current directory to Python path
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from ml.hybrid_analysis import HybridAnalysisAPI

def test_hybrid_api():
    """Test the Hybrid Analysis API directly."""
    print("Testing Hybrid Analysis API")
    print("=" * 30)
    
    # Get API key from environment variable
    api_key = os.environ.get('HYBRID_ANALYSIS_API_KEY')
    
    if not api_key:
        print("HYBRID_ANALYSIS_API_KEY environment variable not set.")
        print("Please set it to test the Hybrid Analysis integration.")
        return
    
    print(f"API Key found: {api_key[:10]}...")
    
    # Initialize Hybrid Analysis API
    print("\nInitializing Hybrid Analysis API...")
    ha = HybridAnalysisAPI(api_key)
    
    # Test with a known safe URL
    test_urls = [
        "https://www.google.com",
        "https://github.com",
        "https://www.oracle.com"
    ]
    
    for test_url in test_urls:
        print(f"\nTesting URL: {test_url}")
        print("-" * 40)
        
        try:
            result = ha.analyze_url(test_url, max_wait_time=60)
            print(f"Analysis result: {result}")
            
            if result['success']:
                print(f"URL is {'malicious' if result['malicious'] else 'safe'}")
                print(f"Confidence: {result['confidence']}%")
            else:
                print(f"Analysis failed: {result.get('error', 'Unknown error')}")
        except Exception as e:
            print(f"Error during analysis: {e}")
            import traceback
            traceback.print_exc()

if __name__ == "__main__":
    test_hybrid_api()