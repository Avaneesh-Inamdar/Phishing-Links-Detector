"""
Test script for Hybrid Analysis API integration.
"""

import os
import sys

# Add the current directory to Python path
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from ml.hybrid_analysis import HybridAnalysisAPI

def test_hybrid_analysis():
    """Test the Hybrid Analysis API integration."""
    # Get API key from environment variable
    api_key = os.environ.get('HYBRID_ANALYSIS_API_KEY')
    
    if not api_key:
        print("HYBRID_ANALYSIS_API_KEY environment variable not set.")
        print("Please set it to test the Hybrid Analysis integration.")
        return
    
    print("Initializing Hybrid Analysis API...")
    ha = HybridAnalysisAPI(api_key)
    
    # Test with a known safe URL
    test_url = "https://www.google.com"
    print(f"Testing with URL: {test_url}")
    
    result = ha.analyze_url(test_url, max_wait_time=60)
    print(f"Analysis result: {result}")
    
    if result['success']:
        print(f"URL is {'malicious' if result['malicious'] else 'safe'}")
        print(f"Confidence: {result['confidence']}%")
    else:
        print(f"Analysis failed: {result.get('error', 'Unknown error')}")

if __name__ == "__main__":
    test_hybrid_analysis()