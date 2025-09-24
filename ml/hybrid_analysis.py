"""
Hybrid Analysis API integration for phishing URL detection.
Provides functions to submit URLs for analysis and retrieve results.
"""

import requests
import time
import json
from typing import Dict, Any, Optional

class HybridAnalysisAPI:
    """Class for interacting with the Hybrid Analysis API."""
    
    def __init__(self, api_key: str):
        self.api_key = api_key
        self.base_url = "https://www.hybrid-analysis.com/api/v2"
        self.headers = {
            'User-Agent': 'Falcon Sandbox',
            'api-key': self.api_key,
            'Content-Type': 'application/json'
        }
        print(f"HybridAnalysisAPI initialized with key: {api_key[:10]}...")  # Log first 10 chars for debugging
    
    def submit_url_for_analysis(self, url: str) -> Optional[str]:
        """
        Submit a URL for analysis to Hybrid Analysis.
        
        Args:
            url (str): The URL to analyze
            
        Returns:
            str: Job ID for the submitted analysis, or None if submission failed
        """
        print(f"Submitting URL to Hybrid Analysis: {url}")
        
        # Based on the API documentation and error messages, let's try the correct endpoints
        # First, let's try the quick-scan endpoint with proper payload
        endpoint = f"{self.base_url}/quick-scan/url"
        
        import uuid
        import hashlib
        
        # Generate a proper ID for the scan
        scan_id = str(uuid.uuid4())
        url_hash = hashlib.md5(url.encode()).hexdigest()
        
        # Try different payload formats based on the API documentation
        payloads = [
            # Format 1: Try with proper scan ID
            {"url": url, "scan_type": "all", "id": scan_id},
            
            # Format 2: Try with URL hash as ID
            {"url": url, "scan_type": "all", "id": url_hash},
            
            # Format 3: Try with environment_id and proper ID
            {"url": url, "environment_id": 100, "id": scan_id},
            
            # Format 4: Try with just URL and environment
            {"url": url, "environment_id": 100},
            
            # Format 5: Try minimal payload
            {"url": url},
        ]
        
        for i, payload in enumerate(payloads):
            print(f"Trying payload format {i+1}: {payload}")
            
            try:
                response = requests.post(
                    endpoint, 
                    headers=self.headers, 
                    json=payload,
                    timeout=30
                )
                
                print(f"Submission response status: {response.status_code}")
                if response.text:
                    print(f"Submission response text: {response.text[:500]}...")
                
                if response.status_code in [200, 201]:
                    try:
                        result = response.json()
                        print(f"Submission successful: {result}")
                        
                        # Look for job ID in various possible locations
                        job_id = (result.get('job_id') or 
                                 result.get('id') or 
                                 result.get('sha256') or
                                 result.get('scan_id') or
                                 result.get('data', {}).get('job_id') or
                                 result.get('response', {}).get('job_id'))
                        
                        if job_id:
                            print(f"  → Submitted URL to Hybrid Analysis (Job ID: {job_id})")
                            return job_id
                        else:
                            print(f"  → Submission successful but no job ID found in response")
                            return str(result)
                    except json.JSONDecodeError:
                        print(f"  → Submission successful but response is not JSON")
                        return response.text
                elif response.status_code == 400:
                    print(f"  → Bad request")
                    try:
                        error_result = response.json()
                        print(f"  → Error details: {error_result}")
                    except:
                        pass
                elif response.status_code == 401:
                    print(f"  → Authentication failed. Check API key.")
                    return None
                elif response.status_code == 403:
                    print(f"  → Forbidden - API key may not have permission")
                    return None
                elif response.status_code == 429:
                    print(f"  → Rate limit exceeded")
                    return None
                elif response.status_code == 404:
                    print(f"  → Endpoint not found")
                    break  # Try different endpoint
                else:
                    print(f"  → Endpoint failed with status code: {response.status_code}")
                    
            except Exception as e:
                print(f"  → Error with payload: {str(e)}")
        
        # If the quick-scan endpoint doesn't work, try other endpoints
        other_endpoints = [
            f"{self.base_url}/submit/url-for-analysis",
            f"{self.base_url}/submit/url",
            f"{self.base_url}/submit/url-to-file",
            f"{self.base_url}/overview/url",
        ]
        
        # Use different payloads for other endpoints
        other_payloads = [
            {"url": url, "environment_id": 100},
            {"url": url, "environment_id": "100"},
            {"url": url},
            {"scan_type": "all", "url": url, "environment_id": 100},
        ]
        
        for i, endpoint in enumerate(other_endpoints):
            print(f"Trying endpoint: {endpoint}")
            payload = other_payloads[min(i, len(other_payloads) - 1)]
            print(f"Using payload: {payload}")
            
            try:
                response = requests.post(
                    endpoint, 
                    headers=self.headers, 
                    json=payload,
                    timeout=30
                )
                
                print(f"Submission response status: {response.status_code}")
                if response.text:
                    print(f"Submission response text: {response.text[:500]}...")
                
                if response.status_code in [200, 201]:
                    try:
                        result = response.json()
                        job_id = (result.get('job_id') or 
                                 result.get('id') or 
                                 result.get('sha256') or
                                 result.get('scan_id'))
                        
                        if job_id:
                            print(f"  → Submitted URL to Hybrid Analysis (Job ID: {job_id})")
                            return job_id
                        else:
                            print(f"  → Submission successful but no job ID found in response")
                            return str(result)
                    except json.JSONDecodeError:
                        print(f"  → Submission successful but response is not JSON")
                        return response.text
                elif response.status_code == 400:
                    print(f"  → Bad request")
                    try:
                        error_result = response.json()
                        print(f"  → Error details: {error_result}")
                    except:
                        pass
                elif response.status_code == 401:
                    print(f"  → Authentication failed. Check API key.")
                    return None
                elif response.status_code == 403:
                    print(f"  → Forbidden - API key may not have permission")
                    return None
                elif response.status_code == 429:
                    print(f"  → Rate limit exceeded")
                    return None
                else:
                    print(f"  → Endpoint failed with status code: {response.status_code}")
                    
            except Exception as e:
                print(f"  → Error with endpoint: {str(e)}")
        
        print(f"  → Failed to submit URL for analysis")
        return None
    
    def get_analysis_result(self, job_id: str) -> Optional[Dict[str, Any]]:
        """
        Retrieve the analysis result for a submitted job.
        
        Args:
            job_id (str): The job ID returned from submit_url_for_analysis
            
        Returns:
            dict: Analysis results, or None if retrieval failed
        """
        # Try the most common endpoint for getting results
        endpoints = [
            f"{self.base_url}/report/{job_id}/summary",
            f"{self.base_url}/report/{job_id}",
            f"{self.base_url}/quick-scan/{job_id}"
        ]
        
        print(f"Getting analysis result from Hybrid Analysis for Job ID: {job_id}")
        
        for endpoint in endpoints:
            print(f"Trying endpoint: {endpoint}")
            
            try:
                response = requests.get(endpoint, headers=self.headers, timeout=30)
                
                print(f"Result response status: {response.status_code}")
                if response.text:
                    print(f"Result response text: {response.text[:500]}...")
                
                if response.status_code == 200:
                    try:
                        result = response.json()
                        print(f"  → Retrieved analysis result from Hybrid Analysis (Job ID: {job_id})")
                        return result
                    except json.JSONDecodeError:
                        print(f"  → Result retrieved but response is not JSON")
                        return {"status": "completed", "raw_response": response.text}
                elif response.status_code == 404:
                    # Analysis might still be in progress
                    print(f"  → Analysis still in progress or not found (Job ID: {job_id})")
                    return {"status": "pending"}
                elif response.status_code == 401:
                    print(f"  → Authentication failed. Check API key.")
                    return None
                else:
                    print(f"  → Endpoint failed with status code: {response.status_code}")
                    
            except Exception as e:
                print(f"  → Error getting analysis result: {str(e)}")
        
        return {"status": "pending"}
    
    def is_url_malicious(self, analysis_result: Dict[str, Any]) -> bool:
        """
        Determine if a URL is malicious based on Hybrid Analysis results.
        
        Args:
            analysis_result (dict): The analysis result from get_analysis_result
            
        Returns:
            bool: True if URL is malicious, False otherwise
        """
        if not analysis_result:
            print("  → No analysis result provided")
            return False
            
        # Check for explicit malicious indicators in various possible locations
        # Look for verdict information in the entire result structure
        def check_for_malicious_indicators(data):
            if not isinstance(data, dict):
                return False
                
            # Direct checks
            if data.get('malicious') is True:
                return True
            if data.get('suspicious') is True:
                return True
            if data.get('threat_level', 0) > 0:
                return True
            if isinstance(data.get('verdict'), str) and data['verdict'].lower() in ['malicious', 'suspicious', 'phishing']:
                return True
            if data.get('score', 0) > 50:  # Assuming 0-100 scale
                return True
            if data.get('threat_score', 0) > 50:
                return True
            if data.get('risk_score', 0) > 50:
                return True
                
            # Check tags
            if isinstance(data.get('tags'), list):
                malicious_tags = ['malicious', 'phishing', 'suspicious', 'malware', 'dangerous']
                if any(isinstance(tag, str) and tag.lower() in malicious_tags for tag in data['tags']):
                    return True
            
            # Check verdicts array
            if isinstance(data.get('verdicts'), list):
                if any(isinstance(v, dict) and v.get('malicious', False) for v in data['verdicts']):
                    return True
                    
            return False
        
        # Check the entire result structure recursively
        def recursive_check(data, depth=0):
            if depth > 5:  # Prevent infinite recursion
                return False
                
            if check_for_malicious_indicators(data):
                return True
                
            # Recursively check nested dictionaries
            if isinstance(data, dict):
                for key, value in data.items():
                    if isinstance(value, (dict, list)):
                        if recursive_check(value, depth + 1):
                            return True
            elif isinstance(data, list):
                for item in data:
                    if isinstance(item, (dict, list)):
                        if recursive_check(item, depth + 1):
                            return True
                            
            return False
        
        result = recursive_check(analysis_result)
        print(f"  → Hybrid Analysis result: {'Malicious' if result else 'Safe'}")
        return result
    
    def search_url_analysis(self, url: str) -> Optional[Dict[str, Any]]:
        """
        Search for existing analysis of a URL.
        
        Args:
            url (str): The URL to search for
            
        Returns:
            dict: Search results, or None if search failed
        """
        print(f"Searching for existing analysis of URL: {url}")
        
        # Try different search approaches
        search_endpoints = [
            f"{self.base_url}/search/hash",
            f"{self.base_url}/search/terms",
        ]
        
        import hashlib
        import urllib.parse
        
        # Generate different hashes and search terms
        url_clean = url.strip().lower()
        if not url_clean.startswith(('http://', 'https://')):
            url_clean = 'http://' + url_clean
            
        url_encoded = urllib.parse.quote(url_clean)
        url_sha256 = hashlib.sha256(url_clean.encode()).hexdigest()
        url_md5 = hashlib.md5(url_clean.encode()).hexdigest()
        
        # Extract domain for searching
        try:
            from urllib.parse import urlparse
            parsed = urlparse(url_clean)
            domain = parsed.netloc
        except:
            domain = url_clean
        
        search_queries = [
            # Search by URL directly
            {"filename": url_clean},
            {"filename": url},
            {"url": url_clean},
            {"url": url},
            
            # Search by domain
            {"filename": domain},
            {"domain": domain},
            
            # Search by hash (though this might not work for URLs)
            {"hash": url_sha256},
            {"hash": url_md5},
        ]
        
        for endpoint in search_endpoints:
            for query in search_queries:
                print(f"  → Trying search: {endpoint} with {query}")
                
                try:
                    response = requests.post(endpoint, headers=self.headers, json=query, timeout=30)
                    
                    print(f"    Search response status: {response.status_code}")
                    
                    if response.status_code == 200:
                        try:
                            result = response.json()
                            if result and (isinstance(result, dict) and result.get('data')) or (isinstance(result, list) and len(result) > 0):
                                print(f"    → Found existing analysis!")
                                return result
                        except json.JSONDecodeError:
                            pass
                    elif response.status_code == 404:
                        print(f"    → No existing analysis found")
                        continue
                    else:
                        print(f"    → Search failed with status: {response.status_code}")
                        
                except Exception as e:
                    print(f"    → Search error: {str(e)}")
        
        print(f"  → No existing analysis found for URL")
        return None

    def analyze_url(self, url: str, max_wait_time: int = 120) -> Dict[str, Any]:
        """
        Analyze a URL using Hybrid Analysis (restricted API - search only).
        
        Args:
            url (str): The URL to analyze
            max_wait_time (int): Maximum time to wait for analysis results (seconds)
            
        Returns:
            dict: Analysis results with verdict and confidence
        """
        print(f"Hybrid Analysis checking URL: {url} (Restricted API - search only)")
        
        # With restricted API, we can only search for existing analysis
        existing_result = self.search_url_analysis(url)
        if existing_result:
            print(f"  → Found existing analysis, processing results...")
            malicious = self.is_url_malicious(existing_result)
            confidence = 85 if malicious else 75  # High confidence from existing analysis
            return {
                'success': True,
                'malicious': malicious,
                'confidence': confidence,
                'result_details': existing_result,
                'source': 'existing_analysis'
            }
        
        # For restricted API keys, we cannot submit new analysis
        # Instead, we'll do a basic domain reputation check
        print(f"  → No existing analysis found. Performing basic domain reputation check...")
        
        try:
            from urllib.parse import urlparse
            parsed = urlparse(url.lower())
            domain = parsed.netloc or parsed.path
            
            # Remove www. prefix
            if domain.startswith('www.'):
                domain = domain[4:]
            
            # Basic reputation check based on known patterns
            suspicious_patterns = [
                # Suspicious TLDs
                '.tk', '.ml', '.ga', '.cf', '.pw', '.top', '.click', '.download',
                '.stream', '.science', '.racing', '.review', '.faith', '.cricket',
                '.win', '.date', '.loan', '.men', '.party', '.trade', '.accountant',
                
                # Suspicious patterns in domain names
                'phishing', 'secure-', 'verify-', 'update-', 'confirm-',
                'account-', 'banking-', 'paypal-', 'amazon-', 'microsoft-',
                'google-', 'facebook-', 'apple-', 'netflix-', 'ebay-',
                
                # URL shorteners (can be suspicious)
                'bit.ly', 'tinyurl', 't.co', 'goo.gl', 'ow.ly', 'short.link',
                
                # Suspicious subdomains
                'secure.', 'verify.', 'update.', 'login.', 'account.',
            ]
            
            # Check for suspicious patterns
            is_suspicious = any(pattern in domain for pattern in suspicious_patterns)
            
            # Check for IP addresses (often suspicious)
            import re
            ip_pattern = r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b'
            is_ip = re.search(ip_pattern, domain)
            
            # Check for excessive subdomains (can be suspicious)
            subdomain_count = domain.count('.')
            excessive_subdomains = subdomain_count > 3
            
            # Check for suspicious URL length
            suspicious_length = len(url) > 100
            
            # Calculate suspicion score
            suspicion_score = 0
            if is_suspicious:
                suspicion_score += 40
            if is_ip:
                suspicion_score += 30
            if excessive_subdomains:
                suspicion_score += 20
            if suspicious_length:
                suspicion_score += 10
            
            # Determine result based on suspicion score
            if suspicion_score >= 50:
                print(f"  → Domain appears suspicious (score: {suspicion_score})")
                return {
                    'success': True,
                    'malicious': True,
                    'confidence': min(70, 50 + suspicion_score // 2),
                    'source': 'domain_reputation',
                    'suspicion_factors': {
                        'suspicious_patterns': is_suspicious,
                        'ip_address': bool(is_ip),
                        'excessive_subdomains': excessive_subdomains,
                        'suspicious_length': suspicious_length,
                        'score': suspicion_score
                    }
                }
            else:
                print(f"  → Domain appears legitimate (score: {suspicion_score})")
                return {
                    'success': True,
                    'malicious': False,
                    'confidence': max(40, 80 - suspicion_score),
                    'source': 'domain_reputation',
                    'suspicion_factors': {
                        'suspicious_patterns': is_suspicious,
                        'ip_address': bool(is_ip),
                        'excessive_subdomains': excessive_subdomains,
                        'suspicious_length': suspicious_length,
                        'score': suspicion_score
                    }
                }
                
        except Exception as e:
            print(f"  → Error in domain reputation check: {e}")
            
        # Fallback result
        print(f"  → Returning neutral result (restricted API, no existing analysis)")
        return {
            'success': True,  # Don't fail completely
            'malicious': False,  # Default to safe when uncertain
            'confidence': 35,  # Low confidence
            'source': 'restricted_api_fallback',
            'message': 'Restricted API key - limited analysis capabilities'
        }