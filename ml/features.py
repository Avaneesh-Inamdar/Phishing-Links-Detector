"""
Feature extraction module for phishing URL detection.
Extracts various features from URLs to help identify phishing attempts.
"""

import re
import urllib.parse
from typing import Dict, Any
import tldextract


def extract_features(url: str) -> Dict[str, Any]:
    """
    Extract robust features from a URL for phishing detection.
    Focus on features that actually distinguish phishing from legitimate sites.
    
    Args:
        url (str): The URL to analyze
        
    Returns:
        Dict[str, Any]: Dictionary containing extracted features
    """
    features = {}
    
    # Basic URL preprocessing
    original_url = url.strip()
    url_lower = original_url.lower()
    if not url_lower.startswith(('http://', 'https://')):
        url_lower = 'http://' + url_lower
    
    try:
        parsed_url = urllib.parse.urlparse(url_lower)
        domain = parsed_url.netloc
        path = parsed_url.path
        query = parsed_url.query
        
        # Extract domain components using tldextract
        extracted = tldextract.extract(url_lower)
        subdomain = extracted.subdomain
        domain_name = extracted.domain
        suffix = extracted.suffix
        
    except Exception:
        # If URL parsing fails, use basic parsing
        domain = url_lower.replace('http://', '').replace('https://', '').split('/')[0]
        path = ""
        query = ""
        subdomain = ""
        domain_name = domain.split('.')[0] if '.' in domain else domain
        suffix = ""
    
    # Comprehensive whitelist of legitimate domains
    legitimate_domains = {
        # Tech Giants
        'google', 'youtube', 'facebook', 'amazon', 'wikipedia', 'twitter', 'instagram',
        'linkedin', 'reddit', 'netflix', 'microsoft', 'apple', 'github', 'stackoverflow',
        'yahoo', 'bing', 'ebay', 'cnn', 'bbc', 'nytimes', 'washingtonpost', 'espn',
        'gmail', 'outlook', 'dropbox', 'spotify', 'adobe', 'salesforce', 'zoom',
        
        # Browsers & Tools
        'mozilla', 'firefox', 'chrome', 'opera', 'brave', 'edge', 'safari',
        'wordpress', 'blogger', 'medium', 'tumblr', 'pinterest', 'snapchat', 'tiktok',
        'whatsapp', 'telegram', 'discord', 'slack', 'skype', 'teams',
        
        # Financial & Payment Services
        'paypal', 'stripe', 'visa', 'mastercard', 'amex', 'discover', 'razorpay', 'paytm',
        'phonepe', 'googlepay', 'amazonpay', 'mobikwik', 'freecharge', 'bharatpe',
        'cred', 'jupiter', 'niyo', 'fi', 'slice', 'uni',
        
        # Major Banks (India)
        'sbi', 'hdfcbank', 'icicibank', 'axisbank', 'kotakbank', 'yesbank',
        'pnb', 'bankofbaroda', 'canarabank', 'unionbank', 'indianbank',
        'idfcfirstbank', 'rbl', 'federalbank', 'southindianbank', 'karurbank',
        'cityunionbank', 'dhanbank', 'bandhanbank', 'aubank', 'csb',
        
        # Major Banks (Global)
        'chase', 'wellsfargo', 'bankofamerica', 'citibank', 'usbank',
        'jpmorgan', 'goldmansachs', 'morganstanley', 'hsbc', 'barclays',
        'lloyds', 'santander', 'bnpparibas', 'deutschebank', 'ubs',
        
        # Government Websites (India)
        'gov', 'nic', 'india', 'mygov', 'digitalindia', 'aadhaar', 'uidai',
        'incometax', 'gst', 'epfo', 'esic', 'nsdl', 'cdsl', 'sebi',
        'rbi', 'irdai', 'pfrda', 'nabard', 'sidbi', 'exim',
        'cbdt', 'cbic', 'dgft', 'fema', 'pmjay', 'nha',
        'cowin', 'digilocker', 'umang', 'parivahan', 'vahan',
        'irctc', 'indianrailways', 'airindia', 'psu', 'cpse',
        
        # Government Websites (Global)
        'usa', 'uk', 'canada', 'australia', 'singapore', 'uae',
        'irs', 'ssa', 'medicare', 'medicaid', 'usps', 'dmv',
        'nhs', 'hmrc', 'dvla', 'passport', 'immigration',
        
        # Educational Institutions
        'mit', 'harvard', 'stanford', 'berkeley', 'caltech', 'princeton',
        'yale', 'columbia', 'cornell', 'upenn', 'dartmouth', 'brown',
        'iit', 'iisc', 'iim', 'nit', 'iiit', 'bits', 'vit', 'srm',
        'du', 'jnu', 'bhu', 'amu', 'jamia', 'tiss', 'isi', 'jmi',
        
        # Cloud & Infrastructure
        'cloudflare', 'aws', 'azure', 'gcp', 'heroku', 'digitalocean',
        'ubuntu', 'debian', 'redhat', 'centos', 'fedora', 'opensuse',
        'linuxmint', 'manjaro', 'arch', 'elementary', 'zorin', 'suse',
        'kde', 'gnome',
        'nvidia', 'intel', 'amd', 'qualcomm', 'samsung', 'lg', 'sony',
        
        # E-commerce (Global)
        'walmart', 'target', 'bestbuy', 'homedepot', 'lowes', 'costco',
        'alibaba', 'aliexpress', 'shopify', 'etsy', 'mercadolibre',
        
        # E-commerce & Services (India)
        'flipkart', 'myntra', 'ajio', 'nykaa', 'bigbasket', 'grofers', 'blinkit',
        'swiggy', 'zomato', 'dunzo', 'urbancompany', 'bookmyshow', 'makemytrip',
        'goibibo', 'cleartrip', 'redbus', 'ola', 'rapido', 'zepto',
        'jiomart', 'reliancedigital', 'croma', 'vijaysales', 'tatacliq',
        'policybazaar', 'coverfox', 'acko', 'digit', 'bajajfinserv', 'olx',
        
        # Insurance Companies
        'lic', 'sbi', 'hdfc', 'icici', 'bajaj', 'tata', 'reliance',
        'birla', 'max', 'star', 'oriental', 'national', 'united',
        'allstate', 'geico', 'progressive', 'statefarm', 'farmers',
        
        # Mutual Funds & Investment
        'amfiindia', 'valueresearch', 'morningstar', 'moneycontrol', 'economictimes',
        'zerodha', 'upstox', 'groww', 'angelone', 'icicidirect',
        'hdfcsec', 'kotaksecurities', 'sbicap', 'motilal', 'sharekhan',
        
        # Transportation & Logistics
        'usps', 'fedex', 'ups', 'dhl', 'airbnb', 'uber', 'lyft',
        'booking', 'expedia', 'hotels', 'trivago', 'agoda',
        'indianrailways', 'irctc', 'airindia', 'indigo', 'spicejet',
        'vistara', 'goair', 'akasaair', 'alliance', 'trujet',
        
        # Gaming & Entertainment
        'steam', 'epic', 'origin', 'uplay', 'battlenet', 'gog', 'roblox',
        'twitch', 'vimeo', 'dailymotion', 'hulu', 'disneyplus', 'hbo',
        'hotstar', 'sonyliv', 'voot', 'altbalaji', 'mxplayer', 'jiosaavn',
        'gaana', 'wynk', 'hungama', 'saavn', 'spotify',
        
        # Education & News (India)
        'byjus', 'unacademy', 'vedantu', 'toppr', 'whitehatjr', 'coursera',
        'udemy', 'khan', 'edx', 'swayam', 'nptel', 'ignou', 'nios',
        'timesofindia', 'hindustantimes', 'indianexpress', 'thehindu',
        'ndtv', 'republicworld', 'zeenews', 'aajtak', 'news18',
        'livemint', 'businessstandard', 'financialexpress', 'moneycontrol',
        
        # Telecom (India)
        'jio', 'airtel', 'vi', 'bsnl', 'mtnl', 'idea', 'vodafone',
        
        # Healthcare
        'who', 'cdc', 'nih', 'fda', 'mohfw', 'icmr', 'aiims',
        'apollo', 'fortis', 'max', 'manipal', 'narayana', 'aster',
        'practo', '1mg', 'netmeds', 'pharmeasy', 'medlife', 'apollo247',
        
        # Utilities & Services
        'adani', 'tata', 'reliance', 'ongc', 'ntpc', 'powergrid',
        'coal', 'indianoil', 'bpcl', 'hpcl', 'gail', 'sail',
        'bhel', 'hal', 'bel', 'rites', 'ircon', 'nbcc'
    }
    
    # Check if it's a known legitimate domain (this should be a STRONG indicator of legitimacy)
    features['is_legitimate_domain'] = 1 if domain_name in legitimate_domains else 0
    
    # URL length features (phishing URLs tend to be longer)
    features['url_length'] = len(original_url)
    features['url_very_long'] = 1 if len(original_url) > 75 else 0
    features['url_extremely_long'] = 1 if len(original_url) > 150 else 0
    
    # Domain analysis
    features['domain_length'] = len(domain)
    features['domain_very_long'] = 1 if len(domain) > 30 else 0
    
    # Protocol analysis
    features['uses_https'] = 1 if original_url.lower().startswith('https://') else 0
    features['uses_http'] = 1 if original_url.lower().startswith('http://') else 0
    
    # IP address instead of domain (major red flag)
    ip_pattern = r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b'
    features['uses_ip_address'] = 1 if re.search(ip_pattern, domain) else 0
    
    # Subdomain analysis (many subdomains can be suspicious)
    subdomain_count = len(subdomain.split('.')) if subdomain else 0
    features['subdomain_count'] = subdomain_count
    features['many_subdomains'] = 1 if subdomain_count > 2 else 0
    features['has_www'] = 1 if subdomain == 'www' else 0
    
    # Suspicious characters in domain
    features['domain_has_dash'] = 1 if '-' in domain_name else 0
    features['domain_has_numbers'] = 1 if any(c.isdigit() for c in domain_name) else 0
    features['domain_has_underscore'] = 1 if '_' in domain else 0
    
    # @ symbol in URL (redirect trick)
    features['has_at_symbol'] = 1 if '@' in original_url else 0
    
    # Double slash in path (redirect trick)
    features['double_slash_redirect'] = 1 if '//' in path else 0
    
    # Dots in domain (excluding normal ones)
    dot_count = domain.count('.')
    features['dot_count'] = dot_count
    features['excessive_dots'] = 1 if dot_count > 3 else 0
    
    # Path analysis
    features['path_length'] = len(path)
    features['long_path'] = 1 if len(path) > 50 else 0
    path_segments = [p for p in path.split('/') if p]
    features['path_depth'] = len(path_segments)
    features['deep_path'] = 1 if len(path_segments) > 4 else 0
    
    # Query parameters
    features['has_query'] = 1 if query else 0
    features['query_length'] = len(query)
    features['long_query'] = 1 if len(query) > 100 else 0
    
    # Suspicious words in URL (but be careful not to flag legitimate uses)
    # Focus on words that are commonly used in phishing contexts
    phishing_keywords = [
        'secure-', 'account-', 'verify-', 'update-', 'confirm-', 'suspended',
        'limited', 'alert', 'warning', 'urgent', 'expire', 'click-here',
        'signin-', 'login-', 'bank-', 'paypal-', 'amazon-', 'microsoft-'
    ]
    
    # Only count if these words appear with suspicious patterns (like with dashes)
    features['suspicious_keywords'] = sum(1 for word in phishing_keywords if word in url_lower)
    features['has_suspicious_keywords'] = 1 if features['suspicious_keywords'] > 0 else 0
    
    # URL shortening services
    shortener_domains = [
        'bit.ly', 'tinyurl.com', 'goo.gl', 't.co', 'short.link', 'ow.ly',
        'buff.ly', 'adf.ly', 'bl.ink', 'rebrand.ly', 'tiny.cc'
    ]
    features['is_url_shortener'] = 1 if any(shortener in domain for shortener in shortener_domains) else 0
    
    # Suspicious TLDs
    suspicious_tlds = ['.tk', '.ml', '.ga', '.cf', '.click', '.download', '.link', '.zip']
    features['suspicious_tld'] = 1 if any(tld in suffix.lower() for tld in suspicious_tlds) else 0
    
    # Character analysis
    features['digit_count'] = sum(c.isdigit() for c in original_url)
    features['digit_ratio'] = features['digit_count'] / len(original_url) if len(original_url) > 0 else 0
    features['high_digit_ratio'] = 1 if features['digit_ratio'] > 0.1 else 0
    
    # Special character analysis
    special_chars = ['%', '&', '?', '=', '+', '*', '!', '#', '$', '^', '~']
    features['special_char_count'] = sum(original_url.count(char) for char in special_chars)
    features['special_char_ratio'] = features['special_char_count'] / len(original_url) if len(original_url) > 0 else 0
    features['high_special_char_ratio'] = 1 if features['special_char_ratio'] > 0.05 else 0
    
    # Domain entropy (randomness - phishing domains often look random)
    def calculate_entropy(text):
        if not text or len(text) < 2:
            return 0
        from collections import Counter
        import math
        counter = Counter(text.lower())
        length = len(text)
        entropy = -sum((count/length) * math.log2(count/length) for count in counter.values())
        return entropy
    
    domain_entropy = calculate_entropy(domain_name)
    features['domain_entropy'] = domain_entropy
    features['high_domain_entropy'] = 1 if domain_entropy > 3.5 else 0
    features['low_domain_entropy'] = 1 if domain_entropy < 2.0 else 0
    
    # Homograph/lookalike detection
    suspicious_chars = ['а', 'е', 'о', 'р', 'с', 'х', 'у', 'і', 'ο', 'а']  # Cyrillic lookalikes
    features['has_homograph_chars'] = 1 if any(char in original_url for char in suspicious_chars) else 0
    
    # Brand impersonation patterns (common phishing technique)
    major_brands = ['google', 'facebook', 'amazon', 'microsoft', 'apple', 'paypal', 'ebay']
    brand_variations = []
    for brand in major_brands:
        # Look for variations like g00gle, fac3book, etc.
        if brand in domain_name and domain_name != brand:
            brand_variations.append(brand)
    
    features['brand_impersonation'] = 1 if brand_variations else 0
    
    # Port number in URL (unusual for normal browsing)
    features['has_port'] = 1 if ':' in domain and not domain.startswith('http') else 0
    
    return features


def extract_features_batch(urls: list) -> list:
    """
    Extract features from a batch of URLs.
    
    Args:
        urls (list): List of URLs to process
        
    Returns:
        list: List of feature dictionaries
    """
    return [extract_features(url) for url in urls]