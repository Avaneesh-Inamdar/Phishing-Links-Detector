"""
Prediction module for phishing URL detection.
Supports both ML model-only mode and Hybrid Analysis mode.
"""

import joblib
import os
import pandas as pd
from dotenv import load_dotenv
from .features import extract_features

# Load environment variables
load_dotenv()

# Add the Hybrid Analysis API import
from .hybrid_analysis import HybridAnalysisAPI


class PhishingPredictor:
    """Class for making predictions on URLs using ML model and/or Hybrid Analysis."""
    
    def __init__(self, model_dir='models'):
        """
        Initialize the predictor with both ML model and Hybrid Analysis capabilities.
        """
        self.model_dir = model_dir
        self.model = None
        self.scaler = None
        self.feature_names = None
        self.hybrid_analysis = None
        self.load_model()
        self.load_hybrid_analysis()
    
    def load_model(self):
        """Load the trained ML model, scaler, and feature names."""
        try:
            model_path = os.path.join(self.model_dir, 'best_model.joblib')
            scaler_path = os.path.join(self.model_dir, 'scaler.joblib')
            features_path = os.path.join(self.model_dir, 'feature_names.joblib')
            
            self.model = joblib.load(model_path)
            self.scaler = joblib.load(scaler_path)
            self.feature_names = joblib.load(features_path)
            
            print("✅ ML Model loaded successfully!")
            
        except FileNotFoundError as e:
            print(f"⚠️  ML Model files not found: {e}")
            print("ML model-only mode will not be available.")
            print("To use ML model mode, run: python -m ml.train")
    
    def load_hybrid_analysis(self):
        """Initialize Hybrid Analysis API."""
        try:
            from config import Config
            api_key = Config.HYBRID_ANALYSIS_API_KEY
        except ImportError:
            # Fallback to environment variable if config module not available
            api_key = os.environ.get('HYBRID_ANALYSIS_API_KEY')
        
        if api_key:
            print(f"Initializing Hybrid Analysis with API key: {api_key[:10]}...")
            self.hybrid_analysis = HybridAnalysisAPI(api_key)
            print("✅ Hybrid Analysis API initialized successfully!")
        else:
            print("⚠️  Hybrid Analysis API key not found.")
            print("Set HYBRID_ANALYSIS_API_KEY environment variable for Hybrid Analysis mode.")
        
        print("🛡️  Phishing Detection System initialized!")
        print("👥 Team ZeroPhish - Walchand College of Engineering, Sangli")
        print(f"   • ML Model available: {self.model is not None}")
        print(f"   • Hybrid Analysis available: {self.hybrid_analysis is not None}")
    
    def reload_hybrid_analysis(self):
        """
        Reload Hybrid Analysis API (useful if API key was added after initialization).
        """
        self.load_hybrid_analysis()
    
    def predict_url_model_only(self, url: str) -> tuple:
        """
        Predict using ML model only + whitelist.
        
        Args:
            url (str): URL to analyze
            
        Returns:
            tuple: (result, confidence) where result is "Phishing" or "Legitimate"
        """
        print(f"🤖 ML Model Mode - Analyzing URL: {url}")
        
        if self.model is None:
            return "Error", 0.0, "ML model not available. Please train the model first."
        
        # Rule-based override for known legitimate domains (always used)
        import tldextract
        try:
            extracted = tldextract.extract(url.lower())
            domain_name = extracted.domain
            full_domain = f"{extracted.domain}.{extracted.suffix}".lower()
            
            # Special patterns for educational institutions and government sites
            educational_patterns = [
                '.edu', '.ac.in', '.edu.in', '.ernet.in', '.res.in', '.ac.uk', '.edu.au',
                'iit', 'nit', 'iiit', 'iim', 'iisc', 'bits', 'vit', 'university', 'college',
                'school', 'institute', 'academy', 'campus'
            ]
            
            government_patterns = [
                '.gov.in', '.nic.in', '.gov', '.mil', '.gov.uk', '.gov.au', '.gov.ca',
                '.gov.sg', '.gov.ae', '.org'
            ]
            
            # Banking patterns - any domain containing these should be treated carefully
            banking_patterns = [
                'bank', 'banking', 'sbi', 'hdfc', 'icici', 'axis', 'kotak', 'pnb',
                'chase', 'wells', 'citi', 'hsbc', 'barclays', 'santander'
            ]
            
            # E-commerce patterns
            ecommerce_patterns = [
                'amazon', 'flipkart', 'ebay', 'walmart', 'target', 'shop', 'store',
                'market', 'buy', 'sell', 'commerce', 'retail'
            ]
            
            # Check for educational institutions
            if any(pattern in full_domain for pattern in educational_patterns):
                print("  → Detected educational institution domain (rule-based)")
                return "Legitimate", 95.0
                
            # Check for government sites
            if any(pattern in full_domain for pattern in government_patterns):
                print("  → Detected government domain (rule-based)")
                return "Legitimate", 95.0
            
            # COMPREHENSIVE WHITELIST - All legitimate domains should be flagged as safe
            legitimate_domains = {
                # ===== TECH GIANTS & MAJOR PLATFORMS =====
                'google', 'youtube', 'facebook', 'amazon', 'wikipedia', 'twitter', 'instagram',
                'linkedin', 'reddit', 'netflix', 'microsoft', 'apple', 'github', 'stackoverflow',
                'yahoo', 'bing', 'duckduckgo', 'ebay', 'gmail', 'outlook', 'dropbox', 'spotify',
                'adobe', 'salesforce', 'zoom', 'oracle', 'ibm', 'intel', 'cisco', 'vmware',
                'dell', 'hp', 'lenovo', 'meta', 'alphabet', 'tesla', 'spacex', 'nvidia',
                
                # ===== BROWSERS & DEVELOPMENT TOOLS =====
                'mozilla', 'firefox', 'chrome', 'opera', 'brave', 'edge', 'safari',
                'wordpress', 'blogger', 'medium', 'tumblr', 'pinterest', 'snapchat', 'tiktok',
                'whatsapp', 'telegram', 'discord', 'slack', 'skype', 'teams', 'notion',
                'figma', 'canva', 'trello', 'asana', 'jira', 'confluence', 'bitbucket',
                
                # ===== FINANCIAL & PAYMENT SERVICES =====
                'paypal', 'stripe', 'visa', 'mastercard', 'amex', 'discover', 'razorpay', 'paytm',
                'phonepe', 'googlepay', 'amazonpay', 'mobikwik', 'freecharge', 'bharatpe',
                'cred', 'jupiter', 'niyo', 'fi', 'slice', 'uni', 'cashfree', 'instamojo',
                'billdesk', 'ccavenue', 'payumoney', 'citrus', 'atom', 'ebs', 'techprocess',
                
                # ===== MAJOR BANKS (INDIA) =====
                'sbi', 'hdfcbank', 'icicibank', 'axisbank', 'kotakbank', 'yesbank',
                'pnb', 'bankofbaroda', 'canarabank', 'unionbank', 'indianbank', 'bankofmaharashtra',
                'idfcfirstbank', 'rbl', 'federalbank', 'southindianbank', 'karurbank',
                'cityunionbank', 'dhanbank', 'bandhanbank', 'aubank', 'csb', 'dcb',
                'indusind', 'jammubank', 'kvb', 'lakshmivilas', 'nainitalbank', 'tmb',
                'ucb', 'vijayabank', 'syndicate', 'allahabad', 'andhra', 'corporation',
                'dena', 'oriental', 'punjabsind', 'unitedbank', 'centralbank',
                
                # ===== MAJOR BANKS (GLOBAL) =====
                'chase', 'wellsfargo', 'bankofamerica', 'citibank', 'usbank', 'pnc',
                'jpmorgan', 'goldmansachs', 'morganstanley', 'hsbc', 'barclays', 'standardchartered',
                'lloyds', 'santander', 'bnpparibas', 'deutschebank', 'ubs', 'creditsuisse',
                'rbs', 'natwest', 'commerzbank', 'unicredit', 'intesa', 'bbva',
                'ing', 'abn', 'rabobank', 'nordea', 'swedbank', 'danskebank',
                
                # ===== GOVERNMENT WEBSITES (INDIA) =====
                'gov', 'nic', 'india', 'mygov', 'digitalindia', 'aadhaar', 'uidai',
                'incometax', 'gst', 'epfo', 'esic', 'nsdl', 'cdsl', 'sebi', 'rbi',
                'irdai', 'pfrda', 'nabard', 'sidbi', 'exim', 'cbdt', 'cbic', 'dgft',
                'fema', 'pmjay', 'nha', 'cowin', 'digilocker', 'umang', 'parivahan',
                'vahan', 'irctc', 'indianrailways', 'airindia', 'psu', 'cpse', 'drdo',
                'isro', 'dae', 'dst', 'csir', 'icar', 'icmr', 'ncert', 'cbse',
                'nta', 'ugc', 'aicte', 'mci', 'bci', 'pci', 'coa', 'iia',
                
                # ===== GOVERNMENT WEBSITES (GLOBAL) =====
                'usa', 'uk', 'canada', 'australia', 'singapore', 'uae', 'germany',
                'irs', 'ssa', 'medicare', 'medicaid', 'usps', 'dmv', 'fbi', 'cia',
                'nhs', 'hmrc', 'dvla', 'passport', 'immigration', 'homeoffice',
                'canada', 'cra', 'servicecanada', 'australia', 'ato', 'centrelink',
                
                # ===== EDUCATIONAL INSTITUTIONS =====
                'mit', 'harvard', 'stanford', 'berkeley', 'caltech', 'princeton', 'yale',
                'columbia', 'cornell', 'upenn', 'dartmouth', 'brown', 'chicago', 'northwestern',
                'duke', 'vanderbilt', 'rice', 'emory', 'georgetown', 'carnegiemellon',
                'iit', 'iisc', 'iim', 'nit', 'iiit', 'bits', 'vit', 'srm', 'amity',
                'du', 'jnu', 'bhu', 'amu', 'jamia', 'tiss', 'isi', 'jmi', 'manipal',
                'oxford', 'cambridge', 'imperial', 'lse', 'ucl', 'kcl', 'edinburgh',
                'manchester', 'warwick', 'bristol', 'nottingham', 'birmingham',
                
                # ===== CLOUD & INFRASTRUCTURE =====
                'cloudflare', 'aws', 'azure', 'gcp', 'heroku', 'digitalocean', 'linode',
                'vultr', 'ovh', 'rackspace', 'godaddy', 'namecheap', 'bluehost', 'hostgator',
                'ubuntu', 'debian', 'redhat', 'centos', 'fedora', 'opensuse', 'arch',
                'docker', 'kubernetes', 'jenkins', 'gitlab', 'atlassian', 'jetbrains',
                
                # ===== E-COMMERCE (GLOBAL) =====
                'walmart', 'target', 'bestbuy', 'homedepot', 'lowes', 'costco', 'macys',
                'alibaba', 'aliexpress', 'shopify', 'etsy', 'mercadolibre', 'rakuten',
                'zalando', 'otto', 'asos', 'boohoo', 'next', 'argos', 'currys',
                'johnlewis', 'marksandspencer', 'tesco', 'sainsburys', 'asda', 'morrisons',
                
                # ===== E-COMMERCE & SERVICES (INDIA) =====
                'flipkart', 'myntra', 'ajio', 'nykaa', 'bigbasket', 'grofers', 'blinkit',
                'swiggy', 'zomato', 'dunzo', 'urbancompany', 'bookmyshow', 'makemytrip',
                'goibibo', 'cleartrip', 'redbus', 'ola', 'rapido', 'zepto', 'instamart',
                'jiomart', 'reliancedigital', 'croma', 'vijaysales', 'tatacliq', 'snapdeal',
                'shopclues', 'pepperfry', 'urbanladder', 'fabindia', 'lifestyle', 'pantaloons',
                'westside', 'max', 'reliance', 'future', 'bigbazaar', 'easyday',
                
                # ===== INSURANCE COMPANIES =====
                'lic', 'sbi', 'hdfc', 'icici', 'bajaj', 'tata', 'reliance', 'aditya',
                'birla', 'max', 'star', 'oriental', 'national', 'united', 'newindia',
                'allstate', 'geico', 'progressive', 'statefarm', 'farmers', 'liberty',
                'aig', 'prudential', 'metlife', 'cigna', 'anthem', 'humana',
                
                # ===== MUTUAL FUNDS & INVESTMENT =====
                'amfiindia', 'valueresearch', 'morningstar', 'moneycontrol', 'economictimes',
                'zerodha', 'upstox', 'groww', 'angelone', 'icicidirect', 'hdfcsec',
                'kotaksecurities', 'sbicap', 'motilal', 'sharekhan', 'religare', 'karvy',
                'fidelity', 'vanguard', 'blackrock', 'schwab', 'etrade', 'robinhood',
                
                # ===== TRANSPORTATION & LOGISTICS =====
                'usps', 'fedex', 'ups', 'dhl', 'airbnb', 'uber', 'lyft', 'grab',
                'booking', 'expedia', 'hotels', 'trivago', 'agoda', 'priceline',
                'indianrailways', 'irctc', 'airindia', 'indigo', 'spicejet', 'vistara',
                'goair', 'akasaair', 'alliance', 'trujet', 'jetairways', 'kingfisher',
                'emirates', 'etihad', 'qatar', 'singapore', 'cathay', 'lufthansa',
                'britishairways', 'klm', 'airfrance', 'delta', 'united', 'american',
                
                # ===== GAMING & ENTERTAINMENT =====
                'steam', 'epic', 'origin', 'uplay', 'battlenet', 'gog', 'roblox',
                'twitch', 'vimeo', 'dailymotion', 'hulu', 'disneyplus', 'hbo', 'paramount',
                'hotstar', 'sonyliv', 'voot', 'altbalaji', 'mxplayer', 'jiosaavn',
                'gaana', 'wynk', 'hungama', 'saavn', 'spotify', 'applemusic', 'amazonmusic',
                'nintendo', 'playstation', 'xbox', 'activision', 'ea', 'ubisoft',
                'rockstar', 'bethesda', 'blizzard', 'riot', 'valve', 'mojang',
                
                # ===== CELEBRITY & ARTIST WEBSITES =====
                'eminem', 'taylorswift', 'justinbieber', 'arianagrande', 'selenagomez',
                'ladygaga', 'rihanna', 'beyonce', 'kanyewest', 'drake', 'jayz',
                'brunomars', 'edsheeran', 'adele', 'coldplay', 'u2', 'metallica',
                'madonna', 'eltonjohn', 'paulmccartney', 'rollingstones', 'queen',
                
                # ===== NEWS & MEDIA =====
                'cnn', 'bbc', 'nytimes', 'washingtonpost', 'espn', 'foxnews', 'msnbc',
                'reuters', 'ap', 'bloomberg', 'wsj', 'usatoday', 'guardian', 'independent',
                'timesofindia', 'hindustantimes', 'indianexpress', 'thehindu', 'ndtv',
                'republicworld', 'zeenews', 'aajtak', 'news18', 'indiatoday', 'firstpost',
                'livemint', 'businessstandard', 'financialexpress', 'moneycontrol', 'et',
                
                # ===== EDUCATION & LEARNING =====
                'byjus', 'unacademy', 'vedantu', 'toppr', 'whitehatjr', 'coursera',
                'udemy', 'khan', 'edx', 'swayam', 'nptel', 'ignou', 'nios', 'skillshare',
                'pluralsight', 'lynda', 'masterclass', 'brilliant', 'duolingo', 'babbel',
                
                # ===== TELECOM (INDIA) =====
                'jio', 'airtel', 'vi', 'bsnl', 'mtnl', 'idea', 'vodafone', 'tata',
                
                # ===== TELECOM (GLOBAL) =====
                'verizon', 'att', 'tmobile', 'sprint', 'vodafone', 'orange', 'telefonica',
                'deutsche', 'bt', 'ee', 'three', 'o2', 'virgin', 'sky',
                
                # ===== HEALTHCARE =====
                'who', 'cdc', 'nih', 'fda', 'mohfw', 'icmr', 'aiims', 'pgimer',
                'apollo', 'fortis', 'max', 'manipal', 'narayana', 'aster', 'cloudnine',
                'practo', '1mg', 'netmeds', 'pharmeasy', 'medlife', 'apollo247', 'tata1mg',
                'mayoclinic', 'clevelandclinic', 'johnshopkins', 'massgeneral', 'cedars',
                
                # ===== UTILITIES & SERVICES =====
                'adani', 'tata', 'reliance', 'ongc', 'ntpc', 'powergrid', 'coal',
                'indianoil', 'bpcl', 'hpcl', 'gail', 'sail', 'bhel', 'hal', 'bel',
                'rites', 'ircon', 'nbcc', 'rvnl', 'pgcil', 'nhpc', 'sjvn',
                
                # ===== FOOD & DELIVERY =====
                'mcdonalds', 'kfc', 'pizzahut', 'dominos', 'subway', 'starbucks',
                'burgerking', 'tacobell', 'dunkindonuts', 'baskinrobbins', 'cocacola',
                'pepsi', 'nestle', 'unilever', 'pg', 'jnj', 'loreal', 'nivea',
                
                # ===== RETAIL & FASHION =====
                'nike', 'adidas', 'puma', 'reebok', 'underarmour', 'hm', 'zara',
                'uniqlo', 'gap', 'levis', 'tommy', 'calvin', 'ralph', 'gucci',
                'prada', 'versace', 'armani', 'dior', 'chanel', 'hermes', 'lvmh',
                
                # ===== AUTOMOTIVE =====
                'toyota', 'honda', 'nissan', 'hyundai', 'kia', 'mazda', 'subaru',
                'ford', 'gm', 'chrysler', 'bmw', 'mercedes', 'audi', 'volkswagen',
                'porsche', 'ferrari', 'lamborghini', 'maserati', 'bentley', 'rollsroyce',
                'maruti', 'mahindra', 'tata', 'bajaj', 'hero', 'tvs', 'royal',
                
                # ===== REAL ESTATE =====
                'magicbricks', 'housing', '99acres', 'commonfloor', 'proptiger', 'makaan',
                'zillow', 'realtor', 'redfin', 'trulia', 'apartments', 'rent',
                
                # ===== TRAVEL & HOSPITALITY =====
                'marriott', 'hilton', 'hyatt', 'intercontinental', 'accor', 'wyndham',
                'radisson', 'sheraton', 'westin', 'ritz', 'fourseasons', 'mandarin',
                'taj', 'oberoi', 'itc', 'leela', 'trident', 'vivanta',
                
                # ===== CRYPTOCURRENCY & FINTECH =====
                'coinbase', 'binance', 'kraken', 'gemini', 'bitfinex', 'huobi',
                'wazirx', 'coindcx', 'zebpay', 'unocoin', 'bitbns', 'giottus',
                'square', 'paypal', 'venmo', 'cashapp', 'revolut', 'wise',
                
                # ===== SOCIAL & COMMUNICATION =====
                'clubhouse', 'signal', 'viber', 'wechat', 'line', 'kakao',
                'meetup', 'eventbrite', 'zoom', 'webex', 'gotomeeting', 'bluejeans'
            }
            
            # If it's a known legitimate domain, return legitimate with high confidence
            if domain_name in legitimate_domains:
                print("  → Detected known legitimate domain (whitelist)")
                return "Legitimate", 95.0
            
            # Check for banking domains (be extra careful with these)
            if any(pattern in domain_name.lower() for pattern in banking_patterns):
                # If it contains banking keywords, check if it's in our whitelist
                if domain_name in legitimate_domains:
                    print("  → Detected legitimate banking domain (whitelist)")
                    return "Legitimate", 95.0
                else:
                    # Banking domain not in whitelist - could be suspicious
                    print("  → Banking-related domain not in whitelist - proceeding with ML analysis")
            
            # Check for e-commerce domains
            if any(pattern in domain_name.lower() for pattern in ecommerce_patterns):
                if domain_name in legitimate_domains:
                    print("  → Detected legitimate e-commerce domain (whitelist)")
                    return "Legitimate", 95.0
                
        except Exception as e:
            print(f"  → Error in domain extraction: {e}")
            pass  # Continue with ML model if domain extraction fails
        
        # If not in whitelist, use ML model for prediction
        print("  → URL not in whitelist, using ML model for prediction")
        
        # Extract features
        features = extract_features(url)
        
        # Convert to DataFrame with correct feature order
        features_df = pd.DataFrame([features])
        
        # Ensure all expected features are present
        if self.feature_names is not None:
            for feature_name in self.feature_names:
                if feature_name not in features_df.columns:
                    features_df[feature_name] = 0
        
        # Reorder columns to match training data
        if self.feature_names is not None:
            features_df = features_df[self.feature_names]
        
        # Scale features
        features_scaled = None
        if self.scaler is not None:
            features_scaled = self.scaler.transform(features_df)
        
        # Make prediction
        prediction = None
        probability = None
        if self.model is not None and features_scaled is not None:
            prediction = self.model.predict(features_scaled)[0]
            probability = self.model.predict_proba(features_scaled)[0]
        
        if prediction is not None and probability is not None:
            result = "Phishing" if prediction == 1 else "Legitimate"
            confidence = max(probability) * 100
            print(f"  → ML Model prediction: {result} (Confidence: {confidence:.2f}%)")
            return result, confidence
        else:
            # Fallback if model prediction fails
            print("  → ML Model prediction failed - using fallback")
            return "Unknown", 50.0

    def predict_url_hybrid(self, url: str) -> tuple:
        """
        Predict using Hybrid Analysis + whitelist.
        
        Args:
            url (str): URL to analyze
            
        Returns:
            tuple: (result, confidence) where result is "Phishing" or "Legitimate"
        """
        print(f"🌐 Hybrid Analysis Mode - Analyzing URL: {url}")
        
        if self.hybrid_analysis is None:
            return "Error", 0.0, "Hybrid Analysis not available. Please set HYBRID_ANALYSIS_API_KEY."

        # Rule-based override for known legitimate domains (always used)
        import tldextract
        try:
            extracted = tldextract.extract(url.lower())
            domain_name = extracted.domain
            full_domain = f"{extracted.domain}.{extracted.suffix}".lower()
            
            # Special patterns for educational institutions and government sites
            educational_patterns = [
                '.edu', '.ac.in', '.edu.in', '.ernet.in', '.res.in', '.ac.uk', '.edu.au',
                'iit', 'nit', 'iiit', 'iim', 'iisc', 'bits', 'vit', 'university', 'college',
                'school', 'institute', 'academy', 'campus'
            ]
            
            government_patterns = [
                '.gov.in', '.nic.in', '.gov', '.mil', '.gov.uk', '.gov.au', '.gov.ca',
                '.gov.sg', '.gov.ae', '.org'
            ]
            
            # Banking patterns - any domain containing these should be treated carefully
            banking_patterns = [
                'bank', 'banking', 'sbi', 'hdfc', 'icici', 'axis', 'kotak', 'pnb',
                'chase', 'wells', 'citi', 'hsbc', 'barclays', 'santander'
            ]
            
            # E-commerce patterns
            ecommerce_patterns = [
                'amazon', 'flipkart', 'ebay', 'walmart', 'target', 'shop', 'store',
                'market', 'buy', 'sell', 'commerce', 'retail'
            ]
            
            # Check for educational institutions
            if any(pattern in full_domain for pattern in educational_patterns):
                print("  → Detected educational institution domain (rule-based)")
                return "Legitimate", 95.0
                
            # Check for government sites
            if any(pattern in full_domain for pattern in government_patterns):
                print("  → Detected government domain (rule-based)")
                return "Legitimate", 95.0
            
            # COMPREHENSIVE WHITELIST - All legitimate domains should be flagged as safe
            legitimate_domains = {
                # ===== TECH GIANTS & MAJOR PLATFORMS =====
                'google', 'youtube', 'facebook', 'amazon', 'wikipedia', 'twitter', 'instagram',
                'linkedin', 'reddit', 'netflix', 'microsoft', 'apple', 'github', 'stackoverflow',
                'yahoo', 'bing', 'duckduckgo', 'ebay', 'gmail', 'outlook', 'dropbox', 'spotify',
                'adobe', 'salesforce', 'zoom', 'oracle', 'ibm', 'intel', 'cisco', 'vmware',
                'dell', 'hp', 'lenovo', 'meta', 'alphabet', 'tesla', 'spacex', 'nvidia',
                
                # ===== BROWSERS & DEVELOPMENT TOOLS =====
                'mozilla', 'firefox', 'chrome', 'opera', 'brave', 'edge', 'safari',
                'wordpress', 'blogger', 'medium', 'tumblr', 'pinterest', 'snapchat', 'tiktok',
                'whatsapp', 'telegram', 'discord', 'slack', 'skype', 'teams', 'notion',
                'figma', 'canva', 'trello', 'asana', 'jira', 'confluence', 'bitbucket',
                
                # ===== FINANCIAL & PAYMENT SERVICES =====
                'paypal', 'stripe', 'visa', 'mastercard', 'amex', 'discover', 'razorpay', 'paytm',
                'phonepe', 'googlepay', 'amazonpay', 'mobikwik', 'freecharge', 'bharatpe',
                'cred', 'jupiter', 'niyo', 'fi', 'slice', 'uni', 'cashfree', 'instamojo',
                'billdesk', 'ccavenue', 'payumoney', 'citrus', 'atom', 'ebs', 'techprocess',
                
                # ===== MAJOR BANKS (INDIA) =====
                'sbi', 'hdfcbank', 'icicibank', 'axisbank', 'kotakbank', 'yesbank',
                'pnb', 'bankofbaroda', 'canarabank', 'unionbank', 'indianbank', 'bankofmaharashtra',
                'idfcfirstbank', 'rbl', 'federalbank', 'southindianbank', 'karurbank',
                'cityunionbank', 'dhanbank', 'bandhanbank', 'aubank', 'csb', 'dcb',
                'indusind', 'jammubank', 'kvb', 'lakshmivilas', 'nainitalbank', 'tmb',
                'ucb', 'vijayabank', 'syndicate', 'allahabad', 'andhra', 'corporation',
                'dena', 'oriental', 'punjabsind', 'unitedbank', 'centralbank',
                
                # ===== MAJOR BANKS (GLOBAL) =====
                'chase', 'wellsfargo', 'bankofamerica', 'citibank', 'usbank', 'pnc',
                'jpmorgan', 'goldmansachs', 'morganstanley', 'hsbc', 'barclays', 'standardchartered',
                'lloyds', 'santander', 'bnpparibas', 'deutschebank', 'ubs', 'creditsuisse',
                'rbs', 'natwest', 'commerzbank', 'unicredit', 'intesa', 'bbva',
                'ing', 'abn', 'rabobank', 'nordea', 'swedbank', 'danskebank',
                
                # ===== GOVERNMENT WEBSITES (INDIA) =====
                'gov', 'nic', 'india', 'mygov', 'digitalindia', 'aadhaar', 'uidai',
                'incometax', 'gst', 'epfo', 'esic', 'nsdl', 'cdsl', 'sebi', 'rbi',
                'irdai', 'pfrda', 'nabard', 'sidbi', 'exim', 'cbdt', 'cbic', 'dgft',
                'fema', 'pmjay', 'nha', 'cowin', 'digilocker', 'umang', 'parivahan',
                'vahan', 'irctc', 'indianrailways', 'airindia', 'psu', 'cpse', 'drdo',
                'isro', 'dae', 'dst', 'csir', 'icar', 'icmr', 'ncert', 'cbse',
                'nta', 'ugc', 'aicte', 'mci', 'bci', 'pci', 'coa', 'iia',
                
                # ===== GOVERNMENT WEBSITES (GLOBAL) =====
                'usa', 'uk', 'canada', 'australia', 'singapore', 'uae', 'germany',
                'irs', 'ssa', 'medicare', 'medicaid', 'usps', 'dmv', 'fbi', 'cia',
                'nhs', 'hmrc', 'dvla', 'passport', 'immigration', 'homeoffice',
                'canada', 'cra', 'servicecanada', 'australia', 'ato', 'centrelink',
                
                # ===== EDUCATIONAL INSTITUTIONS =====
                'mit', 'harvard', 'stanford', 'berkeley', 'caltech', 'princeton', 'yale',
                'columbia', 'cornell', 'upenn', 'dartmouth', 'brown', 'chicago', 'northwestern',
                'duke', 'vanderbilt', 'rice', 'emory', 'georgetown', 'carnegiemellon',
                'iit', 'iisc', 'iim', 'nit', 'iiit', 'bits', 'vit', 'srm', 'amity',
                'du', 'jnu', 'bhu', 'amu', 'jamia', 'tiss', 'isi', 'jmi', 'manipal',
                'oxford', 'cambridge', 'imperial', 'lse', 'ucl', 'kcl', 'edinburgh',
                'manchester', 'warwick', 'bristol', 'nottingham', 'birmingham',
                
                # ===== CLOUD & INFRASTRUCTURE =====
                'cloudflare', 'aws', 'azure', 'gcp', 'heroku', 'digitalocean', 'linode',
                'vultr', 'ovh', 'rackspace', 'godaddy', 'namecheap', 'bluehost', 'hostgator',
                'ubuntu', 'debian', 'redhat', 'centos', 'fedora', 'opensuse', 'arch',
                'docker', 'kubernetes', 'jenkins', 'gitlab', 'atlassian', 'jetbrains',
                
                # ===== E-COMMERCE (GLOBAL) =====
                'walmart', 'target', 'bestbuy', 'homedepot', 'lowes', 'costco', 'macys',
                'alibaba', 'aliexpress', 'shopify', 'etsy', 'mercadolibre', 'rakuten',
                'zalando', 'otto', 'asos', 'boohoo', 'next', 'argos', 'currys',
                'johnlewis', 'marksandspencer', 'tesco', 'sainsburys', 'asda', 'morrisons',
                
                # ===== E-COMMERCE & SERVICES (INDIA) =====
                'flipkart', 'myntra', 'ajio', 'nykaa', 'bigbasket', 'grofers', 'blinkit',
                'swiggy', 'zomato', 'dunzo', 'urbancompany', 'bookmyshow', 'makemytrip',
                'goibibo', 'cleartrip', 'redbus', 'ola', 'rapido', 'zepto', 'instamart',
                'jiomart', 'reliancedigital', 'croma', 'vijaysales', 'tatacliq', 'snapdeal',
                'shopclues', 'pepperfry', 'urbanladder', 'fabindia', 'lifestyle', 'pantaloons',
                'westside', 'max', 'reliance', 'future', 'bigbazaar', 'easyday',
                
                # ===== INSURANCE COMPANIES =====
                'lic', 'sbi', 'hdfc', 'icici', 'bajaj', 'tata', 'reliance', 'aditya',
                'birla', 'max', 'star', 'oriental', 'national', 'united', 'newindia',
                'allstate', 'geico', 'progressive', 'statefarm', 'farmers', 'liberty',
                'aig', 'prudential', 'metlife', 'cigna', 'anthem', 'humana',
                
                # ===== MUTUAL FUNDS & INVESTMENT =====
                'amfiindia', 'valueresearch', 'morningstar', 'moneycontrol', 'economictimes',
                'zerodha', 'upstox', 'groww', 'angelone', 'icicidirect', 'hdfcsec',
                'kotaksecurities', 'sbicap', 'motilal', 'sharekhan', 'religare', 'karvy',
                'fidelity', 'vanguard', 'blackrock', 'schwab', 'etrade', 'robinhood',
                
                # ===== TRANSPORTATION & LOGISTICS =====
                'usps', 'fedex', 'ups', 'dhl', 'airbnb', 'uber', 'lyft', 'grab',
                'booking', 'expedia', 'hotels', 'trivago', 'agoda', 'priceline',
                'indianrailways', 'irctc', 'airindia', 'indigo', 'spicejet', 'vistara',
                'goair', 'akasaair', 'alliance', 'trujet', 'jetairways', 'kingfisher',
                'emirates', 'etihad', 'qatar', 'singapore', 'cathay', 'lufthansa',
                'britishairways', 'klm', 'airfrance', 'delta', 'united', 'american',
                
                # ===== GAMING & ENTERTAINMENT =====
                'steam', 'epic', 'origin', 'uplay', 'battlenet', 'gog', 'roblox',
                'twitch', 'vimeo', 'dailymotion', 'hulu', 'disneyplus', 'hbo', 'paramount',
                'hotstar', 'sonyliv', 'voot', 'altbalaji', 'mxplayer', 'jiosaavn',
                'gaana', 'wynk', 'hungama', 'saavn', 'spotify', 'applemusic', 'amazonmusic',
                'nintendo', 'playstation', 'xbox', 'activision', 'ea', 'ubisoft',
                'rockstar', 'bethesda', 'blizzard', 'riot', 'valve', 'mojang',
                
                # ===== CELEBRITY & ARTIST WEBSITES =====
                'eminem', 'taylorswift', 'justinbieber', 'arianagrande', 'selenagomez',
                'ladygaga', 'rihanna', 'beyonce', 'kanyewest', 'drake', 'jayz',
                'brunomars', 'edsheeran', 'adele', 'coldplay', 'u2', 'metallica',
                'madonna', 'eltonjohn', 'paulmccartney', 'rollingstones', 'queen',
                
                # ===== NEWS & MEDIA =====
                'cnn', 'bbc', 'nytimes', 'washingtonpost', 'espn', 'foxnews', 'msnbc',
                'reuters', 'ap', 'bloomberg', 'wsj', 'usatoday', 'guardian', 'independent',
                'timesofindia', 'hindustantimes', 'indianexpress', 'thehindu', 'ndtv',
                'republicworld', 'zeenews', 'aajtak', 'news18', 'indiatoday', 'firstpost',
                'livemint', 'businessstandard', 'financialexpress', 'moneycontrol', 'et',
                
                # ===== EDUCATION & LEARNING =====
                'byjus', 'unacademy', 'vedantu', 'toppr', 'whitehatjr', 'coursera',
                'udemy', 'khan', 'edx', 'swayam', 'nptel', 'ignou', 'nios', 'skillshare',
                'pluralsight', 'lynda', 'masterclass', 'brilliant', 'duolingo', 'babbel',
                
                # ===== TELECOM (INDIA) =====
                'jio', 'airtel', 'vi', 'bsnl', 'mtnl', 'idea', 'vodafone', 'tata',
                
                # ===== TELECOM (GLOBAL) =====
                'verizon', 'att', 'tmobile', 'sprint', 'vodafone', 'orange', 'telefonica',
                'deutsche', 'bt', 'ee', 'three', 'o2', 'virgin', 'sky',
                
                # ===== HEALTHCARE =====
                'who', 'cdc', 'nih', 'fda', 'mohfw', 'icmr', 'aiims', 'pgimer',
                'apollo', 'fortis', 'max', 'manipal', 'narayana', 'aster', 'cloudnine',
                'practo', '1mg', 'netmeds', 'pharmeasy', 'medlife', 'apollo247', 'tata1mg',
                'mayoclinic', 'clevelandclinic', 'johnshopkins', 'massgeneral', 'cedars',
                
                # ===== UTILITIES & SERVICES =====
                'adani', 'tata', 'reliance', 'ongc', 'ntpc', 'powergrid', 'coal',
                'indianoil', 'bpcl', 'hpcl', 'gail', 'sail', 'bhel', 'hal', 'bel',
                'rites', 'ircon', 'nbcc', 'rvnl', 'pgcil', 'nhpc', 'sjvn',
                
                # ===== FOOD & DELIVERY =====
                'mcdonalds', 'kfc', 'pizzahut', 'dominos', 'subway', 'starbucks',
                'burgerking', 'tacobell', 'dunkindonuts', 'baskinrobbins', 'cocacola',
                'pepsi', 'nestle', 'unilever', 'pg', 'jnj', 'loreal', 'nivea',
                
                # ===== RETAIL & FASHION =====
                'nike', 'adidas', 'puma', 'reebok', 'underarmour', 'hm', 'zara',
                'uniqlo', 'gap', 'levis', 'tommy', 'calvin', 'ralph', 'gucci',
                'prada', 'versace', 'armani', 'dior', 'chanel', 'hermes', 'lvmh',
                
                # ===== AUTOMOTIVE =====
                'toyota', 'honda', 'nissan', 'hyundai', 'kia', 'mazda', 'subaru',
                'ford', 'gm', 'chrysler', 'bmw', 'mercedes', 'audi', 'volkswagen',
                'porsche', 'ferrari', 'lamborghini', 'maserati', 'bentley', 'rollsroyce',
                'maruti', 'mahindra', 'tata', 'bajaj', 'hero', 'tvs', 'royal',
                
                # ===== REAL ESTATE =====
                'magicbricks', 'housing', '99acres', 'commonfloor', 'proptiger', 'makaan',
                'zillow', 'realtor', 'redfin', 'trulia', 'apartments', 'rent',
                
                # ===== TRAVEL & HOSPITALITY =====
                'marriott', 'hilton', 'hyatt', 'intercontinental', 'accor', 'wyndham',
                'radisson', 'sheraton', 'westin', 'ritz', 'fourseasons', 'mandarin',
                'taj', 'oberoi', 'itc', 'leela', 'trident', 'vivanta',
                
                # ===== CRYPTOCURRENCY & FINTECH =====
                'coinbase', 'binance', 'kraken', 'gemini', 'bitfinex', 'huobi',
                'wazirx', 'coindcx', 'zebpay', 'unocoin', 'bitbns', 'giottus',
                'square', 'paypal', 'venmo', 'cashapp', 'revolut', 'wise',
                
                # ===== SOCIAL & COMMUNICATION =====
                'clubhouse', 'signal', 'viber', 'wechat', 'line', 'kakao',
                'meetup', 'eventbrite', 'zoom', 'webex', 'gotomeeting', 'bluejeans'
            }
            
            # If it's a known legitimate domain, return legitimate with high confidence
            if domain_name in legitimate_domains:
                print("  → Detected known legitimate domain (whitelist)")
                return "Legitimate", 95.0
            
            # Check for banking domains (be extra careful with these)
            if any(pattern in domain_name.lower() for pattern in banking_patterns):
                # If it contains banking keywords, check if it's in our whitelist
                if domain_name in legitimate_domains:
                    print("  → Detected legitimate banking domain (whitelist)")
                    return "Legitimate", 95.0
                else:
                    # Banking domain not in whitelist - could be suspicious
                    print("  → Banking-related domain not in whitelist - proceeding with Hybrid Analysis")
            
            # Check for e-commerce domains
            if any(pattern in domain_name.lower() for pattern in ecommerce_patterns):
                if domain_name in legitimate_domains:
                    print("  → Detected legitimate e-commerce domain (whitelist)")
                    return "Legitimate", 95.0
                
        except Exception as e:
            print(f"  → Error in domain extraction: {e}")
            pass  # Continue with Hybrid Analysis if domain extraction fails
        
        # If not in whitelist, use Hybrid Analysis for detection
        print("  → URL not in whitelist, using Hybrid Analysis for detection")
        try:
            ha_result = self.hybrid_analysis.analyze_url(url, max_wait_time=30)
            print(f"  → Hybrid Analysis result: {ha_result}")
            
            if ha_result['success']:
                if ha_result['malicious']:
                    print("  → Hybrid Analysis detected malicious URL")
                    return "Phishing", ha_result['confidence']
                else:
                    print("  → Hybrid Analysis detected safe URL")
                    return "Legitimate", ha_result['confidence']
            else:
                print(f"  → Hybrid Analysis failed: {ha_result.get('error', 'Unknown error')}")
                # Fallback to basic heuristics
                return self._basic_heuristics(url)
                
        except Exception as e:
            print(f"  → Hybrid Analysis check failed: {e}")
            return self._basic_heuristics(url)

    def _basic_heuristics(self, url: str) -> tuple:
        """Basic heuristics fallback when Hybrid Analysis is not available."""
        print("  → Using basic heuristics fallback")
        
        # Basic suspicious pattern detection
        suspicious_indicators = 0
        
        # Check for suspicious TLDs
        suspicious_tlds = ['.tk', '.ml', '.ga', '.cf', '.pw', '.top', '.click', '.download']
        if any(tld in url.lower() for tld in suspicious_tlds):
            suspicious_indicators += 2
            print(f"    → Suspicious TLD detected")
        
        # Check for suspicious keywords
        suspicious_keywords = ['secure-', 'verify-', 'update-', 'confirm-', 'account-', 'banking-']
        if any(keyword in url.lower() for keyword in suspicious_keywords):
            suspicious_indicators += 2
            print(f"    → Suspicious keywords detected")
        
        # Check for IP addresses
        import re
        ip_pattern = r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b'
        if re.search(ip_pattern, url):
            suspicious_indicators += 3
            print(f"    → IP address detected in URL")
        
        # Check URL length (very long URLs can be suspicious)
        if len(url) > 100:
            suspicious_indicators += 1
            print(f"    → Very long URL detected")
        
        # Check for excessive subdomains
        if url.count('.') > 4:
            suspicious_indicators += 1
            print(f"    → Excessive subdomains detected")
        
        # Determine result based on suspicious indicators
        if suspicious_indicators >= 3:
            print(f"    → High suspicion score ({suspicious_indicators}), flagging as phishing")
            return "Phishing", min(70 + suspicious_indicators * 5, 90)
        elif suspicious_indicators >= 1:
            print(f"    → Medium suspicion score ({suspicious_indicators}), flagging as suspicious")
            return "Phishing", min(50 + suspicious_indicators * 10, 75)
        else:
            print(f"    → Low suspicion score ({suspicious_indicators}), appears legitimate")
            return "Legitimate", 60.0
    
    def predict_batch(self, urls: list) -> list:
        """
        Predict multiple URLs at once.
        
        Args:
            urls (list): List of URLs to analyze
            
        Returns:
            list: List of tuples (result, confidence)
        """
        return [self.predict_url(url) for url in urls]


# Global predictor instance
_predictor = None

def get_predictor():
    """Get or create the global predictor instance."""
    global _predictor
    if _predictor is None:
        _predictor = PhishingPredictor()
    return _predictor

def predict_url(url: str) -> str:
    """
    Convenience function to predict a single URL.
    
    Args:
        url (str): URL to analyze
        
    Returns:
        str: "Phishing" or "Legitimate"
    """
    predictor = get_predictor()
    result, confidence = predictor.predict_url(url)
    return result
