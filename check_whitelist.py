import tldextract

# Test the whitelist from predict.py Hybrid mode
legitimate_domains = {
    # ===== TECH GIANTS & MAJOR PLATFORMS =====
    'google', 'youtube', 'facebook', 'amazon', 'wikipedia', 'twitter', 'instagram',
    'linkedin', 'reddit', 'netflix', 'microsoft', 'apple', 'github', 'stackoverflow',
    'yahoo', 'bing', 'duckduckgo', 'ebay', 'gmail', 'outlook', 'dropbox', 'spotify',
    'adobe', 'salesforce', 'zoom', 'oracle', 'ibm', 'intel', 'cisco', 'vmware',
    'dell', 'hp', 'lenovo', 'meta', 'alphabet', 'tesla', 'spacex', 'nvidia',
    'meesho', 'minepi', 'codechef', 'mi', 'poco',
    
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
    
    # Additional Educational Institutions
    'coursera', 'udemy', 'khanacademy', 'edx', 'swayam', 'nptel', 'ignou', 'nios',
    # Indian Educational Institutions (.ac.in)
    'walchandsangli', 'iitb', 'iitm', 'iisc', 'jnu', 'du', 'amu', 'bhu',
    'iitd', 'iitk', 'iitr', 'iitg', 'iith', 'iitbbs', 'iitj', 'iitpkd',
    'iitgoa', 'iitbhilai', 'iittirupati', 'iitdh', 'iitmandi',
    'nitk', 'nitt', 'nitc', 'nitw', 'nitr', 'nits', 'nitd', 'nitj', 'nitap',
    'iiitd', 'iiitb', 'iiith', 'iiitg', 'iiitl', 'iiitm', 'iiitv', 'iiita',
    'dtu', 'nsit', 'igdtuw', 'thapar', 'lpu', 'chitkara', 'bennett'
    
    # ===== CLOUD & INFRASTRUCTURE =====
    'cloudflare', 'aws', 'azure', 'gcp', 'heroku', 'digitalocean', 'linode',
    'vultr', 'ovh', 'rackspace', 'godaddy', 'namecheap', 'bluehost', 'hostgator',
    'ubuntu', 'debian', 'redhat', 'centos', 'fedora', 'opensuse', 'arch',
    'linuxmint', 'manjaro', 'elementary', 'zorin', 'kde', 'gnome', 'suse',
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
    'westside', 'max', 'reliance', 'future', 'bigbazaar', 'easyday', 'olx',
    
    # Additional E-commerce Domains
    'quikr', 'paytmmall', 'shopsy', 'meesho', 'dealshare', 'bulkmro'
    
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
    
    # ===== AI PLATFORMS & TOOLS =====
    'openai', 'chatgpt', 'perplexity', 'anthropic', 'claude', 'gemini', 'googleai',
    'mistral', 'deepseek', 'copilot', 'bing', 'metaai', 'huggingface', 'cohere',
    'replicate', 'runwayml', 'stability', 'midjourney', 'dalle', 'leonardo',
    'jasper', 'writesonic', 'copyai', 'rytr', 'wordtune', 'quillbot', 'grammarly',
    'notion', 'obsidian', 'replit', 'kaggle', 'poe', 'you', 'phind', 'forefront',
    'character', 'ai', 'socratic', 'wolfram', 'wolframalpha', 'photomath',
    
    # ===== SOCIAL & COMMUNICATION =====
    'clubhouse', 'signal', 'viber', 'wechat', 'line', 'kakao',
    'meetup', 'eventbrite', 'zoom', 'webex', 'gotomeeting', 'bluejeans',
}

# Test if AI domains are in the whitelist
ai_domains = ['chatgpt', 'openai', 'perplexity', 'anthropic', 'claude', 'gemini']
print("Checking if AI domains are in the whitelist:")
for domain in ai_domains:
    if domain in legitimate_domains:
        print(f"✅ {domain} is in the whitelist")
    else:
        print(f"❌ {domain} is NOT in the whitelist")