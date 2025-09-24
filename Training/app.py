"""
Flask Frontend for Phishing URL Detection
Author: GitHub Copilot
"""

from flask import Flask, render_template_string, request
import joblib
import numpy as np
import re
from urllib.parse import urlparse

# Load model and scaler
MODEL_PATH = 'Training/phishing_url_model.joblib'
SCALER_PATH = 'Training/phishing_url_scaler.joblib'
model = joblib.load(MODEL_PATH)
scaler = joblib.load(SCALER_PATH)

# Feature extraction functions

def has_ip(url):
    ip_pattern = r"(\d{1,3}\.){3}\d{1,3}"
    return 1 if re.search(ip_pattern, url) else 0

def count_special_chars(url):
    return len(re.findall(r'[@\?\-=_%&/]', url))

def count_digits(url):
    return len(re.findall(r'\d', url))

def count_subdomains(url):
    try:
        hostname = urlparse(url).hostname
        if hostname:
            return hostname.count('.')
        else:
            return 0
    except:
        return 0

def domain_length(url):
    try:
        hostname = urlparse(url).hostname
        if hostname:
            return len(hostname)
        else:
            return 0
    except:
        return 0

def extract_features_from_url(url):
    features = [
        len(url),
        url.count('.'),
        1 if url.startswith('https') else 0,
        count_special_chars(url),
        count_digits(url),
        count_subdomains(url),
        domain_length(url),
        has_ip(url)
    ]
    return np.array(features).reshape(1, -1)

# Flask app
app = Flask(__name__)

HTML = """
<!DOCTYPE html>
<html lang='en'>
<head>
    <meta charset='UTF-8'>
    <title>Phishing URL Detector</title>
    <style>
        body { font-family: Arial, sans-serif; background: #f4f4f4; }
        .container { max-width: 500px; margin: 50px auto; background: #fff; padding: 30px; border-radius: 8px; box-shadow: 0 2px 8px #ccc; }
        h2 { text-align: center; }
        input[type=text] { width: 100%; padding: 10px; margin: 10px 0; border-radius: 4px; border: 1px solid #ccc; }
        button { padding: 10px 20px; background: #007bff; color: #fff; border: none; border-radius: 4px; cursor: pointer; }
        .result { margin-top: 20px; font-size: 1.2em; text-align: center; }
        .phishing { color: #d9534f; }
        .legitimate { color: #5cb85c; }
    </style>
</head>
<body>
    <div class='container'>
        <h2>Phishing URL Detector</h2>
        <form method='post'>
            <input type='text' name='url' placeholder='Enter URL to check...' required>
            <button type='submit'>Check</button>
        </form>
        {% if result %}
        <div class='result {{ result_class }}'>
            <strong>{{ result }}</strong>
        </div>
        {% endif %}
    </div>
</body>
</html>
"""

@app.route('/', methods=['GET', 'POST'])
def index():
    result = None
    result_class = ''
    if request.method == 'POST':
        url = request.form['url']
        features = extract_features_from_url(url)
        features_scaled = scaler.transform(features)
        pred = model.predict(features_scaled)[0]
        if pred == 1:
            result = 'Phishing URL Detected!'
            result_class = 'phishing'
        else:
            result = 'Legitimate URL.'
            result_class = 'legitimate'
    return render_template_string(HTML, result=result, result_class=result_class)

if __name__ == '__main__':
    app.run(debug=True)
