"""
Flask web application for phishing URL detection.
Provides a simple web interface for users to check URLs.
"""

from flask import Flask, render_template, request, jsonify
import os
import sys
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()

# Add the current directory to Python path
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from ml.predict import PhishingPredictor

app = Flask(__name__)

# Initialize the predictor
try:
    predictor = PhishingPredictor(model_dir='models')
    system_loaded = True
    model_available = predictor.model is not None
    hybrid_available = predictor.hybrid_analysis is not None
except Exception as e:
    print(f"Warning: Could not initialize system - {e}")
    predictor = None
    system_loaded = False
    model_available = False
    hybrid_available = False


@app.route('/')
def index():
    """Main page with URL input form."""
    return render_template('index.html', 
                         system_loaded=system_loaded,
                         model_available=model_available,
                         hybrid_available=hybrid_available)


@app.route('/predict', methods=['POST'])
def predict():
    """API endpoint for URL prediction."""
    if not system_loaded or predictor is None:
        return jsonify({
            'error': 'System not initialized properly.',
            'result': 'Error',
            'confidence': 0
        })
    
    try:
        data = request.get_json()
        url = data.get('url', '').strip()
        mode = data.get('mode', 'hybrid')  # 'model_only' or 'hybrid'
        
        if not url:
            return jsonify({
                'error': 'Please provide a URL',
                'result': 'Error',
                'confidence': 0
            })
        
        # Make prediction based on mode
        if mode == 'model_only':
            if not model_available:
                return jsonify({
                    'error': 'ML model not available. Please train the model first.',
                    'result': 'Error',
                    'confidence': 0
                })
            result, confidence = predictor.predict_url_model_only(url)
        else:  # hybrid mode
            if not hybrid_available:
                return jsonify({
                    'error': 'Hybrid Analysis not available. Please set HYBRID_ANALYSIS_API_KEY.',
                    'result': 'Error',
                    'confidence': 0
                })
            result, confidence = predictor.predict_url_hybrid(url)
        
        return jsonify({
            'result': result,
            'confidence': round(confidence, 2),
            'url': url,
            'mode': mode,
            'error': None
        })
        
    except Exception as e:
        return jsonify({
            'error': str(e),
            'result': 'Error',
            'confidence': 0
        })


@app.route('/reload_api', methods=['POST'])
def reload_api():
    """API endpoint to reload Hybrid Analysis API."""
    if not system_loaded or predictor is None:
        return jsonify({
            'error': 'System not initialized properly.',
            'success': False
        })
    
    try:
        predictor.reload_hybrid_analysis()
        
        return jsonify({
            'success': True,
            'message': 'Hybrid Analysis API reloaded successfully'
        })
        
    except Exception as e:
        return jsonify({
            'error': str(e),
            'success': False
        })


@app.route('/status')
def status():
    """API endpoint to get system status."""
    if not system_loaded or predictor is None:
        return jsonify({
            'error': 'System not initialized properly.',
            'status': 'error'
        })
    
    return jsonify({
        'status': 'ready',
        'model_available': predictor.model is not None,
        'hybrid_analysis_available': predictor.hybrid_analysis is not None,
        'modes_available': {
            'model_only': predictor.model is not None,
            'hybrid': predictor.hybrid_analysis is not None
        }
    })


@app.route('/health')
def health():
    """Health check endpoint."""
    return jsonify({
        'status': 'healthy',
        'system_loaded': system_loaded,
        'model_available': predictor.model is not None if predictor else False,
        'hybrid_analysis_available': predictor.hybrid_analysis is not None if predictor else False
    })


if __name__ == '__main__':
    print("🛡️  Phishing URL Detection System")
    print("👥 Team ZeroPhish - Walchand College of Engineering, Sangli")
    print("=" * 60)
    
    if not system_loaded:
        print("❌ System initialization failed!")
        print("=" * 60)
    else:
        print("✅ System initialized successfully!")
        print(f"🤖 ML Model available: {'Yes' if model_available else 'No'}")
        print(f"🌐 Hybrid Analysis available: {'Yes' if hybrid_available else 'No'}")
        
        if model_available and hybrid_available:
            print("🔍 Both detection modes available!")
        elif model_available:
            print("🔍 ML Model mode available")
            print("ℹ️  Set HYBRID_ANALYSIS_API_KEY for Hybrid Analysis mode")
        elif hybrid_available:
            print("🔍 Hybrid Analysis mode available")
            print("ℹ️  Train model (python -m ml.train) for ML Model mode")
        else:
            print("⚠️  No detection modes available")
        print("=" * 60)
    
    print("🌐 Access the app at: http://localhost:5000")
    app.run(debug=True, host='0.0.0.0', port=5000)