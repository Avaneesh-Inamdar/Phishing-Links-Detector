# Hybrid Analysis API Integration

This project can be enhanced with Hybrid Analysis malware sandbox integration for improved phishing URL detection accuracy.

## What is Hybrid Analysis?

Hybrid Analysis is a free malware analysis service that detects and analyzes unknown threats using a unique Hybrid Analysis technology. It provides a powerful API that can be used to submit URLs for analysis and retrieve detailed reports.

## Setting up Hybrid Analysis Integration

1. **Sign up for an account**
   - Visit [hybrid-analysis.com](https://www.hybrid-analysis.com/signup) to create a free account
   - Verify your email address

2. **Get your API key**
   - Log in to your Hybrid Analysis account
   - Navigate to the "API Key" section in your account settings
   - Copy your API key

3. **Set the API key as an environment variable**
   
   On Windows:
   ```cmd
   set HYBRID_ANALYSIS_API_KEY=your_api_key_here
   ```
   
   On Linux/Mac:
   ```bash
   export HYBRID_ANALYSIS_API_KEY=your_api_key_here
   ```

4. **Run the application**
   - When you start the Flask application, it will automatically detect the API key and enable Hybrid Analysis integration
   - URLs will be checked against both the ML model and the Hybrid Analysis sandbox for improved accuracy

## How it works

When Hybrid Analysis integration is enabled:

1. **Primary Check**: The ML model analyzes the URL as usual
2. **Enhanced Detection**: If the ML model is uncertain (confidence < 80%), the URL is submitted to Hybrid Analysis
3. **Result Combination**: Results from both systems are combined for the final verdict
4. **High Confidence**: URLs flagged as malicious by Hybrid Analysis receive high confidence scores

## Benefits

- **Improved Accuracy**: Hybrid Analysis provides an additional layer of verification
- **Real-time Analysis**: URLs are analyzed in real-time by a professional malware sandbox
- **Reduced False Positives**: Legitimate URLs are less likely to be incorrectly flagged
- **Enhanced Security**: Unknown phishing techniques can be detected

## API Usage Limits

Hybrid Analysis provides free API access with reasonable rate limits for community use. For heavy usage, consider their premium plans.

## Testing the Integration

You can test the integration with the provided test script:

```bash
# Set your API key first
set HYBRID_ANALYSIS_API_KEY=your_api_key_here

# Run the test
python test_hybrid_analysis.py
```

## Troubleshooting

If the integration isn't working:

1. **Check the API key**: Ensure it's correctly set in the environment variable
2. **Network connectivity**: Verify that your system can access `https://www.hybrid-analysis.com`
3. **Rate limits**: If you've made many requests, you might be temporarily rate-limited

For any issues, check the console output for error messages.