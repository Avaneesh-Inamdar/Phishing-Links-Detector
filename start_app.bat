@echo off
echo Starting Phishing URL Detection App with Hybrid Analysis integration...
echo.
if "%HYBRID_ANALYSIS_API_KEY%"=="" (
    echo API Key Status: Not set. Create a .env file with HYBRID_ANALYSIS_API_KEY.
) else (
    echo API Key Status: Set via environment
)
echo.

REM Check if a test parameter is provided
if "%1"=="test" (
    echo Running Hybrid Analysis API test...
    python test_hybrid_api.py
) else (
    echo Starting Flask app...
    python app.py
)