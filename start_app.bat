@echo off
set HYBRID_ANALYSIS_API_KEY=iwqh1aw6e4c8ee3fr0z6gcg47fe7ccbecdo72mndccd0d1d5usphjeecda559b5e
echo Starting Phishing URL Detection App with Hybrid Analysis integration...
echo.
echo API Key Status: Enabled
echo.

REM Check if a test parameter is provided
if "%1"=="test" (
    echo Running Hybrid Analysis API test...
    python test_hybrid_api.py
) else (
    echo Starting Flask app...
    python app.py
)