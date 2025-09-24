@echo off
echo Starting Phishing URL Detection App with Hybrid Analysis integration...
echo.
REM Load HYBRID_ANALYSIS_API_KEY from .env if not already set
if "%HYBRID_ANALYSIS_API_KEY%"=="" (
    if exist .env (
        for /f "usebackq tokens=1,* delims==" %%A in (".env") do (
            if /I "%%A"=="HYBRID_ANALYSIS_API_KEY" set HYBRID_ANALYSIS_API_KEY=%%B
        )
    )
)

if "%HYBRID_ANALYSIS_API_KEY%"=="" (
    echo API Key Status: Not set. Create a .env file with HYBRID_ANALYSIS_API_KEY.
) else (
    echo API Key Status: Set (hidden)
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