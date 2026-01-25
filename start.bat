@echo off
REM PCAP Anomaly Detector - Start Script for Windows
REM Author: Senaraufi
REM Description: Easy launcher for the PCAP analysis tool

setlocal enabledelayedexpansion

REM Project directory
set "PROJECT_DIR=%~dp0"
set "VENV_DIR=%PROJECT_DIR%venv"

echo ========================================
echo     PCAP Anomaly Detector Launcher
echo ========================================
echo.

REM Function to check if virtual environment exists
if not exist "%VENV_DIR%" (
    echo [YELLOW]Virtual environment not found. Creating one...[NC]
    python -m venv "%VENV_DIR%"
    if !errorlevel! neq 0 (
        echo [RED]✗ Failed to create virtual environment[NC]
        pause
        exit /b 1
    )
    echo [GREEN]✓ Virtual environment created[NC]
)

REM Function to activate virtual environment
call "%VENV_DIR%\Scripts\activate.bat"
if !errorlevel! neq 0 (
    echo [RED]✗ Failed to activate virtual environment[NC]
    pause
    exit /b 1
)
echo [GREEN]✓ Virtual environment activated[NC]

REM Function to install dependencies
echo [YELLOW]Checking dependencies...[NC]
pip install -r requirements.txt >nul 2>&1
if !errorlevel! neq 0 (
    echo [RED]✗ Failed to install dependencies[NC]
    pause
    exit /b 1
)
echo [GREEN]✓ Dependencies installed[NC]

REM Check command
if "%1"=="" goto help
if "%1"=="help" goto help
if "%1"=="setup" goto setup
if "%1"=="test" goto test
if "%2"=="" goto missing_file

REM Run analysis
if not exist "%2" (
    echo [RED]✗ PCAP file not found: %2[NC]
    echo [YELLOW]Available files in directory:[NC]
    dir *.pcap 2>nul || echo [YELLOW]No .pcap files found[NC]
    pause
    exit /b 1
)

echo [BLUE]Analyzing: %2[NC]
echo [BLUE]Command: %1[NC]
echo.

if "%1"=="info" (
    python -c "from pcap_analyzer.cli import cli; cli(['info', '%2'] %3 %4 %5 %6 %7 %8 %9"
) else if "%1"=="analyze" (
    python -c "from pcap_analyzer.cli import cli; cli(['analyze', '%2'] %3 %4 %5 %6 %7 %8 %9"
) else if "%1"=="advanced" (
    python -c "from pcap_analyzer.cli import cli; cli(['analyze', '%2', '--advanced'] %3 %4 %5 %6 %7 %8 %9"
) else if "%1"=="domains" (
    python -c "from pcap_analyzer.cli import cli; cli(['analyze', '%2', '--domains-only'] %3 %4 %5 %6 %7 %8 %9"
) else if "%1"=="traffic" (
    python -c "from pcap_analyzer.cli import cli; cli(['analyze', '%2', '--traffic-only'] %3 %4 %5 %6 %7 %8 %9"
) else if "%1"=="exfil" (
    python -c "from pcap_analyzer.cli import cli; cli(['analyze', '%2', '--exfil-only'] %3 %4 %5 %6 %7 %8 %9"
) else if "%1"=="malware" (
    python -c "from pcap_analyzer.cli import cli; cli(['analyze', '%2', '--malware-only'] %3 %4 %5 %6 %7 %8 %9"
) else if "%1"=="anomalies" (
    python -c "from pcap_analyzer.cli import cli; cli(['analyze', '%2', '--anomaly-only'] %3 %4 %5 %6 %7 %8 %9"
) else (
    goto help
)

goto end

:setup
echo [BLUE]Setting up environment...[NC]
echo [GREEN]✓ Setup complete! Ready to use.[NC]
goto end

:test
echo [BLUE]Running analysis with test file...[NC]
if not exist "test_traffic.pcap" (
    echo [YELLOW]Creating test file...[NC]
    python test_sample.py
    if !errorlevel! neq 0 (
        echo [RED]✗ Failed to create test file[NC]
        pause
        exit /b 1
    )
)
python -c "from pcap_analyzer.cli import cli; cli(['analyze', 'test_traffic.pcap', '--advanced'])"
goto end

:help
echo [CYAN]Usage: %~nx0 [OPTION] [PCAP_FILE][NC]
echo.
echo [YELLOW]OPTIONS:[NC]
echo   info <file>              Show PCAP file information
echo   analyze <file>           Run basic analysis
echo   advanced <file>          Run advanced analysis (recommended)
echo   domains <file>           Only analyze suspicious domains
echo   traffic <file>            Only analyze traffic spikes
echo   exfil <file>             Only analyze data exfiltration
echo   malware <file>            Only analyze malware indicators
echo   anomalies <file>          Only analyze network anomalies
echo   test                     Run with test file
echo   setup                    Setup environment only
echo   help                     Show this help message
echo.
echo [YELLOW]EXAMPLES:[NC]
echo   %~nx0 advanced traffic.pcap
echo   %~nx0 info suspicious_traffic.pcap
echo   %~nx0 test
echo.
echo [YELLOW]OUTPUT OPTIONS:[NC]
echo   Add '--output filename.txt' to save results
echo   Add '--verbose' for detailed logging
echo.
echo [YELLOW]ADVANCED EXAMPLES:[NC]
echo   %~nx0 advanced traffic.pcap --output report.txt --verbose
echo   %~nx0 malware suspicious.pcap --output malware_report.txt
goto end

:missing_file
echo [RED]✗ Please provide a PCAP file[NC]
goto help

:end
pause
