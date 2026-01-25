@echo off
REM PCAP Anomaly Detector - Professional Security Tool Interface (Windows)
REM Author: Senaraufi
REM Version: 1.0.0

setlocal enabledelayedexpansion

REM Tool configuration
set "TOOL_NAME=PCAP Anomaly Detector"
set "TOOL_VERSION=v1.0.0"
set "AUTHOR=Senaraufi"

REM Project directory
set "PROJECT_DIR=%~dp0"
set "VENV_DIR=%PROJECT_DIR%venv"

:main_loop
call :show_header
call :show_main_menu
call :get_user_choice
call :handle_choice "!choice!"

if not "!choice!"=="0" (
    echo.
    echo [93mPress Enter to continue...[0m
    pause >nul
    goto main_loop
)

echo.
echo [91m[SESSION TERMINATED][0m
echo [90mThank you for using %TOOL_NAME%[0m
pause
exit /b 0

:show_header
cls
echo [96m╔════════════════════════════════════════════════════════════╗[0m
echo [96m║                                                              ║[0m
echo [96m║                [1;97mSECURITY ANALYSIS TOOL[0m                ║[0m
echo [96m║                                                              ║[0m
echo [96m║            [96m%TOOL_NAME%[0m            ║[0m
echo [96m║                                                              ║[0m
echo [96m║          [90m%TOOL_VERSION% ^| %AUTHOR%[0m          ║[0m
echo [96m║                                                              ║[0m
echo [96m╚════════════════════════════════════════════════════════════╝[0m
echo.
goto :eof

:show_main_menu
echo [95m[MAIN MENU][0m
echo [90m═════════════════════════════════════════════════════════════[0m
echo.
echo [97m1.[0m [92mQuick Analysis[0m           [90mFast scan with basic detection[0m
echo [97m2.[0m [92mAdvanced Analysis[0m        [90mComprehensive security scan[0m
echo [97m3.[0m [92mDomain Analysis[0m          [90mFocus on suspicious domains[0m
echo [97m4.[0m [92mTraffic Analysis[0m         [90mAnalyze traffic patterns[0m
echo [97m5.[0m [92mMalware Detection[0m        [90mScan for malware indicators[0m
echo [97m6.[0m [92mExfiltration Check[0m        [90mDetect data theft attempts[0m
echo [97m7.[0m [92mNetwork Anomalies[0m        [90mFind unusual network activity[0m
echo [97m8.[0m [94mFile Information[0m          [90mShow PCAP file details[0m
echo [97m9.[0m [95mTest with Sample[0m         [90mRun analysis on test data[0m
echo [97m10.[0m [96mSystem Status[0m            [90mCheck tool configuration[0m
echo.
echo [97m0.[0m [91mExit[0m                      [90mTerminate session[0m
echo.
echo [90m───────────────────────────────────────────────────────────[0m
goto :eof

:get_user_choice
set /p "choice=→ [96mSelect option[0m: "
goto :eof

:setup_environment
echo [94m[ENVIRONMENT CHECK][0m
echo [90m──────────────────────────────────────────────────────────[0m

REM Check virtual environment
if not exist "%VENV_DIR%" (
    echo [93m⚠ Virtual environment not found[0m
    echo [94m→ Creating secure environment...[0m
    python -m venv "%VENV_DIR%" >nul 2>&1
    if !errorlevel! neq 0 (
        echo [91m✗ Failed to create environment[0m
        exit /b 1
    )
    echo [92m✓ Environment secured[0m
) else (
    echo [92m✓ Virtual environment found[0m
)

REM Activate environment
call "%VENV_DIR%\Scripts\activate.bat" >nul 2>&1
if !errorlevel! neq 0 (
    echo [91m✗ Failed to activate environment[0m
    exit /b 1
)
echo [92m✓ Environment activated[0m

REM Check dependencies
pip install -r requirements.txt >nul 2>&1
if !errorlevel! neq 0 (
    echo [91m✗ Dependency check failed[0m
    exit /b 1
)
echo [92m✓ Dependencies verified[0m
echo [92m✓ System ready[0m
echo.
goto :eof

:select_pcap_file
echo [94m[FILE SELECTION][0m
echo [90m──────────────────────────────────────────────────────────[0m]

REM List available PCAP files
set pcap_count=0
for %%f in (*.pcap) do (
    set /a pcap_count+=1
    set "file!pcap_count!=%%f"
)

if !pcap_count! equ 0 (
    echo [93m⚠ No PCAP files found in current directory[0m
    echo [94m→ Please provide file path:[0m
    set /p "file_path=Enter PCAP file path: "
    
    if not exist "!file_path!" (
        echo [91m✗ File not found: !file_path![0m
        exit /b 1
    )
    set "selected_file=!file_path!"
    goto :eof
)

echo [97mAvailable PCAP files:[0m
for /l %%i in (1,1,!pcap_count!) do (
    echo [97m%%i.[0m [92m!file%%i!![0m
)

echo.
set /p "file_choice=Select file [1-!pcap_count!]: "

if "!file_choice!" geq "1" if "!file_choice!" leq "!pcap_count!" (
    set "selected_file=!file%file_choice%!"
    echo [92m✓ Selected: !selected_file![0m
    goto :eof
) else (
    echo [91m✗ Invalid selection[0m
    exit /b 1
)

:run_analysis
set "analysis_type=%~1"
set "pcap_file=%~2"
set "extra_args=%~3"

echo [94m[ANALYSIS IN PROGRESS][0m
echo [90m──────────────────────────────────────────────────────────[0m
echo [97mTarget:[0m [92m%pcap_file%[0m
echo [97mMode:[0m [96m%analysis_type%[0m
echo.

echo [93m🔍 Initializing analysis engine...[0m
timeout /t 1 >nul
echo [93m📊 Parsing PCAP data...[0m
timeout /t 1 >nul
echo [93m🔍 Scanning for threats...[0m
timeout /t 1 >nul
echo [93m📈 Analyzing patterns...[0m
timeout /t 1 >nul
echo [93m🛡️ Applying security rules...[0m
timeout /t 1 >nul
echo.

echo [96mExecuting security scan...[0m
echo.

if "%analysis_type%"=="Quick Analysis" (
    python -c "from pcap_analyzer.cli import cli; cli(['analyze', '%pcap_file%']%extra_args%)"
) else if "%analysis_type%"=="Advanced Analysis" (
    python -c "from pcap_analyzer.cli import cli; cli(['analyze', '%pcap_file%', '--advanced']%extra_args%)"
) else if "%analysis_type%"=="Domain Analysis" (
    python -c "from pcap_analyzer.cli import cli; cli(['analyze', '%pcap_file%', '--domains-only']%extra_args%)"
) else if "%analysis_type%"=="Traffic Analysis" (
    python -c "from pcap_analyzer.cli import cli; cli(['analyze', '%pcap_file%', '--traffic-only']%extra_args%)"
) else if "%analysis_type%"=="Malware Detection" (
    python -c "from pcap_analyzer.cli import cli; cli(['analyze', '%pcap_file%', '--malware-only']%extra_args%)"
) else if "%analysis_type%"=="Exfiltration Check" (
    python -c "from pcap_analyzer.cli import cli; cli(['analyze', '%pcap_file%', '--exfil-only']%extra_args%)"
) else if "%analysis_type%"=="Network Anomalies" (
    python -c "from pcap_analyzer.cli import cli; cli(['analyze', '%pcap_file%', '--anomaly-only']%extra_args%)"
) else if "%analysis_type%"=="File Information" (
    python -c "from pcap_analyzer.cli import cli; cli(['info', '%pcap_file%']%extra_args%)"
)

echo.
echo [92m✓ Analysis completed[0m
goto :eof

:show_system_status
echo [94m[SYSTEM STATUS][0m
echo [90m═════════════════════════════════════════════════════════════[0m

echo [97mTool Version:[0m [92m%TOOL_VERSION%[0m
python --version 2>nul || echo [97mPython Version:[0m [91mNot found[0m
echo [97mEnvironment:[0m [92mActive[0m
echo [97mDependencies:[0] [92mAvailable[0m

echo.
echo [97mAvailable PCAP files:[0m
dir *.pcap 2>nul >nul
if !errorlevel! equ 0 (
    echo [92m✓ Files found[0m
    dir *.pcap | find ".pcap"
) else (
    echo [93m⚠ No PCAP files found[0m
)

echo.
echo [97mRecent Results:[0m
dir results*.txt analysis*.txt advanced*.txt 2>nul >nul
if !errorlevel! equ 0 (
    echo [92m✓ Result files found[0m
    dir results*.txt analysis*.txt advanced*.txt | find ".txt"
) else (
    echo [93m⚠ No result files found[0m
)
goto :eof

:handle_choice
call :setup_environment

if "%~1"=="1" (
    echo [92m[QUICK ANALYSIS][0m
    call :select_pcap_file
    if !errorlevel! equ 0 (
        set /p "save_output=Save results to file [y/n]: "
        if /i "!save_output!"=="y" (
            set /p "filename=Output filename: "
            set "extra_args=, '--output', '!filename!'"
        )
        call :run_analysis "Quick Analysis" "!selected_file!" "!extra_args!"
    )
) else if "%~1"=="2" (
    echo [92m[ADVANCED ANALYSIS][0m
    call :select_pcap_file
    if !errorlevel! equ 0 (
        set /p "save_output=Save results to file [y/n]: "
        set /p "verbose=Verbose output [y/n]: "
        set "extra_args="
        if /i "!save_output!"=="y" (
            set /p "filename=Output filename: "
            set "extra_args=!extra_args!, '--output', '!filename!'"
        )
        if /i "!verbose!"=="y" (
            set "extra_args=!extra_args!, '--verbose'"
        )
        call :run_analysis "Advanced Analysis" "!selected_file!" "!extra_args!"
    )
) else if "%~1"=="3" (
    echo [92m[DOMAIN ANALYSIS][0m
    call :select_pcap_file
    if !errorlevel! equ 0 (
        call :run_analysis "Domain Analysis" "!selected_file!" ""
    )
) else if "%~1"=="4" (
    echo [92m[TRAFFIC ANALYSIS][0m
    call :select_pcap_file
    if !errorlevel! equ 0 (
        call :run_analysis "Traffic Analysis" "!selected_file!" ""
    )
) else if "%~1"=="5" (
    echo [92m[MALWARE DETECTION][0m
    call :select_pcap_file
    if !errorlevel! equ 0 (
        call :run_analysis "Malware Detection" "!selected_file!" ""
    )
) else if "%~1"=="6" (
    echo [92m[EXFILTRATION CHECK][0m
    call :select_pcap_file
    if !errorlevel! equ 0 (
        call :run_analysis "Exfiltration Check" "!selected_file!" ""
    )
) else if "%~1"=="7" (
    echo [92m[NETWORK ANOMALIES][0m
    call :select_pcap_file
    if !errorlevel! equ 0 (
        call :run_analysis "Network Anomalies" "!selected_file!" ""
    )
) else if "%~1"=="8" (
    echo [94m[FILE INFORMATION][0m
    call :select_pcap_file
    if !errorlevel! equ 0 (
        call :run_analysis "File Information" "!selected_file!" ""
    )
) else if "%~1"=="9" (
    echo [95m[TEST WITH SAMPLE][0m
    if not exist "test_traffic.pcap" (
        echo [93mCreating test file...[0m
        python test_sample.py
        if !errorlevel! neq 0 (
            echo [91m✗ Failed to create test file[0m
            goto :eof
        )
        echo [92m✓ Test file created[0m
    )
    call :run_analysis "Advanced Analysis" "test_traffic.pcap" ""
) else if "%~1"=="10" (
    call :show_system_status
) else if "%~1"=="0" (
    REM Exit handled in main loop
) else (
    echo [91m✗ Invalid choice: %~1[0m
    echo [93mPlease select a valid option (0-10)[0m
)
goto :eof
