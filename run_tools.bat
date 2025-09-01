@echo off
echo ============================================
echo        Security Analysis Toolkit
echo ============================================
echo.
echo Available Tools:
echo 1. Network Scanner - Discover and scan network devices
echo 2. Log Analyzer - Analyze security logs for threats
echo 3. Security Analyzer - Comprehensive security assessment
echo 4. Exit
echo.

:menu
set /p choice="Select a tool (1-4): "

if "%choice%"=="1" (
    echo.
    echo Starting Network Scanner...
    echo Use --help for command options
    echo Example: NetworkScanner.exe --full-scan
    echo.
    cd dist
    NetworkScanner.exe
    cd ..
    goto menu
)

if "%choice%"=="2" (
    echo.
    echo Starting Log Analyzer...
    echo Use --help for command options  
    echo Example: LogAnalyzer.exe --analyze sample_security.log
    echo.
    cd dist
    LogAnalyzer.exe
    cd ..
    goto menu
)

if "%choice%"=="3" (
    echo.
    echo Starting Security Analyzer...
    echo Use --help for command options
    echo Example: SecurityAnalyzer.exe --comprehensive
    echo.
    cd dist
    SecurityAnalyzer.exe
    cd ..
    goto menu
)

if "%choice%"=="4" (
    echo Goodbye!
    exit /b
)

echo Invalid choice. Please select 1-4.
goto menu
