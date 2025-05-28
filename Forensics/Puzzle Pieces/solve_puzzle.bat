@echo off
setlocal enabledelayedexpansion

set result=

for /f "delims=" %%i in ('powershell -Command "Get-ChildItem -Path . -Filter *.exe | Sort-Object LastWriteTime | ForEach-Object { $_.Name }"') do (
    echo Running %%i
    for /f %%o in ('%%i') do (
        set output=%%o
        set result=!result!!output! 
    )
)

:: Remove all whitespace using PowerShell and display final cleaned output
for /f %%r in ('powershell -Command "$input = '%result%'; $input -replace '\s',''"') do (
    set cleaned=%%r
)

echo.
echo FinalOutput:!cleaned!
