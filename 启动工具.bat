@echo off
chcp 65001 >nul
title 蚂蚁安全 - Windows应急排查工具
cd /d "%~dp0"

echo ========================================
echo   Windows应急排查工具
echo   蚂蚁安全 | www.mayisafe.cn
echo ========================================
echo.

REM 检查Python
python --version >nul 2>&1
if %errorlevel% neq 0 (
    echo [错误] 未检测到Python，请先安装Python 3.8+
    echo 下载地址: https://www.python.org/downloads/
    pause
    exit /b 1
)

REM 检查依赖
python -c "import requests" >nul 2>&1
if %errorlevel% neq 0 (
    echo [提示] 正在安装依赖...
    pip install requests Pillow
)

REM 启动GUI
echo [启动] 正在启动应急排查工具...
python gui_app.py

pause
