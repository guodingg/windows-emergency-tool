# -*- coding: utf-8 -*-
"""
打包脚本 - 将应急排查工具打包为独立可执行文件
Copyright (C) 蚂蚁安全 | www.mayisafe.cn
"""

import os
import sys
import shutil
import subprocess
from pathlib import Path

def check_pyinstaller():
    """检查PyInstaller"""
    try:
        subprocess.run(["pyinstaller", "--version"], capture_output=True)
        return True
    except:
        return False

def install_dependencies():
    """安装依赖"""
    print("[*] 安装依赖库...")
    subprocess.run([sys.executable, "-m", "pip", "install", "requests", "Pillow", "pyinstaller", "-q"])
    print("[*] 依赖安装完成")

def build_executable():
    """构建可执行文件"""
    print("[*] 开始打包...")
    
    # PyInstaller命令行参数
    args = [
        "pyinstaller",
        "--onefile",                    # 打包成单个文件
        "--windowed",                   # Windows GUI模式
        "--name=应急排查工具",           # 输出文件名
        "--add-data=.;.",               # 添加当前目录
        "--hidden-import=tkinter",
        "--hidden-import=tkinter.ttk",
        "--hidden-import=tkinter.scrolledtext",
        "--hidden-import=requests",
        "--hidden-import=PIL",
        "--collect-all=PIL",
        "--console=False",              # 不显示控制台
        "--icon=NONE",                   # 图标（可自定义）
        "gui_app.py"
    ]
    
    subprocess.run(args)
    print("[*] 打包完成")
    print("[*] 可执行文件位于 dist 目录")

def main():
    print("=" * 50)
    print("  Windows应急排查工具 - 打包工具")
    print("  蚂蚁安全 | www.mayisafe.cn")
    print("=" * 50)
    
    if not check_pyinstaller():
        print("[*] PyInstaller未安装，正在安装...")
        install_dependencies()
    
    if os.path.exists("dist"):
        shutil.rmtree("dist")
    if os.path.exists("build"):
        shutil.rmtree("build")
    
    build_executable()
    
    print("\n打包完成！")
    print("请在 dist 目录找到生成的可执行文件")

if __name__ == "__main__":
    main()
