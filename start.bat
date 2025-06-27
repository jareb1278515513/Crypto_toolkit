@echo off
chcp 65001 >nul
title 密码学工具包 

echo.
echo ================================================================
echo                            密码学工具包
echo ================================================================


:: 检查Python是否安装
echo [检查] 正在检查Python环境...
python --version >nul 2>&1
if errorlevel 1 (
    echo ❌ [错误] 未找到Python，请先安装Python 3.6或更高版本
    echo.
    echo 💡 提示: 请从 https://www.python.org/downloads/ 下载并安装Python
    echo.
    pause
    exit /b 1
)

for /f "tokens=2" %%i in ('python --version 2^>^&1') do set PYTHON_VERSION=%%i
echo ✅ [成功] Python %PYTHON_VERSION% 环境检查通过
echo.

:: 检查pycryptodome库
echo [检查] 正在检查加密库依赖...
python -c "import Crypto" >nul 2>&1
if errorlevel 1 (
    echo ⚠️  [警告] 未找到pycryptodome加密库
    echo [信息] 正在自动安装pycryptodome库...
    echo.
    pip install pycryptodome
    if errorlevel 1 (
        echo ❌ [错误] 自动安装pycryptodome失败
        echo.
        echo 💡 请手动运行以下命令安装:
        echo    pip install pycryptodome
        echo.
        echo 或者尝试:
        echo    python -m pip install pycryptodome
        echo.
        pause
        exit /b 1
    )
    echo ✅ [成功] pycryptodome库安装完成
) else (
    echo ✅ [成功] pycryptodome库检查通过
)

echo.
echo [检查] 依赖库检查完成
echo [启动] 正在启动密码学工具包主程序...
echo.
python crypto_toolkit.py

:check_error
if errorlevel 1 (
    echo.
    echo ❌ [错误] 程序运行时出现错误
    echo.
    echo 💡 故障排除建议:
    echo    1. 确保所有文件完整存在
    echo    2. 检查Python和依赖库是否正确安装
    echo    3. 尝试重新安装pycryptodome库
    echo.
    pause
)
goto exit_program

:exit_program
echo.
echo 👋 感谢使用密码学工具包！
echo.
echo 程序已退出，按任意键关闭窗口...
pause >nul