@echo off
title CryptoAccess Health Secure 3.0
cd /d "%~dp0"

if not exist venv (
    echo Creando entorno virtual...
    python -m venv venv
)

echo Instalando o verificando dependencias...
.\venv\Scripts\python.exe -m pip install -r requirements.txt

echo Iniciando CryptoAccess Health Secure...
.\venv\Scripts\python.exe main.py
pause
