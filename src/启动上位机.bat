@echo off
chcp 65001 >nul
cd /d %~dp0
start "" http://127.0.0.1:31416/
py\python.exe pz_host.py
