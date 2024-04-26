@echo off


REM Nastavenie premennej s cestou k interpreteru Pythonu
SET PYTHON_PATH=C:\Users\domin\AppData\Local\Programs\Python\Python310\python.exe

REM Odstranenie Docker Compose Kontajnerov
docker-compose down

REM Inštalácia potrebných Python balíčkov
pip install getmac

docker load -i Flask/authchain.tar
REM Spustenie Python skriptu
%PYTHON_PATH% device_id_loader.py

REM Spustenie Docker Compose
#docker-compose build
docker-compose up -d
