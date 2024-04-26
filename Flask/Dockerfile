# Základný obraz: Python 3
FROM python:3

# Nastaví pracovný adresár v kontajneri
WORKDIR /usr/src/app

# Aktualizuje pip
RUN pip install --no-cache-dir --upgrade pip
# Inštalácia Gunicorn
RUN pip install gunicorn

# Kopíruje súbory requirements.txt do kontajnera a inštaluje závislosti
COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

# Kopíruje všetky súbory projektu do pracovného adresára v kontajneri
COPY . .

# Exponuje port, na ktorom Flask beží
EXPOSE 5000

# Spúšťací príkaz pre Flask aplikáciu
CMD ["flask", "run", "--host=0.0.0.0"]

