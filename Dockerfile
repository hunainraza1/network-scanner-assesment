FROM python:3.11-slim

WORKDIR /app
COPY scanner2.py .

CMD ["python", "scanner2.py", "192.168.0.0/24", "--json", "--report"]