FROM python:3.11-slim

WORKDIR /app

RUN apt-get update && apt-get install -y gcc libffi-dev build-essential && rm -rf /var/lib/apt/lists/*

COPY requirements_railway.txt .
RUN pip install --no-cache-dir -r requirements_railway.txt

COPY . .

EXPOSE 8000

CMD ["sh", "-c", "uvicorn main:app --host 0.0.0.0 --port ${PORT:-8000}"]
