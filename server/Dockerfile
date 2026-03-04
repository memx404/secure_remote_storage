FROM python:3.11-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1

RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
 && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY requirements.txt /app/requirements.txt
RUN pip install --upgrade pip && pip install -r requirements.txt

COPY . /app

RUN useradd -m -u 10001 appuser

RUN mkdir -p /app/secure_storage/vault \
 && chown -R appuser:appuser /app/secure_storage \
 && chmod -R 750 /app/secure_storage \
 && chown -R appuser:appuser /app

USER appuser

EXPOSE 5000
ENV SRS_STORAGE=/app/secure_storage

CMD ["gunicorn", "-w", "2", "-b", "0.0.0.0:5000", "server.app:app"]
