FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    STUN_HOST=0.0.0.0 \
    STUN_PORT=3478 \
    STUN_METRICS_HOST=0.0.0.0 \
    STUN_METRICS_PORT=8080

WORKDIR /app
COPY . /app

RUN useradd --system --create-home --home-dir /nonexistent --shell /usr/sbin/nologin stun
USER stun

EXPOSE 3478/udp 8080/tcp
CMD ["python", "app.py"]
