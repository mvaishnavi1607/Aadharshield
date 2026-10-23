FROM python:3.11-slim

ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1
ENV AADHARSHIELD_HOST=0.0.0.0
ENV AADHARSHIELD_PORT=8790

WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends \
    libglib2.0-0 \
    libgl1 \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY aadharshield ./aadharshield

EXPOSE 8790

CMD ["python", "-m", "aadharshield.cli", "serve"]
