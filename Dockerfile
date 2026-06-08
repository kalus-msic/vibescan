FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc libpq-dev curl \
    libcairo2 libpango-1.0-0 libpangocairo-1.0-0 libgdk-pixbuf-2.0-0 libffi-dev \
    chromium nodejs npm \
    fonts-liberation ca-certificates \
    libnss3 libnspr4 libatk1.0-0 libatk-bridge2.0-0 libcups2 libdrm2 libxkbcommon0 \
    libxcomposite1 libxdamage1 libxext6 libxfixes3 libxrandr2 libgbm1 libasound2 \
    && npm install -g lighthouse@12 \
    && rm -rf /var/lib/apt/lists/*

ENV CHROME_PATH=/usr/bin/chromium

# Download Tailwind CSS v3 standalone CLI (auto-detect arch)
RUN ARCH=$(dpkg --print-architecture) && \
    if [ "$ARCH" = "arm64" ] || [ "$ARCH" = "aarch64" ]; then \
      TAILWIND_ARCH="tailwindcss-linux-arm64"; \
    else \
      TAILWIND_ARCH="tailwindcss-linux-x64"; \
    fi && \
    curl -sLO "https://github.com/tailwindlabs/tailwindcss/releases/download/v3.4.19/${TAILWIND_ARCH}" \
    && chmod +x "${TAILWIND_ARCH}" \
    && mv "${TAILWIND_ARCH}" /usr/local/bin/tailwindcss

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

RUN if ! getent group app >/dev/null; then addgroup --system app; fi && \
    if ! getent passwd app >/dev/null; then \
        adduser --system --ingroup app --home /home/app --create-home app; \
    fi && \
    mkdir -p /home/app && chown -R app:app /home/app

ENV HOME=/home/app

COPY . .

# Build Tailwind CSS
RUN mkdir -p static/css \
    && tailwindcss -i static/src/input.css -o static/css/style.css --minify

RUN mkdir -p /app/logs && chown -R app:app /app

# Collect static files (dummy secrets for build only, not persisted in runtime env)
RUN SECRET_KEY=build-only DB_PASSWORD=build-only python manage.py collectstatic --noinput

USER app
