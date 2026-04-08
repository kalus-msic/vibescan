FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc libpq-dev curl \
    libcairo2 libpango-1.0-0 libpangocairo-1.0-0 libgdk-pixbuf-2.0-0 libffi-dev \
    && rm -rf /var/lib/apt/lists/*

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

RUN addgroup --system app && adduser --system --ingroup app app

COPY . .

# Build Tailwind CSS
RUN mkdir -p static/css \
    && tailwindcss -i static/src/input.css -o static/css/style.css --minify

# Collect static files (dummy secrets for build only, not persisted in runtime env)
RUN SECRET_KEY=build-only DB_PASSWORD=build-only python manage.py collectstatic --noinput

RUN chown -R app:app /app
USER app
