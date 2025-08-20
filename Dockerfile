# Shield4U Crawler Service Dockerfile
# Lightweight Python base image
FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=off \
    PIP_DISABLE_PIP_VERSION_CHECK=on \
    DEBIAN_FRONTEND=noninteractive

# Install system dependencies (Chrome, fonts, tools)
# NOTE: libgconf-2-4 (old dependency) removed in Debian trixie; not needed for modern Chrome.
# Add a few current Chrome runtime deps (atk, cups, u2f, xdg-utils) for stability.
RUN apt-get update && apt-get install -y --no-install-recommends \
    wget gnupg ca-certificates unzip \
    libnss3 libxi6 libxcursor1 libxcomposite1 libasound2 libxrandr2 libxdamage1 \
    libgbm1 libxss1 libgtk-3-0 fontconfig locales libatk1.0-0 libatk-bridge2.0-0 \
    libcups2 libu2f-udev libvulkan1 libdrm2 libxshmfence1 xdg-utils && \
    rm -rf /var/lib/apt/lists/*

# Install Google Chrome (stable)
RUN wget -q -O - https://dl.google.com/linux/linux_signing_key.pub | gpg --dearmor -o /usr/share/keyrings/google-linux.gpg && \
    echo "deb [arch=amd64 signed-by=/usr/share/keyrings/google-linux.gpg] https://dl.google.com/linux/chrome/deb/ stable main" > /etc/apt/sources.list.d/google-chrome.list && \
    apt-get update && apt-get install -y --no-install-recommends google-chrome-stable && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY . .

# Default environment
ENV PORT=5001 \
    CONTROLLER_URL=http://controller:5000 \
    REQUEST_TIMEOUT=25

EXPOSE 5001

# Healthcheck (simple HTTP probe)
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD wget -q -O - http://127.0.0.1:${PORT:-5001}/health >/dev/null 2>&1 || exit 1

# Run the crawler service
CMD ["python", "app.py"]
