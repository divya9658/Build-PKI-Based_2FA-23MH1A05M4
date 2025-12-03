# --- STAGE 1: Builder (Dependency Installation) ---
# Use the same base image for consistency
FROM python:3.11-slim AS builder

# Set working directory
WORKDIR /app

# Copy dependency file and install dependencies (optimizes for caching)
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# --- STAGE 2: Runtime (Minimal Environment Setup, but using the Python image) ---
FROM python:3.11-slim

# 1. Set TZ=UTC environment variable (critical for TOTP time synchronization)
ENV TZ=UTC

# 2. Install system dependencies (cron daemon and timezone data)
RUN apt-get update && \
    # Install cron, tzdata, and ensure necessary libs are present
    apt-get install -y --no-install-recommends \
        cron \
        tzdata \
        libssl-dev \
        libffi-dev \
        build-essential && \
    # Clean up caches
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Set working directory
WORKDIR /app

# 3. Copy installed Python environment from builder stage (ensures all dependencies are available)
COPY --from=builder /usr/local/lib/python3.11/site-packages /usr/local/lib/python3.11/site-packages
COPY --from=builder /usr/local/bin /usr/local/bin

# 4. Copy application code, private key, and cron configuration
COPY api.py .
COPY student_private.pem .
COPY scripts /app/scripts
COPY crontab.txt /etc/cron.d/crontab-2fa

# 5. Setup cron job (set permissions and install the crontab file)
RUN chmod 0644 /etc/cron.d/crontab-2fa && \
    crontab /etc/cron.d/crontab-2fa

# 6. Create volume mount points
RUN mkdir -p /data /cron && \
    chmod 755 /data /cron

# 7. EXPOSE 8080 (for the FastAPI server)
EXPOSE 8080

# 8. Start cron and application
CMD ["sh", "-c", "cron -f && uvicorn api:app --host 0.0.0.0 --port 8080"]