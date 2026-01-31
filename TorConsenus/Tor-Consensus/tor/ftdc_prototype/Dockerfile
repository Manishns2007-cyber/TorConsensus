# TOR-Unveil FTDC Production Dockerfile
# =====================================
# Multi-stage build for optimized production image

# Stage 1: Build stage
FROM python:3.11-slim as builder

WORKDIR /build

# Install build dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    libpcap-dev \
    && rm -rf /var/lib/apt/lists/*

# Copy requirements and install dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir --user -r requirements.txt

# Stage 2: Production stage
FROM python:3.11-slim

# Security: Run as non-root user
RUN groupadd -r ftdc && useradd -r -g ftdc ftdc

WORKDIR /app

# Install runtime dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    libpcap0.8 \
    curl \
    && rm -rf /var/lib/apt/lists/* \
    && apt-get clean

# Copy Python packages from builder
COPY --from=builder /root/.local /home/ftdc/.local

# Copy application code
COPY --chown=ftdc:ftdc . .

# Create necessary directories
RUN mkdir -p /app/ftdc/uploads /app/ftdc/results /app/ftdc/models /var/log/tor-unveil \
    && chown -R ftdc:ftdc /app /var/log/tor-unveil

# Environment variables
ENV PATH=/home/ftdc/.local/bin:$PATH \
    PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    FLASK_ENV=production \
    PORT=5007 \
    UPLOAD_FOLDER=/app/ftdc/uploads \
    RESULTS_FOLDER=/app/ftdc/results \
    MODELS_FOLDER=/app/ftdc/models \
    LOG_FILE=/var/log/tor-unveil/app.log \
    STREAMLIT_SERVER_PORT=5007 \
    STREAMLIT_SERVER_ADDRESS=0.0.0.0 \
    STREAMLIT_SERVER_HEADLESS=true \
    STREAMLIT_BROWSER_GATHER_USAGE_STATS=false

# Switch to non-root user
USER ftdc

# Expose port
EXPOSE 5007

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:5007/_stcore/health || exit 1

# Run with Streamlit
CMD ["streamlit", "run", "dashboard/main.py"]
