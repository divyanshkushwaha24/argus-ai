FROM python:3.11-slim

# Install system dependencies:
# - build tools & libpq for postgres
# - tcpreplay and iproute2 for Linux network packet replay and virtual tap
# - libpcap and networking utilities
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    g++ \
    libpq-dev \
    iproute2 \
    tcpreplay \
    libpcap-dev \
    curl \
    net-tools \
    procps \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Install Python dependencies first for caching
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application source code
COPY . .

# Set runtime environment
ENV PYTHONUNBUFFERED=1
ENV PYTHONPATH=/app

# Default port for Streamlit dashboard
EXPOSE 8501

# Default entrypoint (Cherenkov Real-Time Streaming Detection Engine)
CMD ["python", "-m", "pipeline.consumer", "up", "--auto-start", "--no-network"]

