# syntax=docker/dockerfile:1
# Sentri OT — BMS Cybersecurity Compliance Platform
# Multi-stage build for minimal image size

# Stage 1: Frontend Build
FROM node:20-slim AS frontend-builder

WORKDIR /app/frontend

COPY frontend/package*.json ./
RUN npm ci

COPY frontend/ ./
RUN npm run build

# Output: /app/frontend/dist/

# Stage 2: Backend Runtime
FROM python:3.12-slim

LABEL org.opencontainers.image.title="Sentri OT"
LABEL org.opencontainers.image.description="BMS OT Security Compliance Platform"
LABEL org.opencontainers.image.version="1.0.0"

# Install minimal system dependencies for bacpypes
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    libffi-dev \
    curl \
    && rm -rf /var/lib/apt/lists/* \
    && apt-get clean

# Create non-root user
RUN addgroup --system sentri && \
    adduser --system --ingroup sentri --home /app sentri && \
    mkdir -p /data /app/backend && \
    chown -R sentri:sentri /app /data

WORKDIR /app

# Install Python dependencies
COPY backend/requirements.txt /app/backend/requirements.txt
RUN pip install --no-cache-dir -r /app/backend/requirements.txt

# Copy backend source code
COPY backend/ /app/backend/

# Copy frontend build from stage 1
COPY --from=frontend-builder --chown=sentri:sentri /app/frontend/dist/ /app/backend/static/

# Switch to non-root user
USER sentri

# Health check
HEALTHCHECK --interval=30s --timeout=10s --retries=3 --start-period=10s \
    CMD curl --fail http://localhost:8000/api/health || exit 1

EXPOSE 8000

CMD ["uvicorn", "backend.main:app", "--host", "0.0.0.0", "--port", "8000"]
