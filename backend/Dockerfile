# Multi-stage production Dockerfile for MailSentra FastAPI Backend
FROM python:3.13-slim as builder

WORKDIR /install
COPY requirements.txt .

RUN apt-get update && apt-get install -y --no-install-recommends gcc && \
    pip install --no-cache-dir --prefix=/install/pkg -r requirements.txt

# Final runtime image
FROM python:3.13-slim

# Create unprivileged system user
RUN groupadd -r mailsentra && useradd -r -g mailsentra -d /app -s /sbin/nologin mailsentra

WORKDIR /app

# Copy installed packages from builder
COPY --from=builder /install/pkg /usr/local

# Copy application source
COPY --chown=mailsentra:mailsentra . .

# Switch to non-root user
USER mailsentra

EXPOSE 8000

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    ENVIRONMENT=production

HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:8000/api/v1/health')" || exit 1

CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000", "--workers", "4"]
