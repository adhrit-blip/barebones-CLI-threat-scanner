FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PYTHONPATH=/app

RUN useradd --create-home --uid 10001 appuser
WORKDIR /app
COPY --chown=appuser:appuser . /app/cybersec_project

USER appuser

ENTRYPOINT ["python", "/app/cybersec_project/main.py"]
