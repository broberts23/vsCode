FROM python:3.12-slim

WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends curl \
    && rm -rf /var/lib/apt/lists/*

COPY pyproject.toml README.md ./
COPY src ./src
COPY api ./api
COPY worker ./worker
COPY simulator ./simulator
COPY config ./config
COPY spa ./spa

RUN pip install --no-cache-dir .

ENV PYTHONUNBUFFERED=1
ENV FIXTURES_DIR=/app/config/simulated-events

# Default: API. Override command for worker/simulator in ACA.
EXPOSE 8080
CMD ["uvicorn", "api.main:app", "--host", "0.0.0.0", "--port", "8080"]
