FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1
WORKDIR /app

RUN useradd --uid 10001 --create-home sentinelmesh
COPY pyproject.toml README.md LICENSE ./
COPY src/ src/
COPY scripts/generate_sample_data.py scripts/generate_sample_data.py
RUN python -m pip install --no-cache-dir . \
    && chown -R sentinelmesh:sentinelmesh /app

USER sentinelmesh
CMD ["sh", "-c", "python scripts/generate_sample_data.py && exec sentinelmesh analyze"]
