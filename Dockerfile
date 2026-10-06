FROM python:3.13-slim-bookworm
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
RUN apt-get update && apt-get install -y --no-install-recommends libseccomp2 && rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir --require-hashes -r requirements.txt
RUN useradd --uid 10001 --create-home checker && mkdir -p /data && chown checker:checker /data
COPY --chown=10001:10001 app ./app
USER 10001:10001
EXPOSE 8094
CMD ["sh", "-c", "python -m app.configuration && exec python -m uvicorn app.main:app --host 0.0.0.0 --port 8094 --workers 1 --no-access-log"]
