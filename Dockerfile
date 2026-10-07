FROM python:3.12-slim
ENV PYTHONUNBUFFERED=1 PIP_NO_CACHE_DIR=1
WORKDIR /srv
COPY requirements.txt .
RUN pip install -r requirements.txt
COPY app ./app
COPY sample_apps ./sample_apps
RUN useradd -m appuser && mkdir -p /srv/data && chown -R appuser /srv
USER appuser
ENV DATA_DIR=/srv/data
CMD ["sh", "-c", "uvicorn app.main:app --host 0.0.0.0 --port ${PORT:-8000}"]
