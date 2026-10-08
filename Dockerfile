FROM python:3.12-slim
ENV PYTHONUNBUFFERED=1 PIP_NO_CACHE_DIR=1
WORKDIR /srv
COPY requirements.txt .
RUN pip install -r requirements.txt
COPY app ./app
COPY sample_apps ./sample_apps
RUN useradd -m appuser && mkdir -p /srv/data && chown -R appuser /srv
USER appuser
# The Copilot SDK runs a small native runtime (a single binary, no Node.js needed). Fetch it now so the first request
# does not download it and the container does not need to reach the download host at run time.
RUN python -m copilot download-runtime
ENV DATA_DIR=/srv/data
CMD ["sh", "-c", "uvicorn app.main:app --host 0.0.0.0 --port ${PORT:-8000}"]
