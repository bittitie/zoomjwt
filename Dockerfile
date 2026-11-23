FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY zoom_jwt_server.py .

# Run as non-root
RUN useradd --create-home appuser
USER appuser

EXPOSE 8002

CMD ["uvicorn", "zoom_jwt_server:app", "--host", "0.0.0.0", "--port", "8002"]
