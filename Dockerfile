FROM python:3.11-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY main.py .
COPY seed-data.json .

# Allow the container to run connector scripts if mounted
COPY config.yaml ./
COPY common.py ./

ENV SEED_DIR=/app
ENV PORT=8000

EXPOSE 8000

CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000"]
