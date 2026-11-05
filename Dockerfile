# Python 3.11 (slim keeps the image small)
FROM python:3.11-slim

# no .pyc files; logs go straight to the console (docker logs)
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /app

# install dependencies first so Docker can cache this layer
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# application code, Alembic migrations (the .env file is NOT copied - see .dockerignore)
COPY . .

# run as a normal user, not root
RUN adduser --disabled-password --gecos "" appuser
USER appuser

EXPOSE 8001

# apply database migrations, then start the API.
# Database and JWT settings are read from environment variables supplied by docker-compose.yml
CMD ["sh", "-c", "alembic upgrade head && uvicorn app.main:app --host 0.0.0.0 --port 8001"]
