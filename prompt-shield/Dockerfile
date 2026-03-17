# ── PromptShield Dockerfile ───────────────────────────────────
FROM python:3.11-slim

WORKDIR /app

# Install dependencies first (layer caching)
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy app code
COPY . .

# Expose port
EXPOSE 8000

# Start server
CMD ["uvicorn", "api.main:app", "--host", "0.0.0.0", "--port", "8000"]