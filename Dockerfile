# Single stage - use Bitnami Python
FROM bitnami/python:latest

WORKDIR /app

# Copy project files
COPY pyproject.toml .
COPY README.md .
COPY src/ ./src/

# Install dependencies
RUN pip install --no-cache-dir .

# Create data directory
RUN mkdir -p /app/data/credentials

# Set environment
ENV PYTHONPATH=/app

# Expose Flask port
EXPOSE 5000

# Run with gunicorn
CMD ["gunicorn", "--bind", "0.0.0.0:5000", "--workers", "2", "--threads", "4", "src.app.flask_app:app"]
