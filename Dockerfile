FROM bitnami/python:latest

WORKDIR /app

# Install system dependencies
# Note: psycopg2-binary includes pre-compiled PostgreSQL client, no libpq-dev needed
USER root
RUN install_packages curl

# Copy all project files (src needed for editable install)
COPY pyproject.toml .
COPY README.md .
COPY src/ ./src/

# Install Python dependencies
RUN pip install --no-cache-dir -e .

# Create data directory
RUN mkdir -p /app/data/credentials && chown -R 1001:1001 /app/data

# Switch back to non-root user
USER 1001

# Set PYTHONPATH to ensure src is importable
ENV PYTHONPATH=/app

# Expose Flask port
EXPOSE 5000

# Health check
HEALTHCHECK CMD curl --fail http://localhost:5000/ || exit 1

# Run Flask with Gunicorn
CMD ["gunicorn", "--bind", "0.0.0.0:5000", "--workers", "2", "--threads", "4", "src.app.flask_app:app"]
