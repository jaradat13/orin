# Use a lightweight, official Python base image
FROM python:3.12-slim

# Set environment variables for non-interactive installs and python buffering
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

# Install runtime package build and system dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    python3-dev \
    && rm -rf /var/lib/apt/lists/*

# Set working directory
WORKDIR /app

# Copy packaging metadata and install dependencies
COPY pyproject.toml /app/
RUN pip install --no-cache-dir .

# Copy the rest of the source code
COPY . /app/

# Re-install package in non-editable mode
RUN pip install --no-cache-dir .

# Define entrypoint to invoke orin directly
ENTRYPOINT ["orin"]
CMD ["--help"]
