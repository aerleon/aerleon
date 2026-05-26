FROM python:3.13-slim

WORKDIR /app

# Create a non-root user — RLIMIT_NPROC is enforced per-UID on Linux,
# and root (UID 0) may bypass nproc checks.
RUN useradd -m -u 1001 aerleon_user

# Install aerleon from the repo
COPY pyproject.toml poetry.toml README.md LICENSE ./
COPY aerleon/ ./aerleon/
COPY tools/ ./tools/
RUN pip install --no-cache-dir -e .

# Install Flask (the user's framework)
RUN pip install --no-cache-dir flask

# Copy the reproduction script
COPY repro_tests/BlockingIOErrorFlask/repro_flask_dev.py ./

# Run as non-root user
USER aerleon_user

CMD ["python", "-u", "repro_flask_dev.py"]
