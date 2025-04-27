# Use Playwright's official image with browsers pre-installed
FROM mcr.microsoft.com/playwright/python:v1.27.0-focal

# ---- Poetry installation ----
ENV POETRY_VERSION=2.1.2
RUN curl -sSL https://install.python-poetry.org | python3 - && \
    ln -s /root/.local/bin/poetry /usr/local/bin/poetry

# Set working directory
WORKDIR /app

# Copy project files
COPY pyproject.toml poetry.lock* LICENSE README.md ./
COPY hashcsp ./hashcsp

# Install dependencies
RUN poetry config virtualenvs.create false \
    && poetry install --only main

# Default command
ENTRYPOINT ["hashcsp"]
CMD ["-h"]
