# ---- Base image ----
FROM python:3.12-slim AS base

# Install system dependencies
RUN apt-get update && apt-get install -y curl build-essential && rm -rf /var/lib/apt/lists/*

# ---- Poetry installation ----
ENV POETRY_VERSION=2.1.2
RUN curl -sSL https://install.python-poetry.org | python3 - && \
    ln -s /root/.local/bin/poetry /usr/local/bin/poetry

# ---- Copy project ----
WORKDIR /app
COPY pyproject.toml poetry.lock* LICENSE README.md ./
COPY hashcsp ./hashcsp

# ---- Install dependencies using Poetry ----
RUN poetry config virtualenvs.create false \
    && poetry install --only main

# ---- Default command ----
ENTRYPOINT ["hashcsp"]
CMD ["-h"]