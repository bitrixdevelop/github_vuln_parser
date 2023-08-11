# syntax=docker/dockerfile:1
FROM python:3.11-alpine

ENV PYTHONFAULTHANDLER=1 \
    PYTHONUNBUFFERED=1 \
    PYTHONHASHSEED=random \
    # pip:
    PIP_NO_CACHE_DIR=off \
    PIP_DISABLE_PIP_VERSION_CHECK=on \
    PIP_DEFAULT_TIMEOUT=100 \
    # poetry:
    POETRY_VERSION=1.5.1 \
    POETRY_VIRTUALENVS_CREATE=false \
    POETRY_CACHE_DIR='/var/cache/pypoetry' \
    PYTHONPATH='/app'


WORKDIR /app/app
COPY . /app/

RUN apk add \
        gcc \
        libressl-dev \
        musl-dev \
        libffi-dev && \
    pip install  poetry==${POETRY_VERSION}

RUN poetry install
#USER 2000
CMD python main.py
