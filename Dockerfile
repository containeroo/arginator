FROM python:3.9-alpine

ADD requirements.txt arginator.py /app/

RUN apk add --no-cache --virtual .build-deps gcc musl-dev && \
    pip install -r /app/requirements.txt && \
    apk del .build-deps gcc musl-dev

ENTRYPOINT ['python', '/app/arginator.py']
