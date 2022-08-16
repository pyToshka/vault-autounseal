FROM python:3.11.0b5-alpine
ENV VAULT_URL=""
ENV VAULT_SECRET_SHARES=""
ENV VAULT_SECRET_THRESHOLD=""
ENV NAMESPACE=""
ENV VAULT_ROOT_TOKEN_SECRET=""
ENV VAULT_KEYS_SECRET=""

COPY . /app
WORKDIR /app

RUN  pip install  --use-deprecated=legacy-resolver --no-cache-dir -r ./requirements.txt \
     && chmod +x ./*.py
CMD ["./app.py"]
