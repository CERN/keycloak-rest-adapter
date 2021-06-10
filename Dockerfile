FROM python:3.8-slim

WORKDIR /app
COPY . .
ENV PIP_CONFIG_FILE /app/pip.conf

USER root
RUN mkdir -p /var/log/keycloak-rest-adapter/

RUN pip install --no-cache-dir -r requirements.txt

EXPOSE 8080

RUN chown 1001 /var/log/keycloak-rest-adapter/
USER 1001

CMD [ "gunicorn", "--bind", "0.0.0.0:8080", "wsgi:app" ]
