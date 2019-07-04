FROM python:3.7-alpine
WORKDIR /usr/src/app
COPY . /app
WORKDIR /app

RUN pip install --no-cache-dir -r requirements.txt

EXPOSE 8080
CMD [ "gunicorn", "--bind", "0.0.0.0:8080", "wsgi:app" ]
