FROM cern/cc7-base
WORKDIR /usr/src/app
COPY . /app
WORKDIR /app

RUN yum install python36-pip python36-virtualenv -y  && \
    pip3.6 install -U pip virtualenv==15.1.0 && \
    virtualenv-3.6 /app/venv && \
    /app/venv/bin/pip install --no-cache-dir -r requirements.txt

EXPOSE 8080
CMD [ "/app/venv/bin/gunicorn", "--bind", "0.0.0.0:8080", "wsgi:app" ]
