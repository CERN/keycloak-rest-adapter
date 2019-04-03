FROM cern/cc7-base
WORKDIR /usr/src/app
COPY . /app
WORKDIR /app

RUN yum install python36-pip python36-virtualenv -y  && \
    pip3.6 install -U pip virtualenv && \
    virtualenv-3.6 /app/venv && \
    /app/venv/bin/pip install --no-cache-dir -r requirements.txt

# See this horrible OIDC flask issue: https://github.com/puiterwijk/flask-oidc/issues/52
RUN cat /etc/pki/tls/certs/CERN-bundle.pem >> /app/venv/lib/python3.6/site-packages/httplib2/cacerts.txt

EXPOSE 8080
CMD [ "/app/venv/bin/gunicorn", "--bind", "0.0.0.0:8080", "wsgi:app" ]
