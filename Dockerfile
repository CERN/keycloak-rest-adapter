FROM cern/cc7-base
WORKDIR /usr/src/app
COPY . .
RUN yum install python2-pip -y  && \
    pip install -U pip && \
    pip install --no-cache-dir -r requirements.txt

# See this horrible OIDC flask issue: https://github.com/puiterwijk/flask-oidc/issues/52
RUN cat /etc/pki/tls/certs/CERN-bundle.pem >> /usr/lib/python2.7/site-packages/httplib2/cacerts.txt
EXPOSE 8080
CMD [ "gunicorn", "--bind", "0.0.0.0:8080", "wsgi:app" ]

