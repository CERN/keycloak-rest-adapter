FROM cern/cc7-base
WORKDIR /usr/src/app
COPY . .
RUN yum install python2-pip -y  && \
    pip install --no-cache-dir -r requirements.txt
EXPOSE 8080
CMD [ "gunicorn", "--bind", "0.0.0.0:8080","wsgi:app" ]
