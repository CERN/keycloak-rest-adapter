# Summary

`keycloak-rest-adapter` is a REST API made in Flask that abstracts [Keycloak's Admin REST API](https://www.keycloak.org/docs-api/9.0/rest-api/index.html). It is documented using Swagger: run the application and check the `/swagger-ui` endpoint in your web browser for API documentation.

## Configuration

Register `keycloak-rest-adapter` Keycloak with client credentials enabled. The application needs two roles in Keycloak:

*  Service Account Role `admin` (with full access)
*  `user` (with access for enabling and disabling own credentials).

Copy the configuration example directory to a new directory called `config`.

Edit `config/keycloak_client.cfg` to include your Client ID [`keycloak_rest_adapter_client`] and Client Secret [`keycloak_rest_adapter_client_secret`].

Install certificates in the `config` directory, either from a publicly trusted CA or self signed certificates for testing purposes.

```
openssl req -newkey rsa:2048 -nodes -keyout keycloak-rest-adapter_nopass.key -x509 -days 365 -out keycloak-rest-adapter.crt
```

# Development

## Running locally

In order to run the server locally, the simplest way is to use the flask debug server.

```
pip install -r requirements.txt
FLASK_APP=app.py FLASK_DEBUG=1 flask run
```

## Testing

If you want to run all the integration tests, you'll need to have Docker started on your machine.

To install all the test dependencies:

```
pip install -r test-requirements.txt
```

Then, in the main folder, run:

```
pytest
```

In order to teardown the Keycloak instance running locally on port 8081, set `TEARDOWN = True` in `test_keycloak_api_client.py`.

After the integration tests run you can checkout your things with user/pass: `admin:admin` on `http://localhost:8081`.

## Install dependencies

We manage the dependencies using [pip](https://pypi.org/project/pip/). It is very advisable to install the dependencies in an isolated environment using [virtualenv](https://virtualenv.pypa.io/en/stable/) or a similar tool.

`yum install python3-pip`

Once we have pip installed, we will use it to fulfil the list of dependencies.

```
pip install -r requirements.txt
```

# Docker run

To build the docker container:

```bash
docker build . -t kc-rest
```

To run it exposing the port:

```bash
docker run -d --name keycloak-rest-adapter -p 8080:8080 kc-rest
```

# Systemdfy service

Find the path where the system installed the python script. We will need it to
configure the systemd unit later on.

```
find /usr/lib/ -name keycloak_rest_adapter.py
/usr/lib/python2.7/site-packages/keycloak_rest_adapter-0.1-py2.7.egg/keycloak-rest-adapter/keycloak_rest_adapter.py
```

Create the file **keycloak-rest-adapter.service** on _/etc/systemd/system/_.

Now for its content, we can take a look at the example provided below.
We just need to edit the value of the variable of **ExecStart**,
and make sure it points to the python script returned before.

Example:

```
$ cat /etc/systemd/system/keycloak-rest-adapter.service
[Unit]
Description=Python Keycloak Rest Adapter
After=syslog.target network.target

[Service]
Type=simple
WorkingDirectory=/usr/lib/python2.7/site-packages/
ExecStart=/usr/bin/python /usr/lib/python2.7/site-packages/keycloak_rest_adapter-0.1-py2.7.egg/keycloak-rest-adapter/keycloak_rest_adapter.py
StandardOutput=syslog
StandardError=syslog

[Install]
WantedBy=multi-user.target
```

## Reload systemd daemon

After creating the new systemd unit, we just need to reload the systemd daemon,
so it picks up these new changes.

`systemctl daemon-reload`

## Starting the service

`systemctl start keycloak-rest-adapter.service`

## Real time service logs

`journalctl -u keycloak -f`
