# Summary

`keycloak-rest-adapter` is a REST API made in Flask that abstracts [Keycloak's Admin REST API](https://www.keycloak.org/docs-api/9.0/rest-api/index.html). It is documented using Swagger: run the application and check the `/swagger-ui` endpoint in your web browser for API documentation.

# Configuration

For security reasons, it is recommended that clients typically be registered in a
custom Keycloak Realm, i.e. not in Master. The REST Adapter is an exception and must be
registered in the Master Realm to be able to create and manage Keycloak clients.

Register `keycloak-rest-adapter` in the your Keycloak instance, in the "master" realm with
client credentials enabled. Enable admin permissions for the REST Adapter in the "Service Account Roles" tab.

Modify `default_adapter_config.py` to contain your configuration, notably:
```
# Keycloak
KEYCLOAK_SERVER = "<Your Keycloak server>"
KEYCLOAK_REALM = "master"
KEYCLOAK_CLIENT_ID = "keycloak-rest-adapter"
KEYCLOAK_CLIENT_SECRET ="<Client Secret>"
```

Now configure OIDC for the REST Adapter. Register `keycloak-rest-adapter` again in Keycloak, this time in realm you use to register clients. Enable Implicit flow since this is used by the Swagger interface.

Modify `default_adapter_config.py` to contain your configuration, notably:
```
# Keycloak server
KEYCLOAK_SERVER = "https://keycloak-dev.cern.ch"
# The realm on which the rest adapter operates
KEYCLOAK_REALM = "cern"
# Client that needs to have admin rights in the 'cern' realm and exist in the 'master' realm
KEYCLOAK_CLIENT_ID = "keycloak-rest-adapter"
# Note that this must be the client secret of the "keycloak-rest-adapter" client in
# the "master" realm
KEYCLOAK_SECRET = "xxxx"
```

If you need to override the default configs, you can set the `KEYCLOAK_REST_ADAPTER_CONFIG` environment variable with the path
to the configuration overrides:

```
export KEYCLOAK_REST_ADAPTER_CONFIG=/opt/config/keycloak-overrides.py
```

# Development

## Setting up the environment

Run the `activate.sh` script using this command. It will create a virtualenv
and install all the project dependencies.

```bash
source activate.sh
```

> Note: this project uses `pip-compile` to generate the requirements.txt file. It should not be edited manually!

## Running locally

In order to run the server locally, the simplest way is to use the flask debug server.

Copy the file `default_adapter_config.py` to `test_adapter_config.py` (`test_adapter_config*.py` files are gitignored)
and override the settings you need to override, most likely `KEYCLOAK_CLIENT_SECRET`:

```
# Note that this must be the client secret of the "keycloak-rest-adapter" client in
# the "master" realm
KEYCLOAK_CLIENT_SECRET = "blah-blah-guid"
```

The `.flaskenv` file will set `KEYCLOAK_REST_ADAPTER_CONFIG=test_adapter_config.py` so that your
configuration overrides are loaded, then you can run

```
flask run
```

and access the swagger api on your local machine.

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

Once we have pip installed, we will use it to fulfill the list of dependencies.

```
PIP_CONFIG_FILE=pip.conf pip install -r requirements.txt
```

On Windows (PowerShell):

```
$env:PIP_CONFIG_FILE="$pwd\pip.conf"
pip install -r requirements.txt
```

## Updating dependencies

We use `pip-compile` to keep track of all project dependencies. The `requirements.in` file lists all dependencies for this
project. To update these (except for the packages that are version locked) run:

```
$ pip-compile -U
```

> Note: `pip-tools` must be installed to run the above command.

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

Create the file **keycloak-rest-adapter.service** on _/etc/systemd/system/_. We
need to edit the value of the variable of **ExecStart**,
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
