# Installation process

> **NOTE:** You will need admin rights in order to install the dependencies and
the package. Make sure you do before starting with the installation process.


### Clone the repo

Make sure you get the latest available version

```git clone https://gitlab.cern.ch/authzsvc/keycloak-rest-adapter.git```

### Install dependencies

This package had soa few dependencies on other packages. For simplicity's sake,
in this example we will be using python pip.

```yum install python2-pip -y```

Once we have pip installed, we will use it to fulfill the list of dependencies.

```
pip install -r requirements.txt
```

# Docker run 

To build the docker container:

```bash
dk build . -t kc-rest 
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

Create the file **keycloak-rest-adapter.service** on */etc/systemd/system/*.


Now for its content, we can take a look at the example provided [here keycloak-rest-adapter.service](https://gitlab.cern.ch/authzsvc/keycloak-rest-adapter/blob/master/etc/systemd/system/keycloak-rest-adapter.service).

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

### Reload systemd daemon

After creating the new systemd unit, we just need to reload the systemd daemon,
so it picks up these new changes.

```systemctl daemon-reload```

### Starting the service

```systemctl start keycloak-rest-adapter.service```

### Real time service logs
```journalctl -u keycloak -f```

# Configuration

# Config files

TODO

# Network

By default the application runs on port 5000, if you are using from
outside you will need to open this port.

```
~$ systemctl start firewalld
~$ sudo firewall-cmd --permanent --add-port=5000/tcp
~$ sudo firewall-cmd --reload
```
>>>>>>> openshift_deployment
