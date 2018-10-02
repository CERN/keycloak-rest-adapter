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
pip install Flask
pip install Flask-RESTful
pip install flask_oidc
```

### Actual package installation

```python setup.py install```

Example output:
```
python setup.py install
running install
running bdist_egg
running egg_info
writing requirements to keycloak_rest_adapter.egg-info/requires.txt
writing keycloak_rest_adapter.egg-info/PKG-INFO
writing top-level names to keycloak_rest_adapter.egg-info/top_level.txt
writing dependency_links to keycloak_rest_adapter.egg-info/dependency_links.txt
package init file 'keycloak-rest-adapter/__init__.py' not found (or not a regular file)
reading manifest file 'keycloak_rest_adapter.egg-info/SOURCES.txt'
writing manifest file 'keycloak_rest_adapter.egg-info/SOURCES.txt'
installing library code to build/bdist.linux-x86_64/egg
running install_lib
running build_py
copying keycloak-rest-adapter/keycloak_rest_adapter.py -> build/lib/keycloak-rest-adapter
creating build/bdist.linux-x86_64/egg
creating build/bdist.linux-x86_64/egg/keycloak-rest-adapter
copying build/lib/keycloak-rest-adapter/keycloak_rest_adapter.py -> build/bdist.linux-x86_64/egg/keycloak-rest-adapter
byte-compiling build/bdist.linux-x86_64/egg/keycloak-rest-adapter/keycloak_rest_adapter.py to keycloak_rest_adapter.pyc
Creating missing __init__.py for keycloak-rest-adapter
byte-compiling build/bdist.linux-x86_64/egg/keycloak-rest-adapter/__init__.py to __init__.pyc
creating build/bdist.linux-x86_64/egg/EGG-INFO
copying keycloak_rest_adapter.egg-info/PKG-INFO -> build/bdist.linux-x86_64/egg/EGG-INFO
copying keycloak_rest_adapter.egg-info/SOURCES.txt -> build/bdist.linux-x86_64/egg/EGG-INFO
copying keycloak_rest_adapter.egg-info/dependency_links.txt -> build/bdist.linux-x86_64/egg/EGG-INFO
copying keycloak_rest_adapter.egg-info/not-zip-safe -> build/bdist.linux-x86_64/egg/EGG-INFO
copying keycloak_rest_adapter.egg-info/requires.txt -> build/bdist.linux-x86_64/egg/EGG-INFO
copying keycloak_rest_adapter.egg-info/top_level.txt -> build/bdist.linux-x86_64/egg/EGG-INFO
creating 'dist/keycloak_rest_adapter-0.1-py2.7.egg' and adding 'build/bdist.linux-x86_64/egg' to it
removing 'build/bdist.linux-x86_64/egg' (and everything under it)
Processing keycloak_rest_adapter-0.1-py2.7.egg
removing '/usr/lib/python2.7/site-packages/keycloak_rest_adapter-0.1-py2.7.egg' (and everything under it)
creating /usr/lib/python2.7/site-packages/keycloak_rest_adapter-0.1-py2.7.egg
Extracting keycloak_rest_adapter-0.1-py2.7.egg to /usr/lib/python2.7/site-packages
keycloak-rest-adapter 0.1 is already the active version in easy-install.pth

Installed /usr/lib/python2.7/site-packages/keycloak_rest_adapter-0.1-py2.7.egg
Processing dependencies for keycloak-rest-adapter==0.1
Searching for requests==2.6.0
Best match: requests 2.6.0
Adding requests 2.6.0 to easy-install.pth file

Using /usr/lib/python2.7/site-packages
Searching for Flask-RESTful==0.3.6
Best match: Flask-RESTful 0.3.6
Processing Flask_RESTful-0.3.6-py2.7.egg
Flask-RESTful 0.3.6 is already the active version in easy-install.pth

Using /usr/lib/python2.7/site-packages/Flask_RESTful-0.3.6-py2.7.egg
Searching for Flask==1.0.2
Best match: Flask 1.0.2
Processing Flask-1.0.2-py2.7.egg
Flask 1.0.2 is already the active version in easy-install.pth
Installing flask script to /usr/bin

Using /usr/lib/python2.7/site-packages/Flask-1.0.2-py2.7.egg
Searching for pytz==2018.4
Best match: pytz 2018.4
Processing pytz-2018.4-py2.7.egg
pytz 2018.4 is already the active version in easy-install.pth

Using /usr/lib/python2.7/site-packages/pytz-2018.4-py2.7.egg
Searching for six==1.11.0
Best match: six 1.11.0
Adding six 1.11.0 to easy-install.pth file

Using /usr/lib/python2.7/site-packages
Searching for aniso8601==3.0.0
Best match: aniso8601 3.0.0
Processing aniso8601-3.0.0-py2.7.egg
aniso8601 3.0.0 is already the active version in easy-install.pth

Using /usr/lib/python2.7/site-packages/aniso8601-3.0.0-py2.7.egg
Searching for click==6.7
Best match: click 6.7
Processing click-6.7-py2.7.egg
click 6.7 is already the active version in easy-install.pth

Using /usr/lib/python2.7/site-packages/click-6.7-py2.7.egg
Searching for itsdangerous==0.24
Best match: itsdangerous 0.24
Processing itsdangerous-0.24-py2.7.egg
itsdangerous 0.24 is already the active version in easy-install.pth

Using /usr/lib/python2.7/site-packages/itsdangerous-0.24-py2.7.egg
Searching for Jinja2==2.10
Best match: Jinja2 2.10
Processing Jinja2-2.10-py2.7.egg
Jinja2 2.10 is already the active version in easy-install.pth

Using /usr/lib/python2.7/site-packages/Jinja2-2.10-py2.7.egg
Searching for Werkzeug==0.14.1
Best match: Werkzeug 0.14.1
Processing Werkzeug-0.14.1-py2.7.egg
Werkzeug 0.14.1 is already the active version in easy-install.pth

Using /usr/lib/python2.7/site-packages/Werkzeug-0.14.1-py2.7.egg
Searching for MarkupSafe==1.0
Best match: MarkupSafe 1.0
Processing MarkupSafe-1.0-py2.7.egg
MarkupSafe 1.0 is already the active version in easy-install.pth

Using /usr/lib/python2.7/site-packages/MarkupSafe-1.0-py2.7.egg
Finished processing dependencies for keycloak-rest-adapter==0.1

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
