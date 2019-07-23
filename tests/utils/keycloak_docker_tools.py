import docker
import time


def tear_down_keycloak_docker():
    """
    Tears down the running instance of Keycloak
    """
    try:
        client = docker.from_env()
        containers = client.containers.list(
            all=True, filters={"name": "keycloak-integration"}
        )
        if len(containers) > 0:
            containers[0].remove(force=True)
    except Exception as ex:
        print(f"Exception tearing down docker container: {ex}")


def create_keycloak_docker():
    """
    Creates a Docker client for keycloak
    """
    try:
        client = docker.from_env()
        containers = client.containers.list(
            all=True, filters={"name": "keycloak-integration"}
        )

        if len(containers) > 0:
            print("Container already exists")
            current_container = containers[0]
            if current_container.status != "running":
                print("Not running, gonna start now")
                current_container.start()
                print("Sleeping for 5 secs so that Keycloak is up")
                time.sleep(5)
        else:
            print("Starting Keycloak container from scratch")
            current_container = client.containers.run(
                "gitlab-registry.cern.ch/authzsvc/docker-images/keycloak",
                name="keycloak-integration",
                ports={"8080/tcp": 8081},
                environment={"KEYCLOAK_USER": "admin",
                             "KEYCLOAK_PASSWORD": "admin"},
                detach=True,
            )
            print("Sleeping for 5 secs so that Keycloak is up")
            time.sleep(5)

        while current_container.status != "running":
            current_container = client.containers.get(current_container.id)
            time.sleep(1)
        print("Keycloak should be working fine now...")
    except Exception as e:
        print(
            f"Exception occured while starting Keycloak container. Make sure you have Docker installed and running, and that your user is allowed to access it!. Exception: {e}")
