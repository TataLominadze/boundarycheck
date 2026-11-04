# Docker networking: a beginner-friendly guide

This guide explains the network behavior used by BoundaryCheck's local Compose
example. The secure topology is:

| Service | `app_network` | `db_network` | Host-published port |
| --- | --- | --- | --- |
| NGINX (`proxy`) | Yes | No | `127.0.0.1:8080` to container port 80 |
| FastAPI (`api`) | Yes | Yes | None |
| PostgreSQL (`db`) | No | Yes | None |

The API is the only service attached to both networks. It must receive requests
from NGINX and connect to PostgreSQL. The proxy needs only the application
network; the database needs only the database network.

## Docker bridge networks

A bridge network is a private, software-defined network on a Docker host.
Containers attached to the same user-defined bridge network can communicate
directly using their container ports. Docker Compose creates networks for the
project and attaches each service according to its `networks` declaration.

Compose creates these networks as separate networks, typically with names
prefixed by the Compose project name. Membership in one network does not
automatically make a container a member of another.

## Docker DNS resolution

On a user-defined Docker network, Docker provides DNS resolution for service
names. In this Compose project, the API can connect to the database using host
name `db` and port `5432`; NGINX forwards requests to `api` on port `8000`.
These names resolve for containers sharing the relevant network. They are not
hostnames that should be expected to resolve on the developer's host.

DNS resolution only maps a name to an address. It does not itself grant
network access or authenticate a client. Whether a connection can be made also
depends on network reachability, listening services, firewall rules, and other
controls.

## How containers communicate

Containers on a shared network connect to one another using the destination
service's container port. For this project:

- NGINX sends HTTP to `api:8000` on `app_network`.
- FastAPI sends PostgreSQL traffic to `db:5432` on `db_network`.

The service-to-service traffic does not need a host-published port. In the
secure layout, NGINX and PostgreSQL do not share a network, so the proxy has no
direct network path to the database's address on `db_network`. The API's
membership in both networks is required for the intended application flow; it
also makes the API an important component to protect.

## Published ports versus container ports

A **container port** is the port on which a process listens inside its
container and on the container network. For example, NGINX listens on port 80,
FastAPI on port 8000, and PostgreSQL on port 5432.

A **published port** maps a port on the Docker host to a container port. The
Compose entry `127.0.0.1:8080:80` maps host loopback port 8080 to NGINX
container port 80. Binding to `127.0.0.1` limits this published endpoint to
the local host interface; the configuration does not publish the API or
database ports.

Publishing a port is different from attaching containers to a shared Docker
network. The API and database can communicate over their container ports
without either port being published to the host.

## Docker network isolation

Separate networks limit which containers have direct network connectivity with
one another. In this example, attaching a service only to the network it needs
helps avoid unnecessary paths. It is a useful defense-in-depth measure, not a
substitute for application authentication, database authorization, host
security, or other controls.

Network membership can be inspected using Docker commands. Run these from the
repository root while the secure Compose stack is running:

```sh
docker compose --env-file .env -f docker/compose/compose.yaml ps
docker compose --env-file .env -f docker/compose/compose.yaml config
docker network ls
docker network inspect PROJECT_app_network
docker network inspect PROJECT_db_network
```

Replace `PROJECT` with the Compose project name shown in `docker network ls`;
the default project name is based on the directory name. `docker compose ...
config` shows the resolved service configuration; `docker network ls` shows
created networks. Use `docker network inspect` with the actual network name to
inspect connected containers and addresses. To inspect a container's network
attachments directly, first obtain its ID with
`docker compose --env-file .env -f docker/compose/compose.yaml ps -q proxy`,
then run:

```sh
docker inspect CONTAINER_ID
```

Replace `CONTAINER_ID` with the ID returned by the preceding command.

The secure `proxy` should be listed only on `app_network`. To inspect the
deliberately insecure variant, include both Compose files in each Compose
command, for example:

```sh
docker compose --env-file .env -f docker/compose/compose.yaml -f docker/compose/compose.insecure.yaml config
```

Remember to stop one variant before starting the other: both use host port
`127.0.0.1:8080`.

## Why the reverse proxy should not share the database network

NGINX needs to deliver HTTP requests to FastAPI; it does not need a direct
connection to PostgreSQL. If NGINX is attached to `db_network`, it gains a
direct network path to the database service. A proxy compromise or
misconfiguration could then have a broader set of reachable targets.

The insecure Compose override demonstrates that change by adding `proxy` to
`db_network`. The verification script checks both the network membership and
whether a direct TCP probe to PostgreSQL succeeds. This is a controlled
demonstration of reachability, not a recommendation to run the insecure
configuration outside a local test.

## How network misconfigurations increase attack surface

An unnecessary network attachment can make additional services and ports
reachable from a container. A reachable service may be targeted if the
container is compromised or its configuration is wrong. Broader reachability
can increase the number of paths defenders need to understand, restrict, and
monitor.

Reachability is not the same as successful authentication or authorization:
PostgreSQL can still require valid credentials and permissions. Conversely,
credentials and application checks do not remove the benefit of limiting
unnecessary network paths. Both layers matter.

## Why network separation is not a complete security guarantee

- Docker host administrators and processes with sufficient Docker privileges
  can inspect, change, or join container networks.
- The API is connected to both networks by design. A compromise of that
  service affects a component with access to both sides.
- A failed connection probe can result from service state, test errors, or
  configuration other than network isolation.
- This example checks a specific address, port, and set of paths; it does not
  inventory every protocol, port, route, or exposure.
- Docker network separation does not provide application-level authentication,
  least-privilege database roles, encryption, image security, patch management,
  or host hardening.
- The Compose networks are not declared `internal: true`; network membership
  alone should not be interpreted as a guarantee about all outbound
  connectivity.

Use network separation alongside appropriate identity and access controls,
host protections, secure configuration, logging, patching, and verification
that matches the system's threat model. The Phase 1 verifier can provide
evidence for its specific checks, but cannot certify a deployment.

## Host networking and container isolation

Compose `network_mode: host` places a container in the host's network
namespace instead of attaching it to an ordinary isolated Compose network.
This changes the normal network-membership boundary: the service can use host
network interfaces and ports, and Compose network attachments and port
publishing do not work in the usual way. BoundaryCheck can flag this declared
mode (`BC-CONT-002`) when `no_host_network` is enabled. It does not evaluate
host firewall rules or prove that a host service is reachable.

## Privileged containers

Compose `privileged: true` requests broad Linux capabilities and access to
devices from the host. This significantly weakens the container isolation
provided by a default container. BoundaryCheck reports the explicit setting
as `BC-CONT-001` when `no_privileged_containers` is enabled; it does not
inspect the capabilities or devices granted at runtime. Prefer disabling
privileged mode and granting only individually required capabilities or
devices.

## Docker daemon socket mounts

The Docker daemon socket (commonly `/var/run/docker.sock`) is a control API
for the Docker daemon. A container that can communicate with that socket may
be able to create, inspect, or change Docker resources according to the
daemon's authority. BoundaryCheck reports bind mounts whose source or target
path ends with `docker.sock` as `BC-CONT-003` when `no_docker_socket` is
enabled. This is path-based static detection: it cannot establish that a path
is a live socket, may flag an ordinary file with the same name, cannot
recognize renamed socket paths or Windows named pipes, and cannot prove that
any daemon action was possible or attempted. Avoid mounting the socket; if
Docker API access is essential, prefer a narrowly scoped, authenticated
intermediary.

All three checks inspect normalized Compose declarations only. Findings
describe configuration risk and do not claim exploitation or runtime impact.
