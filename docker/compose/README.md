# Local Docker Compose environment

`compose.yaml` starts the NGINX reverse proxy, FastAPI backend, and PostgreSQL
database with network isolation:

| Service | `app_network` | `db_network` |
| --- | --- | --- |
| NGINX (`proxy`) | Yes | No |
| FastAPI (`api`) | Yes | Yes |
| PostgreSQL (`db`) | No | Yes |

NGINX can reach FastAPI at `api:8000`, and FastAPI can reach PostgreSQL at
`db:5432`. NGINX has no direct network path to PostgreSQL. Keeping containers
on only the networks they need reduces unnecessary connectivity and limits
which services a compromised or misconfigured container can reach.

`compose.insecure.yaml` is an override for demonstrating one intentional
violation: it adds NGINX to `db_network` while preserving `app_network`. The
application, credentials, host-published port, and container privileges are
unchanged. Compose merges service network lists, so the resolved insecure
configuration contains both proxy networks.

The API connects using the non-superuser role configured by `DB_USER` and
`DB_PASSWORD`. The `postgres` bootstrap account is separate and is used only
for initial database setup. Its initialization SQL runs only for an empty
database volume. Copy `.env.example` to `.env` before running any Compose
commands because the database passwords are intentionally required, not
defaulted in Compose.

## Inspect the resolved configurations

Run from the repository root. The project names make Compose-created network
and volume names distinct between environments.

```powershell
docker compose --env-file .env -p boundarycheck-secure -f docker/compose/compose.yaml config
docker compose --env-file .env -p boundarycheck-insecure -f docker/compose/compose.yaml -f docker/compose/compose.insecure.yaml config
```

In the resolved secure configuration, inspect `services.proxy.networks` and
confirm it lists only `app_network`. The insecure configuration should list
both networks for `proxy`; the API and database should have the same networks
in both configurations. `docker compose config` resolves environment
variables, so its output can include credentials from `.env`; do not share that
output publicly without removing sensitive values.

## Run the offline BoundaryCheck scanner

The scanner uses `docker compose config --format json` to inspect configuration
without starting containers or requiring a running Docker Engine. From the
repository root, provide any required Compose interpolation variables and run:

```sh
PYTHONPATH=src py -3.11 -m boundarycheck scan --compose docker/compose/compose.yaml --policy security-policy.json
PYTHONPATH=src py -3.11 -m boundarycheck scan --compose docker/compose/compose.yaml --compose-override docker/compose/compose.insecure.yaml --policy security-policy.json
```

The secure layout passes; the insecure override fails because `proxy` shares
`db_network` with PostgreSQL. This is static configuration analysis only and
does not verify runtime network connectivity. The scanner suppresses Compose
JSON output because it may contain credentials. See the root
[README](../../README.md) for required interpolation values and test commands.

## Automated Phase 1 demonstration

Run the automated checks from the repository root with Bash and a running
Docker Compose V2 daemon:

```sh
bash scripts/verify-demo.sh
```

The verifier builds and tests both environments sequentially because NGINX
uses the same host port, `127.0.0.1:8080`, in each. It prints labeled results
and returns nonzero if any expected behavior is not observed. It uses unique
Compose project names and removes only those demo projects and their volumes
when finished. See [`scripts/verify/README.md`](../../scripts/verify/README.md)
for details on each check and the TCP probe.

The script uses a temporary `postgres:16-alpine` client container that shares
the NGINX container's network namespace. It probes the database container's IP
directly on port 5432, so DNS name resolution cannot obscure whether TCP
connectivity exists. Shared network membership alone indicates a potential
path, DNS lookup only maps a name to an address, and a successful TCP probe
demonstrates reachability to that address and port at the time of the test.
None alone verifies database authentication or overall infrastructure security.
