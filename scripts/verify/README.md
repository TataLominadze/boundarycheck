# Verification scripts

The Phase 1 demonstration verifier is [`../verify-demo.sh`](../verify-demo.sh).
First copy `.env.example` to `.env` and review its development-only values.
From the repository root (or using the script's full path), run it with Bash,
Docker Compose V2, and a running Docker daemon:

```sh
bash scripts/verify-demo.sh
```

The script starts the secure and insecure Compose projects sequentially because
both use host port `127.0.0.1:8080`. It assigns unique project names and waits
up to 90 seconds for all containers to run and configured health checks to
pass. It then runs these checks in both configurations:

- NGINX `/health` returns FastAPI's healthy response, checking proxy forwarding.
- FastAPI `/db-check` returns `database: connected` and `query_result: 1`,
  checking its PostgreSQL query.
- FastAPI and PostgreSQL have no Docker host port bindings.
- Secure: NGINX is not a member of `db_network`, and direct database TCP
  access from the proxy's network namespace is blocked.
- Insecure: NGINX is a member of `db_network`, and direct database TCP access
  from the proxy's network namespace succeeds.

The insecure membership is a violation because NGINX is not intended to have
any direct network path to PostgreSQL; only FastAPI needs that path.

For the TCP probe, a temporary `postgres:16-alpine` diagnostic container uses
`--network container:<proxy-id>` to share the proxy's network namespace. It
connects to the database container's IP on `db_network`, not a DNS name. A
successful `pg_isready` probe means the port responds and PostgreSQL accepts
connections. In the secure case, only the expected no-response exit status
counts as blocked; other failures are not treated as proof of isolation.

Every verification is labeled `PASS` or `FAIL`; any failed check produces a
nonzero exit code. The script explains the insecure policy violation. Its
cleanup removes only the uniquely named demo projects and their own database
volumes. It does not grant privileges or change application images.

A passing secure run establishes that the expected checks passed at that time:
the services are ready, HTTP/database behavior works, the proxy is not on
`db_network`, PostgreSQL is unreachable from its network namespace, and the
API/database ports are not published on the host. A passing insecure run
demonstrates the violation: the proxy is connected to the DB network and can
reach PostgreSQL over TCP. A failed connection test alone cannot prove that
the infrastructure is secure: it may reflect a service or test issue, and
untested ports, networks, credentials, routes, and other configurations may
still expose access.
