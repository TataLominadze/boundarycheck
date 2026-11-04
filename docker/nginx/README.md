# NGINX configuration

`default.conf` listens on container port 80 and forwards incoming HTTP requests
to the FastAPI service at `api:8000` on the Compose `app_network`. Docker Compose
publishes that listener only on the host's loopback address, port 8080.

Validate through the running Compose environment with
`Invoke-RestMethod http://localhost:8080/health`.
