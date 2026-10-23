# Docker → Syft → Exodos

A small Python example for a blog post: when a Docker container starts,
generate an image SBOM with Syft and upload it to a child inventory in Exodos.
One script, two Python dependencies, no persistent state.

## Setup

You need Python 3.10+, a running local Docker daemon, and an already installed
[Syft executable](https://github.com/anchore/syft). You also need an Exodos
organization, an existing parent inventory, and an API key allowed to list its
children, create child inventories, and upload SBOMs.

```sh
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements.txt
```

Edit the constants at the top of `docker_to_exodos.py`:

- `EXODOS_ORGANIZATION_ID`: your organization UUID.
- `EXODOS_PARENT_INVENTORY_ID`: the existing parent inventory UUID.
- `SYFT_BINARY`: `syft` on your PATH, or its absolute executable path.
- `DOCKER_SOCKET`: defaults to `unix:///var/run/docker.sock`; adjust for your host.
- `EXODOS_BASE_URL`: defaults to `https://api.exodos.io`.
- `HTTP_TIMEOUT` and `SCAN_TIMEOUT`: seconds; defaults are 30 and 300.

Docker socket access requires appropriate host permissions. Docker Desktop may
use a different socket path. The script passes the same socket to the SDK and Syft.

Keep the token out of the script; the `EXODOS_API_TOKEN` constant reads it from
the environment:

```sh
export EXODOS_API_TOKEN='your-api-key'
python docker_to_exodos.py
```

Press Ctrl+C to stop.

## What happens

1. Scan all containers already running at startup, one at a time.
2. Watch Docker container `start` events, replaying from a timestamp captured
   before listing containers to reduce the startup gap.
3. Inspect each container and scan its immutable `sha256:…` image ID with
   `syft scan --from docker … -o cyclonedx-json=…`, using a temporary directory.
   Event tags are never used as scan targets.
4. Find or create a private child inventory beneath the configured parent.
5. Upload Syft's JSON bytes unchanged, print the inventory UUID and returned
   BOM ID, then remove the temporary files.

The inventory's internal name is `docker-<UUIDv5>`, derived from the hostname and
container name. Its initial display name is `hostname / container-name`.
The lookup checks every page of direct children and ignores nested grandchildren.
A single match is reused; multiple matches produce an ambiguity error.
Display-name changes in Exodos do not affect reuse. Different containers sharing
an image get separate inventories.

The API calls use `X-API-Key`: `GET /api/v1/root-inventories/{parent_id}/children`,
then `POST /api/v1/root-inventories` if needed. Creation must return HTTP 201,
`status="success"`, and `payload.id`. The upload goes to
`POST /api/v1/boms/inventory/bom/upload` with a multipart `file` and a JSON string
`params={"inventoryroot_id":"<resolved UUID>"}`. Its HTTP 201 success response
provides `payload.bom.id`.

Example output (image IDs shortened):

```text
Scanning running containers, then watching for starts. Ctrl+C to stop.
scanning: container=exodos-sbom-demo image=sha256:abc123…
upload accepted: container=exodos-sbom-demo image=sha256:abc123… inventory=11111111-1111-4111-8111-111111111111 bom=22222222-2222-4222-8222-222222222222
```

“Upload accepted” means Exodos accepted the upload. Its asynchronous analysis
may still be running.

## Small manual demo

Use an otherwise idle, disposable Docker host: startup scans **every running
container**. Start the watcher as above, then use another terminal. Choose an
unused container name; this example uses `exodos-sbom-demo`.

```sh
docker run -d --name exodos-sbom-demo alpine:3 sleep 600
# Wait for "upload accepted" in the watcher's terminal.
docker restart exodos-sbom-demo
# The same container/image pair is skipped; no second upload.
docker rm -f exodos-sbom-demo
```

The `docker run` command may download Alpine. The watcher scans the local image
by its inspected ID. To demonstrate startup scanning instead, start the demo
container before launching the watcher.

## Deliberate limits

- Scans cover **images**, not writable container layers or mounted volumes.
- Inventories are rediscovered through Exodos lookup on restart; resolved UUIDs
  are cached only in memory. No local inventory mapping is written.
- Successful `(container name, image ID)` pairs are deduplicated only for this
  process. Restarting the script may upload the same image again.
- Run **one instance per Docker host**. Creation is a simple lookup then POST.
- Event delivery and crash recovery are best-effort. There are no POST retries,
  queues, or analysis-status polling. A failed scan or upload is logged and is
  eligible again on a later start; an event-stream failure exits the script.

## Tests and references

```sh
python -m unittest -v
```

The tests mock Docker, Syft, and HTTP. They do not contact an Exodos account or
touch Docker workloads.

Interfaces checked against the [Exodos OpenAPI schema](https://api.exodos.io/openapi.json),
the [Docker SDK client/events](https://docker-py.readthedocs.io/en/stable/client.html)
and [container inspection](https://docker-py.readthedocs.io/en/stable/containers.html)
documentation, and Syft's [scan targets and Docker socket settings](https://oss.anchore.com/docs/guides/sbom/scan-targets/)
and [output formats](https://oss.anchore.com/docs/guides/sbom/formats/).

## License

[MIT](LICENSE), copyright 2026 Jens Schmidt. You can reuse, modify, and
redistribute this example, including commercially, provided you keep the
copyright and license notice. The software is provided without warranty.
