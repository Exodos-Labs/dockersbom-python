"""Watch local Docker starts, generate image SBOMs with Syft, and upload to Exodos."""

import json
import os
import socket
import subprocess
import sys
import time
from contextlib import closing
from pathlib import Path
from tempfile import TemporaryDirectory
from uuid import NAMESPACE_DNS, UUID, uuid5

import docker
import requests

SYFT_BINARY = "syft"
DOCKER_SOCKET = "unix:///var/run/docker.sock"
EXODOS_BASE_URL = "https://api.exodos.io"
EXODOS_ORGANIZATION_ID = ""  # Your organization UUID.
EXODOS_PARENT_INVENTORY_ID = ""  # An existing parent inventory UUID.
EXODOS_API_TOKEN = os.environ.get("EXODOS_API_TOKEN", "")
HTTP_TIMEOUT = 30  # Seconds for HTTP requests and Docker API calls.
SCAN_TIMEOUT = 300  # Seconds per Syft scan.


def api(http, method, path, expected=200, **kwargs):
    """Require the documented HTTP status and Exodos success envelope."""
    response = http.request(
        method, EXODOS_BASE_URL.rstrip("/") + path,
        timeout=HTTP_TIMEOUT, allow_redirects=False, **kwargs,
    )
    if response.status_code != expected:
        raise ValueError(f"Exodos {method} {path}: expected HTTP {expected}, got {response.status_code}")
    body = response.json()
    if not isinstance(body, dict) or body.get("status") != "success":
        raise ValueError(f"Exodos {method} {path}: expected a success envelope")
    if not isinstance(body.get("payload"), dict):
        raise ValueError(f"Exodos {method} {path}: missing payload object")
    return body["payload"]


def inventory_for(http, container_name, cache):
    if container_name in cache:
        return cache[container_name]
    host = socket.gethostname()
    # Stable across restarts and display-name edits; separate for each host/container.
    internal_name = f"docker-{uuid5(NAMESPACE_DNS, f'{host}/{container_name}')}"
    matches, page = [], 1
    while True:
        payload = api(http, "GET", f"/api/v1/root-inventories/{EXODOS_PARENT_INVENTORY_ID}/children",
                      params={"page": page, "page_size": 100})
        # Only inspect this page's direct children, never their nested children.
        matches.extend(child["id"] for child in payload["data"] if child["name"] == internal_name)
        if page >= payload["pagination"]["total_pages"]:
            break
        page += 1
    if len(matches) > 1:
        raise ValueError(f"Ambiguous inventory: {len(matches)} direct children named {internal_name}")
    if not matches:
        payload = api(http, "POST", "/api/v1/root-inventories", expected=201, json={
            "name": internal_name, "displayname": f"{host} / {container_name}",
            "organization_id": EXODOS_ORGANIZATION_ID,
            "parent_id": EXODOS_PARENT_INVENTORY_ID, "is_public": False,
        })
        matches.append(payload["id"])
    inventory_id = str(UUID(str(matches[0])))
    cache[container_name] = inventory_id
    return inventory_id


def report_error(context, error):
    message = str(error)
    if EXODOS_API_TOKEN:
        message = message.replace(EXODOS_API_TOKEN, "[redacted]")
    print(f"error: {context}: {message}", flush=True)


def process_container(client, http, container_id, cache, uploaded):
    name = container_id
    try:
        container = client.containers.get(container_id)  # Inspect; don't trust event tags.
        name, image_id = container.name, container.attrs["Image"]
        pair = (name, image_id)
        if pair in uploaded:
            return
        print(f"scanning: container={name} image={image_id}", flush=True)
        with TemporaryDirectory() as directory:
            sbom_path = Path(directory) / "sbom.cdx.json"
            subprocess.run(
                [SYFT_BINARY, "scan", "--from", "docker", image_id,
                 "-o", f"cyclonedx-json={sbom_path}"],
                env={**os.environ, "DOCKER_HOST": DOCKER_SOCKET},
                check=True, timeout=SCAN_TIMEOUT,
            )
            inventory_id = inventory_for(http, name, cache)
            # Upload Syft's bytes unchanged; requests supplies the multipart boundary.
            with sbom_path.open("rb") as sbom:
                payload = api(http, "POST", "/api/v1/boms/inventory/bom/upload", expected=201,
                              files={"file": (sbom_path.name, sbom, "application/json")},
                              data={"params": json.dumps({"inventoryroot_id": inventory_id})})
            bom_id = str(UUID(str(payload["bom"]["id"])))
        uploaded.add(pair)  # A failed scan/upload remains eligible for a later start.
        print(f"upload accepted: container={name} image={image_id} "
              f"inventory={inventory_id} bom={bom_id}", flush=True)
    except docker.errors.NotFound:
        print(f"skipped: container={name} disappeared before inspection", flush=True)
    except (docker.errors.DockerException, requests.RequestException,
            subprocess.SubprocessError, OSError, ValueError, KeyError, TypeError) as error:
        report_error(f"container={name}", error)


def main():
    if not all((EXODOS_API_TOKEN, EXODOS_ORGANIZATION_ID, EXODOS_PARENT_INVENTORY_ID)):
        raise ValueError("Set the organization/parent UUID constants and export EXODOS_API_TOKEN")
    since = int(time.time())  # Capture before listing, so intervening starts can be replayed.
    cache, uploaded = {}, set()
    with closing(docker.DockerClient(base_url=DOCKER_SOCKET, version="auto",
                                    timeout=HTTP_TIMEOUT)) as client:
        with requests.Session() as http:
            http.headers["X-API-Key"] = EXODOS_API_TOKEN
            print("Scanning running containers, then watching for starts. Ctrl+C to stop.", flush=True)
            for container in client.containers.list(sparse=True):
                process_container(client, http, container.id, cache, uploaded)
            with closing(client.events(since=since, decode=True,
                                       filters={"type": "container", "event": "start"})) as events:
                for event in events:
                    process_container(client, http, event["Actor"]["ID"], cache, uploaded)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\nStopped.")
    except (docker.errors.DockerException, requests.RequestException,
            OSError, ValueError, KeyError, TypeError) as error:
        report_error("startup/event stream", error)
        sys.exit(1)
