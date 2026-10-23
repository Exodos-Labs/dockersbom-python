import io
import json
import subprocess
import unittest
from contextlib import redirect_stdout
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock, Mock, patch
from uuid import NAMESPACE_DNS, uuid5

import requests

import docker_to_exodos as app

INVENTORY_ID = "11111111-1111-4111-8111-111111111111"
BOM_ID = "22222222-2222-4222-8222-222222222222"
IMAGE_ID = "sha256:" + "a" * 64
SBOM = b'{ "bomFormat": "CycloneDX", "components": [] }\n'


def reply(payload, code=200, status="success"):
    response = requests.Response()
    response.status_code = code
    response._content = json.dumps({"status": status, "payload": payload}).encode()
    return response


def page(children=(), total_pages=1):
    return reply({"data": list(children), "pagination": {"total_pages": total_pages}})


class WorkflowTests(unittest.TestCase):
    def setUp(self):
        self.http = Mock()
        self.client = Mock()
        self.client.containers.get.return_value = SimpleNamespace(
            name="demo", attrs={"Image": IMAGE_ID}
        )
        self.cache, self.uploaded = {}, set()
        hostname = patch.object(app.socket, "gethostname", return_value="blog-host")
        hostname.start()
        self.addCleanup(hostname.stop)
        self.internal_name = f"docker-{uuid5(NAMESPACE_DNS, 'blog-host/demo')}"
        scanner = patch.object(app.subprocess, "run")
        self.scan = scanner.start()
        self.addCleanup(scanner.stop)
        self.scan.side_effect = lambda command, **kwargs: Path(
            command[-1].split("=", 1)[1]
        ).write_bytes(SBOM)
        self.output = io.StringIO()

    def process(self):
        with redirect_stdout(self.output):
            app.process_container(
                self.client, self.http, "container-id", self.cache, self.uploaded
            )

    def test_reuses_child_on_later_page_despite_changed_display_name(self):
        child = {"id": INVENTORY_ID, "name": self.internal_name, "displayname": "Renamed"}
        # A matching grandchild must not be reused as a direct child.
        self.http.request.side_effect = [
            page([{"name": "unrelated", "children": [child]}], total_pages=2),
            page([child], total_pages=2),
        ]
        self.assertEqual(app.inventory_for(self.http, "demo", self.cache), INVENTORY_ID)
        self.assertEqual(app.inventory_for(self.http, "demo", self.cache), INVENTORY_ID)
        self.assertEqual(self.http.request.call_count, 2)
        self.assertEqual(self.http.request.call_args.kwargs["params"]["page"], 2)
        self.assertTrue(all(call.args[0] == "GET" for call in self.http.request.call_args_list))

    def test_created_inventory_id_is_used_for_unchanged_sbom_upload(self):
        responses = iter([page(), reply({"id": INVENTORY_ID}, 201),
                          reply({"bom": {"id": BOM_ID}}, 201)])

        def request(method, url, **kwargs):
            if "files" in kwargs:
                self.assertEqual(kwargs["files"]["file"][1].read(), SBOM)
                self.assertEqual(json.loads(kwargs["data"]["params"]),
                                 {"inventoryroot_id": INVENTORY_ID})
            return next(responses)

        self.http.request.side_effect = request
        self.process()
        create = self.http.request.call_args_list[1].kwargs["json"]
        self.assertEqual(create, {
            "name": self.internal_name, "displayname": "blog-host / demo",
            "organization_id": app.EXODOS_ORGANIZATION_ID,
            "parent_id": app.EXODOS_PARENT_INVENTORY_ID, "is_public": False,
        })
        command = self.scan.call_args.args[0]
        self.assertEqual(command[:6], [app.SYFT_BINARY, "scan", "--from", "docker", IMAGE_ID, "-o"])
        self.assertTrue(self.scan.call_args.kwargs["check"])
        self.assertEqual(self.scan.call_args.kwargs["timeout"], app.SCAN_TIMEOUT)
        self.assertEqual(self.scan.call_args.kwargs["env"]["DOCKER_HOST"], app.DOCKER_SOCKET)
        self.assertFalse(Path(command[-1].split("=", 1)[1]).exists())
        self.assertIn(f"upload accepted: container=demo image={IMAGE_ID}", self.output.getvalue())
        self.assertIn(f"inventory={INVENTORY_ID} bom={BOM_ID}", self.output.getvalue())

    def test_successful_pair_is_skipped_but_another_container_is_uploaded(self):
        self.cache.update({"demo": INVENTORY_ID, "other": INVENTORY_ID})
        self.http.request.return_value = reply({"bom": {"id": BOM_ID}}, 201)
        self.process()
        self.process()
        self.assertEqual(self.http.request.call_count, 1)
        self.client.containers.get.return_value.name = "other"
        self.process()
        self.assertEqual(self.http.request.call_count, 2)
        self.assertEqual(self.scan.call_count, 2)

    def test_failed_syft_does_not_upload_or_mark_success(self):
        self.scan.side_effect = subprocess.CalledProcessError(1, ["syft"])
        self.process()
        self.http.request.assert_not_called()
        self.assertFalse(self.uploaded)
        self.assertIn("error", self.output.getvalue().lower())

    def test_disappearing_container_is_skipped(self):
        self.client.containers.get.side_effect = app.docker.errors.NotFound("gone")
        self.process()
        self.scan.assert_not_called()
        self.http.request.assert_not_called()
        self.assertIn("disappeared", self.output.getvalue())

    def test_startup_then_events_use_original_timestamp_and_api_key(self):
        self.client.containers.list.return_value = [SimpleNamespace(id="existing")]
        events = MagicMock()
        events.__iter__.return_value = iter([{"Actor": {"ID": "started"}, "from": "mutable:tag"}])
        self.client.events.return_value = events
        with patch.multiple(app, EXODOS_API_TOKEN="test-key",
                            EXODOS_ORGANIZATION_ID=INVENTORY_ID,
                            EXODOS_PARENT_INVENTORY_ID=INVENTORY_ID), \
                patch.object(app.time, "time", return_value=123.9), \
                patch.object(app.docker, "DockerClient", return_value=self.client), \
                patch.object(app.requests, "Session") as session, \
                patch.object(app, "process_container") as process, redirect_stdout(self.output):
            app.main()
        self.assertEqual([call.args[2] for call in process.call_args_list], ["existing", "started"])
        self.client.containers.list.assert_called_once_with(sparse=True)
        self.client.events.assert_called_once_with(
            since=123, decode=True, filters={"type": "container", "event": "start"}
        )
        session.return_value.__enter__.return_value.headers.__setitem__.assert_called_once_with(
            "X-API-Key", "test-key"
        )
        events.close.assert_called_once()
        self.client.close.assert_called_once()

    def test_duplicate_children_are_reported_without_creation(self):
        child = {"id": INVENTORY_ID, "name": self.internal_name}
        self.http.request.side_effect = [page([child], 2), page([child], 2)]
        with self.assertRaisesRegex(ValueError, "[Aa]mbiguous"):
            app.inventory_for(self.http, "demo", self.cache)
        self.assertEqual(self.http.request.call_count, 2)
        self.assertFalse(self.cache)

    def test_invalid_creation_responses_are_not_cached(self):
        for response in (reply({"id": INVENTORY_ID}, 200),
                         reply({"id": INVENTORY_ID}, 201, status="error"),
                         reply({}, 201), reply({"id": "not-a-uuid"}, 201)):
            with self.subTest(response=response.json()):
                self.http.request.side_effect = [page(), response]
                with self.assertRaises((ValueError, KeyError)):
                    app.inventory_for(self.http, "demo", self.cache)
                self.assertFalse(self.cache)


if __name__ == "__main__":
    unittest.main()
