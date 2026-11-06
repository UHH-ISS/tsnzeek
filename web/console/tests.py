# (C) 2026 Doganalp Ergenc, written with the assistance of Claude
"""The API of the web interface against temporary control and log directories (no IDS needed)."""
import json
import tempfile
import time
from pathlib import Path

from django.test import Client, SimpleTestCase, override_settings

from ids.catalog import NAMES
from ids.config import Config
from ids.control import validate


class ApiTest(SimpleTestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.control = Path(self.tmp.name) / "control"
        self.logs = Path(self.tmp.name) / "logs"
        self.logs.mkdir()
        self.override = override_settings(TSNZEEK_CONTROL_DIR=self.control, TSNZEEK_LOG_DIR=self.logs)
        self.override.enable()
        self.client = Client(enforce_csrf_checks=True)

    def tearDown(self):
        self.override.disable()
        self.tmp.cleanup()

    def post(self, url, body):
        self.client.get("/")                       # sets the CSRF cookie
        token = self.client.cookies["csrftoken"].value
        return self.client.post(url, json.dumps(body), content_type="application/json", HTTP_X_CSRFTOKEN=token)

    def written(self):
        return json.loads((self.control / "control.json").read_text())

    def test_page_and_state_without_an_ids(self):
        self.assertContains(self.client.get("/"), "TSNZeek console")
        j = self.client.get("/api/state").json()
        self.assertFalse(j["available"])
        self.assertEqual(j["control"], {})

    def test_state_is_passed_through_with_its_age(self):
        self.control.mkdir()
        (self.control / "state.json").write_text(json.dumps({"updated": time.time() - 1, "rules": []}))
        j = self.client.get("/api/state").json()
        self.assertTrue(j["available"] and not j["stale"])
        (self.control / "state.json").write_text(json.dumps({"updated": time.time() - 60, "rules": []}))
        self.assertTrue(self.client.get("/api/state").json()["stale"])

    def test_disable_and_enable_a_rule_by_name_or_number(self):
        self.assertEqual(self.post("/api/rule", {"rule": "srp_request_burst", "enabled": False}).status_code, 200)
        self.assertEqual(self.post("/api/rule", {"rule": 101, "enabled": False}).status_code, 200)
        self.assertEqual(self.written()["disabled_rules"], ["frer_excess_copies", "srp_request_burst"])
        self.post("/api/rule", {"rule": "srp_request_burst", "enabled": True})
        self.assertEqual(self.written()["disabled_rules"], ["frer_excess_copies"])

    def test_config_set_unset_and_reset(self):
        self.post("/api/config", {"set": {"timeout": 20, "frer_history_size": 7}})
        self.assertEqual(self.written()["config"], {"timeout": 20, "frer_history_size": 7})
        self.post("/api/config", {"unset": ["timeout"]})
        self.assertEqual(self.written()["config"], {"frer_history_size": 7})
        self.assertTrue(self.post("/api/reset", {}).json()["ok"])
        self.assertFalse((self.control / "control.json").exists())
        self.assertTrue(self.post("/api/reset", {}).json()["ok"])          # nothing to remove is fine

    def test_what_does_not_validate_is_refused_and_changes_nothing(self):
        self.post("/api/rule", {"rule": "frer_dead_stream", "enabled": False})
        before = self.written()
        for url, body in (("/api/rule", {"rule": "nope", "enabled": False}), ("/api/rule", {"rule": "frer_dead_stream"}),
                          ("/api/config", {"set": {"nope": 1}}), ("/api/config", {"set": {"timeout": "x"}}),
                          ("/api/config", {"set": {"frer_history_size": 2.5}}), ("/api/config", {"set": [], "unset": 1})):
            r = self.post(url, body)
            self.assertEqual(r.status_code, 400, body)
            self.assertFalse(r.json()["ok"])
        self.assertEqual(self.written(), before)

    def test_post_needs_the_csrf_token_and_json(self):
        self.assertEqual(Client(enforce_csrf_checks=True).post("/api/reset", "{}", content_type="application/json").status_code, 403)
        self.client.get("/")
        token = self.client.cookies["csrftoken"].value
        r = self.client.post("/api/rule", "not json", content_type="application/json", HTTP_X_CSRFTOKEN=token)
        self.assertEqual(r.status_code, 400)
        self.assertEqual(self.client.get("/api/rule").status_code, 405)

    def test_what_the_web_writes_is_what_the_ids_accepts(self):
        self.post("/api/rule", {"rule": 203, "enabled": False})
        self.post("/api/config", {"set": {"timeout": 30}})
        disabled, config = validate(self.written(), Config())
        self.assertEqual(disabled, {"srp_request_burst"})
        self.assertEqual(config.timeout, 30.0)
        self.assertLessEqual(disabled, NAMES)

    def test_log_tail_returns_whole_new_lines_only(self):
        log = self.logs / "frer.log"
        log.write_text("".join(json.dumps({"ts": i}) + "\n" for i in range(100)))
        j = self.client.get("/api/logs?name=frer&offset=-1").json()
        self.assertEqual(len(j["lines"]), 60)
        self.assertEqual(json.loads(j["lines"][-1])["ts"], 99)
        with open(log, "a") as f:
            f.write('{"ts": 100}\n{"ts": 10')                              # the second line is not finished
        k = self.client.get(f"/api/logs?name=frer&offset={j['offset']}").json()
        self.assertEqual(k["lines"], ['{"ts": 100}'])
        with open(log, "a") as f:
            f.write("1}\n")
        m = self.client.get(f"/api/logs?name=frer&offset={k['offset']}").json()
        self.assertEqual(m["lines"], ['{"ts": 101}'])
        log.write_text('{"ts": 0}\n')                                      # rotated: a smaller file starts over
        self.assertEqual(self.client.get(f"/api/logs?name=frer&offset={m['offset']}").json()["lines"], ['{"ts": 0}'])

    def test_logs_are_a_whitelist_and_a_missing_one_is_empty(self):
        self.assertEqual(self.client.get("/api/logs?name=../../etc/passwd").status_code, 404)
        self.assertEqual(self.client.get("/api/logs?name=srp").json()["lines"], [])
        self.assertEqual(self.client.get("/api/logs?name=srp&offset=x").status_code, 400)
        (self.logs / "srp.log").write_text("{}\n")
        self.assertEqual(self.client.get("/api/state").json()["logs"], ["srp"])
