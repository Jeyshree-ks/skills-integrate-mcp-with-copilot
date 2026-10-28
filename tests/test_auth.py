import copy
import json
import tempfile
import time
import unittest
from pathlib import Path
from unittest.mock import patch

from fastapi.testclient import TestClient

from src import auth
from src.app import activities, app


class TeacherAuthTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.salt = "01" * 16
        cls.password_hash = auth.hash_password("assigned-test-password", cls.salt)

    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.credentials_file = Path(self.directory.name) / "teachers.json"
        self.credentials_file.write_text(json.dumps({
            "teacher": {"salt": self.salt, "password_hash": self.password_hash}
        }))
        self.path_patch = patch.object(auth, "CREDENTIALS_FILE", self.credentials_file)
        self.path_patch.start()
        self.addCleanup(self.path_patch.stop)
        self.original_activities = copy.deepcopy(activities)
        self.addCleanup(self.restore_activities)
        auth.sessions.clear()
        self.addCleanup(auth.sessions.clear)
        self.client = TestClient(app)
        self.addCleanup(self.client.close)

    def restore_activities(self):
        activities.clear()
        activities.update(self.original_activities)

    def login(self):
        response = self.client.post("/auth/login", json={
            "username": "teacher", "password": "assigned-test-password"
        })
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.headers["cache-control"], "no-store")
        return response.json()["access_token"]

    def test_public_can_read_but_cannot_change_registrations(self):
        response = self.client.get("/activities")
        self.assertEqual(response.status_code, 200)
        self.assertIn("michael@mergington.edu", response.json()["Chess Club"]["participants"])
        for method, action, email in [
            ("POST", "signup", "new@mergington.edu"),
            ("DELETE", "unregister", "michael@mergington.edu"),
        ]:
            with self.subTest(action=action):
                response = self.client.request(
                    method, f"/activities/Chess Club/{action}", params={"email": email}
                )
                self.assertEqual(response.status_code, 401)
        self.assertEqual(activities, self.original_activities)

    def test_invalid_credentials_do_not_create_sessions(self):
        for username, password in [
            ("teacher", "wrong"), ("unknown", "assigned-test-password")
        ]:
            with self.subTest(username=username):
                response = self.client.post("/auth/login", json={
                    "username": username, "password": password
                })
                self.assertEqual(response.status_code, 401)
                self.assertEqual(response.json()["detail"], "Invalid username or password")
        self.assertEqual(auth.sessions, {})

    def test_missing_credentials_report_configuration_error(self):
        self.credentials_file.unlink()
        response = self.client.post("/auth/login", json={
            "username": "teacher", "password": "test"
        })
        self.assertEqual(response.status_code, 503)

    def test_teacher_signup_duplicate_unregister_and_missing_activity(self):
        headers = {"Authorization": f"Bearer {self.login()}"}
        url = "/activities/Chess Club/signup"
        params = {"email": "new@mergington.edu"}
        response = self.client.post(url, params=params, headers=headers)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json(), {
            "message": "Signed up new@mergington.edu for Chess Club"
        })
        self.assertEqual(self.client.post(url, params=params, headers=headers).status_code, 400)
        response = self.client.delete(
            "/activities/Chess Club/unregister", params=params, headers=headers
        )
        self.assertEqual(response.status_code, 200)
        self.assertEqual(activities, self.original_activities)
        self.assertEqual(self.client.delete(
            "/activities/Chess Club/unregister", params=params, headers=headers
        ).status_code, 400)
        self.assertEqual(self.client.post(
            "/activities/Unknown/signup", params=params, headers=headers
        ).status_code, 404)

    def test_logout_revokes_token_and_leaves_other_teacher_session_active(self):
        token = self.login()
        other_token = self.login()
        headers = {"Authorization": f"Bearer {token}"}
        self.assertEqual(self.client.post("/auth/logout", headers=headers).status_code, 200)
        for method, action in [("POST", "signup"), ("DELETE", "unregister")]:
            response = self.client.request(
                method, f"/activities/Chess Club/{action}",
                params={"email": "michael@mergington.edu"}, headers=headers
            )
            self.assertEqual(response.status_code, 401)
        self.assertIn(other_token, auth.sessions)

    def test_expired_and_forged_tokens_are_rejected(self):
        token = self.login()
        auth.sessions[token] = ("teacher", time.monotonic() - 1)
        for value in [token, "forged-token"]:
            for method, action in [("POST", "signup"), ("DELETE", "unregister")]:
                with self.subTest(token=value, action=action):
                    response = self.client.request(
                        method, f"/activities/Chess Club/{action}",
                        params={"email": "michael@mergington.edu"},
                        headers={"Authorization": f"Bearer {value}"}
                    )
                    self.assertEqual(response.status_code, 401)
        self.assertEqual(activities, self.original_activities)

    def test_credentials_file_is_not_public(self):
        self.assertEqual(self.client.get("/static/teachers.json").status_code, 404)
        self.assertEqual(self.client.get("/teachers.json").status_code, 404)

    def test_password_assignment_and_reset(self):
        self.credentials_file.unlink()
        for password in ["first-assigned-password", "second-assigned-password"]:
            with self.subTest(password_reset=self.credentials_file.exists()):
                with patch("sys.argv", ["src.auth", "new-teacher"]), patch(
                    "getpass.getpass", return_value=password
                ), patch("builtins.print"):
                    auth.main()
                record = json.loads(self.credentials_file.read_text())["new-teacher"]
                self.assertNotIn(password, self.credentials_file.read_text())
                self.assertEqual(self.credentials_file.stat().st_mode & 0o777, 0o600)
                self.assertEqual(
                    record["password_hash"], auth.hash_password(password, record["salt"])
                )
                response = self.client.post("/auth/login", json={
                    "username": "new-teacher", "password": password
                })
                self.assertEqual(response.status_code, 200)
        response = self.client.post("/auth/login", json={
            "username": "new-teacher", "password": "first-assigned-password"
        })
        self.assertEqual(response.status_code, 401)


if __name__ == "__main__":
    unittest.main()
