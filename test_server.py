"""Integration tests for limits, concurrency, reconnects, and shutdown."""

import json
import signal
import socket
import sqlite3
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from contextlib import closing
from datetime import datetime
from pathlib import Path
from unittest import mock

import paramiko

import server as server_module


PROJECT_DIR = Path(__file__).resolve().parent
SERVER = PROJECT_DIR / "server.py"


def unused_port():
    """Ask the operating system for a currently unused loopback TCP port."""
    with socket.socket() as temporary_socket:
        temporary_socket.bind(("127.0.0.1", 0))
        return temporary_socket.getsockname()[1]


class ServerIntegrationTests(unittest.TestCase):
    def setUp(self):
        # Each test uses a real subprocess and an isolated temporary database.
        self.temporary_directory = tempfile.TemporaryDirectory()
        self.database = Path(self.temporary_directory.name) / "attacks.db"
        self.port = unused_port()
        self.process = subprocess.Popen(
            [
                sys.executable,
                "-u",
                str(SERVER),
                "--host",
                "127.0.0.1",
                "--port",
                str(self.port),
                "--database",
                str(self.database),
                "--protocol",
                "legacy",
                "--max-request-bytes",
                "128",
                "--idle-timeout",
                "0.3",
                "--max-session-seconds",
                "2",
                "--max-requests",
                "8",
                "--max-clients",
                "16",
                "--max-database-bytes",
                str(1024 * 1024),
                "--database-busy-timeout",
                "0.2",
                "--database-retries",
                "2",
                "--shutdown-grace-seconds",
                "2",
            ],
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
        )
        self.wait_until_listening()

    def tearDown(self):
        # Give the normal SIGTERM path a chance before forcing a stuck process down.
        if self.process.poll() is None:
            self.process.send_signal(signal.SIGTERM)
            try:
                self.process.communicate(timeout=4)
            except subprocess.TimeoutExpired:
                self.process.kill()
                self.process.communicate()
        self.temporary_directory.cleanup()

    def wait_until_listening(self):
        deadline = time.monotonic() + 4
        while time.monotonic() < deadline:
            if self.process.poll() is not None:
                output = self.process.communicate()[0]
                self.fail(f"server exited during startup:\n{output}")
            try:
                with socket.create_connection(
                    ("127.0.0.1", self.port), timeout=0.1
                ):
                    return
            except OSError:
                time.sleep(0.03)
        self.fail("server did not begin listening")

    def wait_for_connect_events(self, minimum):
        """Block until the server has logged at least `minimum` CONNECT events.

        The startup probe in wait_until_listening accounts for the first one.
        """
        deadline = time.monotonic() + 2
        while time.monotonic() < deadline:
            try:
                with closing(
                    sqlite3.connect(self.database, timeout=0.2)
                ) as connection:
                    count = connection.execute(
                        "SELECT COUNT(*) FROM events WHERE event_type = 'CONNECT'"
                    ).fetchone()[0]
            except sqlite3.Error:
                count = 0
            if count >= minimum:
                return
            time.sleep(0.01)
        self.fail(f"server did not log {minimum} CONNECT events")

    def wait_for_finished_session(self, session_id):
        """Return completed metadata after the worker has finalized its session."""
        deadline = time.monotonic() + 2
        while time.monotonic() < deadline:
            with closing(sqlite3.connect(self.database)) as connection:
                connection.row_factory = sqlite3.Row
                session = connection.execute(
                    """
                    SELECT * FROM sessions
                    WHERE session_id = ? AND ended_at IS NOT NULL
                    """,
                    (session_id,),
                ).fetchone()
            if session is not None:
                return session
            time.sleep(0.01)
        self.fail(f"session {session_id} was not finalized")

    def wait_for_disconnect_reason(self, reason):
        """Return the latest completed session with the requested reason."""
        deadline = time.monotonic() + 2
        while time.monotonic() < deadline:
            with closing(sqlite3.connect(self.database)) as connection:
                connection.row_factory = sqlite3.Row
                session = connection.execute(
                    """
                    SELECT * FROM sessions
                    WHERE disconnect_reason = ? AND ended_at IS NOT NULL
                    ORDER BY started_at DESC
                    LIMIT 1
                    """,
                    (reason,),
                ).fetchone()
            if session is not None:
                return session
            time.sleep(0.01)
        self.fail(f"no completed session recorded reason {reason}")

    def exchange(self, requests):
        """Send protocol requests and decode the server's JSON-line responses."""
        replies = []
        with socket.create_connection(("127.0.0.1", self.port), timeout=1) as client:
            reader = client.makefile("r", encoding="utf-8")
            for request in requests:
                client.sendall((request + "\n").encode())
                line = reader.readline()
                self.assertTrue(line)
                replies.append(json.loads(line))
        return replies

    def test_reconnect_and_logging(self):
        first = self.exchange(["LOGIN root example", "CMD whoami", "LOGOUT"])
        second = self.exchange(["LOGIN admin example", "CMD pwd", "LOGOUT"])
        self.assertIn("root@server", first[0])
        self.assertTrue(first[1].startswith("root\n"))
        self.assertTrue(second[1].startswith("/root\n"))

        with closing(sqlite3.connect(self.database)) as connection:
            event_types = {
                row[0] for row in connection.execute("SELECT event_type FROM events")
            }
            stored_passwords = connection.execute(
                "SELECT password FROM events WHERE event_type = 'LOGIN_FAKE'"
            ).fetchall()
            root_session_id = connection.execute(
                """
                SELECT session_id FROM events
                WHERE event_type = 'LOGIN_FAKE' AND username = 'root'
                """
            ).fetchone()[0]
            admin_session_id = connection.execute(
                """
                SELECT session_id FROM events
                WHERE event_type = 'LOGIN_FAKE' AND username = 'admin'
                """
            ).fetchone()[0]
        self.assertTrue({"CONNECT", "LOGIN_FAKE", "CMD", "DISCONNECT"} <= event_types)
        self.assertTrue(all(password is None for (password,) in stored_passwords))
        self.assertNotEqual(root_session_id, admin_session_id)

        root_session = self.wait_for_finished_session(root_session_id)
        self.assertEqual(root_session["request_count"], 3)
        self.assertEqual(root_session["login_attempts"], 1)
        self.assertEqual(root_session["command_count"], 1)
        self.assertEqual(root_session["disconnect_reason"], "logout")
        self.assertGreaterEqual(root_session["duration_seconds"], 0)

        wall_duration = (
            datetime.fromisoformat(root_session["ended_at"])
            - datetime.fromisoformat(root_session["started_at"])
        ).total_seconds()
        self.assertAlmostEqual(
            root_session["duration_seconds"], wall_duration, delta=0.1
        )

        with closing(sqlite3.connect(self.database)) as connection:
            session_ids = {
                row[0]
                for row in connection.execute(
                    "SELECT session_id FROM events WHERE session_id = ?",
                    (root_session_id,),
                )
            }
            root_event_types = {
                row[0]
                for row in connection.execute(
                    "SELECT event_type FROM events WHERE session_id = ?",
                    (root_session_id,),
                )
            }
        self.assertEqual(session_ids, {root_session_id})
        self.assertEqual(
            root_event_types, {"CONNECT", "LOGIN_FAKE", "CMD", "DISCONNECT"}
        )

    def test_malformed_oversized_and_ssh_clients_are_bounded(self):
        malformed = self.exchange(["NOT_A_REQUEST"])
        self.assertIn("Invalid request", malformed[0])
        failed_login = self.exchange(["LOGIN missing-password"])
        self.assertIn("Invalid request", failed_login[0])

        with socket.create_connection(("127.0.0.1", self.port), timeout=1) as client:
            client.sendall(b"CMD " + b"x" * 200 + b"\n")
            try:
                self.assertEqual(client.recv(1), b"")
            except ConnectionResetError:
                # A reset is also an acceptable rejection of an oversized request.
                pass

        oversized_session = self.wait_for_disconnect_reason("invalid_request")
        self.assertEqual(oversized_session["request_count"], 0)

        with socket.create_connection(("127.0.0.1", self.port), timeout=1) as client:
            client.sendall(b"SSH-2.0-OpenSSH_9.0\r\n")
            response = client.makefile("r", encoding="utf-8").readline()
            self.assertIn("not supported", json.loads(response))

        ssh_session = self.wait_for_disconnect_reason("ssh_probe")
        with closing(sqlite3.connect(self.database)) as connection:
            event_types = {
                row[0]
                for row in connection.execute(
                    "SELECT event_type FROM events WHERE session_id = ?",
                    (ssh_session["session_id"],),
                )
            }
            invalid_count = connection.execute(
                "SELECT COUNT(*) FROM events WHERE event_type = 'INVALID_REQUEST'"
            ).fetchone()[0]
            login_fail_count = connection.execute(
                "SELECT COUNT(*) FROM events WHERE event_type = 'LOGIN_FAIL'"
            ).fetchone()[0]
        self.assertEqual(ssh_session["request_count"], 1)
        self.assertIn("SSH_PROBE", event_types)
        self.assertIn("DISCONNECT", event_types)
        self.assertGreaterEqual(invalid_count, 2)
        self.assertGreaterEqual(login_fail_count, 1)

    def test_idle_client_times_out(self):
        with socket.create_connection(("127.0.0.1", self.port), timeout=1) as client:
            client.settimeout(1)
            self.assertEqual(client.recv(1), b"")

        session = self.wait_for_disconnect_reason("idle_timeout")
        self.assertEqual(session["request_count"], 0)
        self.assertEqual(session["login_attempts"], 0)
        self.assertEqual(session["command_count"], 0)
        self.assertGreaterEqual(session["duration_seconds"], 0.3)
        with closing(sqlite3.connect(self.database)) as connection:
            event_types = {
                row[0]
                for row in connection.execute(
                    "SELECT event_type FROM events WHERE session_id = ?",
                    (session["session_id"],),
                )
            }
        self.assertEqual(event_types, {"CONNECT", "TIMEOUT", "DISCONNECT"})

    def test_concurrent_clients(self):
        failures = []

        def run_client(number):
            try:
                replies = self.exchange(
                    [f"LOGIN user{number} example", "CMD hostname", "LOGOUT"]
                )
                if not replies[1].startswith("server\n"):
                    failures.append(f"unexpected response for client {number}")
            except Exception as error:
                failures.append(f"client {number}: {error}")

        clients = [
            threading.Thread(target=run_client, args=(number,))
            for number in range(12)
        ]
        for client in clients:
            client.start()
        for client in clients:
            client.join(timeout=3)

        self.assertFalse(failures)
        self.assertTrue(all(not client.is_alive() for client in clients))

    def test_sigterm_closes_idle_clients_and_exits_cleanly(self):
        client = socket.create_connection(("127.0.0.1", self.port), timeout=1)
        client.settimeout(2)
        # Wait until the server has accepted this client. A connection still
        # waiting in the listen queue is reset when the listener closes, which
        # is not the graceful-close path this test is checking.
        self.wait_for_connect_events(2)
        self.process.send_signal(signal.SIGTERM)
        output, _ = self.process.communicate(timeout=4)
        self.assertEqual(self.process.returncode, 0, output)
        self.assertEqual(client.recv(1), b"")
        client.close()

        session = self.wait_for_disconnect_reason("server_shutdown")
        self.assertEqual(session["request_count"], 0)
        with closing(sqlite3.connect(self.database)) as connection:
            event_types = {
                row[0]
                for row in connection.execute(
                    "SELECT event_type FROM events WHERE session_id = ?",
                    (session["session_id"],),
                )
            }
        self.assertEqual(event_types, {"CONNECT", "DISCONNECT"})


class SSHIntegrationTests(unittest.TestCase):
    def setUp(self):
        self.temporary_directory = tempfile.TemporaryDirectory()
        directory = Path(self.temporary_directory.name)
        self.database = directory / "attacks.db"
        self.host_key = directory / "ssh_host_rsa_key"
        self.port = unused_port()
        self.process = subprocess.Popen(
            [
                sys.executable,
                "-u",
                str(SERVER),
                "--host",
                "127.0.0.1",
                "--port",
                str(self.port),
                "--database",
                str(self.database),
                "--host-key",
                str(self.host_key),
                "--idle-timeout",
                "1",
                "--max-session-seconds",
                "3",
                "--shutdown-grace-seconds",
                "2",
            ],
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
        )
        deadline = time.monotonic() + 8
        while time.monotonic() < deadline:
            if self.process.poll() is not None:
                self.fail(f"SSH server failed:\n{self.process.communicate()[0]}")
            try:
                with socket.create_connection(
                    ("127.0.0.1", self.port), timeout=0.1
                ):
                    break
            except OSError:
                time.sleep(0.03)
        else:
            self.fail("SSH server did not begin listening")

    def tearDown(self):
        if self.process.poll() is None:
            self.process.send_signal(signal.SIGTERM)
            try:
                self.process.communicate(timeout=4)
            except subprocess.TimeoutExpired:
                self.process.kill()
                self.process.communicate()
        self.temporary_directory.cleanup()

    def connect(self):
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        client.connect(
            "127.0.0.1",
            port=self.port,
            username="root",
            password="definitely-not-real",
            allow_agent=False,
            look_for_keys=False,
            timeout=2,
            banner_timeout=2,
            auth_timeout=2,
        )
        return client

    def wait_for_session(self, reason):
        deadline = time.monotonic() + 3
        while time.monotonic() < deadline:
            with closing(sqlite3.connect(self.database)) as connection:
                connection.row_factory = sqlite3.Row
                row = connection.execute(
                    """
                    SELECT * FROM sessions
                    WHERE disconnect_reason = ? AND ended_at IS NOT NULL
                    ORDER BY started_at DESC LIMIT 1
                    """,
                    (reason,),
                ).fetchone()
            if row is not None:
                return row
            time.sleep(0.02)
        self.fail(f"SSH session was not finalized as {reason}")

    def test_real_ssh_handshake_authentication_and_exec_are_logged(self):
        with self.connect() as client:
            _, stdout, _ = client.exec_command("whoami", timeout=2)
            self.assertEqual(stdout.read().decode().strip(), "root")

        session = self.wait_for_session("command_complete")
        self.assertEqual(session["login_attempts"], 1)
        self.assertEqual(session["command_count"], 1)
        self.assertEqual(session["request_count"], 2)

        with closing(sqlite3.connect(self.database)) as connection:
            events = connection.execute(
                """
                SELECT event_type, username, password, command
                FROM events WHERE session_id = ? ORDER BY id
                """,
                (session["session_id"],),
            ).fetchall()
        self.assertEqual(
            [event[0] for event in events],
            ["CONNECT", "SSH_PROBE", "LOGIN_FAKE", "CMD", "DISCONNECT"],
        )
        self.assertIsNone(events[1][2])
        self.assertEqual(events[3][3], "whoami")

    def test_interactive_ssh_shell_returns_only_fake_output(self):
        with self.connect() as client:
            channel = client.invoke_shell(width=80, height=24)
            channel.settimeout(2)
            welcome = channel.recv(4096).decode()
            self.assertIn(server_module.PROMPT, welcome)
            channel.sendall("pwd\n")
            response = ""
            while server_module.PROMPT not in response:
                response += channel.recv(4096).decode()
            self.assertIn("/root", response)
            channel.sendall("exit\n")
            goodbye = ""
            while "logout" not in goodbye:
                goodbye += channel.recv(4096).decode()
            channel.close()

        session = self.wait_for_session("logout")
        self.assertEqual(session["login_attempts"], 1)
        self.assertEqual(session["command_count"], 2)

    def test_oversized_ssh_exec_request_is_rejected(self):
        with self.connect() as client:
            with self.assertRaises(paramiko.SSHException):
                client.exec_command("x" * 5000, timeout=2)

        session = self.wait_for_session("invalid_request")
        self.assertEqual(session["command_count"], 0)
        with closing(sqlite3.connect(self.database)) as connection:
            invalid_events = connection.execute(
                """
                SELECT COUNT(*) FROM events
                WHERE session_id = ? AND event_type = 'INVALID_REQUEST'
                """,
                (session["session_id"],),
            ).fetchone()[0]
        self.assertEqual(invalid_events, 1)


class StartupFailureTests(unittest.TestCase):
    def test_legacy_database_migration_preserves_events(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            database = Path(temporary_directory) / "legacy.db"
            with closing(sqlite3.connect(database)) as connection:
                connection.execute(
                    """
                    CREATE TABLE events (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        timestamp TEXT NOT NULL,
                        source_ip TEXT NOT NULL,
                        username TEXT,
                        password TEXT,
                        command TEXT,
                        event_type TEXT NOT NULL
                    )
                    """
                )
                connection.execute(
                    """
                    INSERT INTO events
                        (timestamp, source_ip, username, password, command,
                         event_type)
                    VALUES (?, ?, ?, ?, ?, ?)
                    """,
                    (
                        "2026-10-01T00:00:00+00:00",
                        "192.0.2.10",
                        "legacy-user",
                        None,
                        "whoami",
                        "CMD",
                    ),
                )
                connection.commit()

            port = unused_port()
            process = subprocess.Popen(
                [
                    sys.executable,
                    "-u",
                    str(SERVER),
                    "--host",
                    "127.0.0.1",
                    "--port",
                    str(port),
                    "--database",
                    str(database),
                    "--protocol",
                    "legacy",
                    "--retention-days",
                    "1",
                    "--idle-timeout",
                    "0.3",
                    "--shutdown-grace-seconds",
                    "2",
                ],
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
            )
            deadline = time.monotonic() + 4
            while time.monotonic() < deadline:
                if process.poll() is not None:
                    self.fail(f"migration server failed:\n{process.communicate()[0]}")
                try:
                    with socket.create_connection(
                        ("127.0.0.1", port), timeout=0.1
                    ):
                        break
                except OSError:
                    time.sleep(0.03)
            else:
                process.kill()
                self.fail("migration server did not begin listening")

            process.send_signal(signal.SIGTERM)
            output, _ = process.communicate(timeout=4)
            self.assertEqual(process.returncode, 0, output)

            with closing(sqlite3.connect(database)) as connection:
                event_columns = {
                    row[1] for row in connection.execute("PRAGMA table_info(events)")
                }
                legacy_row = connection.execute(
                    """
                    SELECT username, command, event_type, session_id
                    FROM events WHERE username = 'legacy-user'
                    """
                ).fetchone()
                new_session_count = connection.execute(
                    "SELECT COUNT(*) FROM sessions"
                ).fetchone()[0]

        self.assertIn("session_id", event_columns)
        self.assertEqual(legacy_row, ("legacy-user", "whoami", "CMD", None))
        self.assertGreaterEqual(new_session_count, 1)

    def test_database_size_limit_stops_startup(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            database = Path(temporary_directory) / "attacks.db"
            result = subprocess.run(
                [
                    sys.executable,
                    str(SERVER),
                    "--host",
                    "127.0.0.1",
                    "--port",
                    str(unused_port()),
                    "--database",
                    str(database),
                    "--protocol",
                    "legacy",
                    "--max-database-bytes",
                    "1",
                ],
                capture_output=True,
                text=True,
                timeout=4,
            )
        self.assertEqual(result.returncode, 1)
        self.assertIn("database size limit reached", result.stderr)

    def test_unusable_database_path_stops_startup(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            blocking_file = Path(temporary_directory) / "not-a-directory"
            blocking_file.touch()
            result = subprocess.run(
                [
                    sys.executable,
                    str(SERVER),
                    "--database",
                    str(blocking_file / "attacks.db"),
                    "--protocol",
                    "legacy",
                ],
                capture_output=True,
                text=True,
                timeout=4,
            )
        self.assertEqual(result.returncode, 1)
        self.assertIn("cannot create database directory", result.stderr)

    def test_disk_full_error_requests_fatal_shutdown(self):
        original_database = server_module.DATABASE
        original_reason = server_module.shutdown_reason
        try:
            with tempfile.TemporaryDirectory() as temporary_directory:
                server_module.DATABASE = Path(temporary_directory) / "attacks.db"
                server_module.shutdown_event.clear()
                server_module.fatal_error_event.clear()
                server_module.shutdown_reason = None
                with mock.patch.object(
                    server_module,
                    "open_database",
                    side_effect=sqlite3.OperationalError("database or disk is full"),
                ):
                    completed = server_module.run_database_write(
                        lambda connection: None, "test write"
                    )
            self.assertFalse(completed)
            self.assertTrue(server_module.shutdown_event.is_set())
            self.assertTrue(server_module.fatal_error_event.is_set())
            self.assertIn("disk is full", server_module.shutdown_reason)
        finally:
            server_module.DATABASE = original_database
            server_module.shutdown_reason = original_reason
            server_module.shutdown_event.clear()
            server_module.fatal_error_event.clear()


if __name__ == "__main__":
    unittest.main()
