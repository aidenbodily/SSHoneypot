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
from pathlib import Path
from unittest import mock

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
                with sqlite3.connect(self.database, timeout=0.2) as connection:
                    count = connection.execute(
                        "SELECT COUNT(*) FROM events WHERE event_type = 'CONNECT'"
                    ).fetchone()[0]
            except sqlite3.Error:
                count = 0
            if count >= minimum:
                return
            time.sleep(0.01)
        self.fail(f"server did not log {minimum} CONNECT events")

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

        with sqlite3.connect(self.database) as connection:
            event_types = {
                row[0] for row in connection.execute("SELECT event_type FROM events")
            }
            stored_passwords = connection.execute(
                "SELECT password FROM events WHERE event_type = 'LOGIN_FAKE'"
            ).fetchall()
        self.assertTrue({"CONNECT", "LOGIN_FAKE", "CMD", "DISCONNECT"} <= event_types)
        self.assertTrue(all(password is None for (password,) in stored_passwords))

    def test_malformed_oversized_and_ssh_clients_are_bounded(self):
        malformed = self.exchange(["NOT_A_REQUEST"])
        self.assertIn("Invalid request", malformed[0])

        with socket.create_connection(("127.0.0.1", self.port), timeout=1) as client:
            client.sendall(b"CMD " + b"x" * 200 + b"\n")
            try:
                self.assertEqual(client.recv(1), b"")
            except ConnectionResetError:
                # A reset is also an acceptable rejection of an oversized request.
                pass

        with socket.create_connection(("127.0.0.1", self.port), timeout=1) as client:
            client.sendall(b"SSH-2.0-OpenSSH_9.0\r\n")
            response = client.makefile("r", encoding="utf-8").readline()
            self.assertIn("not supported", json.loads(response))

    def test_idle_client_times_out(self):
        with socket.create_connection(("127.0.0.1", self.port), timeout=1) as client:
            client.settimeout(1)
            self.assertEqual(client.recv(1), b"")

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


class StartupFailureTests(unittest.TestCase):
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
