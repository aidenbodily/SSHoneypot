"""Threaded socket server for the CSE310 networking exercise."""

import argparse
import json
import os
import signal
import socket
import sqlite3
import sys
import threading
import time
from contextlib import closing
from datetime import datetime, timezone
from pathlib import Path

# Local demonstration defaults. AWS overrides these through command-line options.
HOST = "127.0.0.1"
PORT = 2222
DATABASE = Path(__file__).resolve().parent / "attacks.db"
PROMPT = "root@server:~$"  # Display a believable prompt for the imaginary shell.

# Bound every client-controlled resource so one connection cannot grow forever.
MAX_REQUEST_BYTES = 4096
IDLE_TIMEOUT_SECONDS = 15
MAX_SESSION_SECONDS = 120
MAX_REQUESTS_PER_SESSION = 100
MAX_CLIENTS = 16

# Captured-data controls. Password storage stays off unless explicitly requested.
RETENTION_DAYS = 0
STORE_PASSWORDS = False
MAX_DATABASE_BYTES = 50 * 1024 * 1024
DATABASE_BUSY_TIMEOUT_SECONDS = 5
DATABASE_RETRIES = 3
SHUTDOWN_GRACE_SECONDS = 20

# These primitives coordinate database writes, client limits, and clean shutdown.
client_slots = threading.BoundedSemaphore(MAX_CLIENTS)
database_lock = threading.Lock()
shutdown_event = threading.Event()
fatal_error_event = threading.Event()
shutdown_lock = threading.Lock()
shutdown_reason = None
active_clients = set()
active_threads = set()
active_clients_lock = threading.Lock()


def clean_for_log(value, limit=256):
    """Keep stored text short and make control characters harmless to display."""
    if value is None:
        return None
    cleaned = "".join(
        character
        if character.isprintable() and character not in "\r\n\t"
        else f"\\x{ord(character):02x}"
        for character in str(value)
    )
    return cleaned[:limit]


def request_shutdown(reason, fatal=True):
    """Request one coordinated stop and preserve the first reason."""
    global shutdown_reason
    with shutdown_lock:
        if shutdown_reason is None:
            shutdown_reason = reason
            print(f"Shutdown requested: {reason}", file=sys.stderr)
    if fatal:
        fatal_error_event.set()
    shutdown_event.set()


def database_size_bytes():
    """Include SQLite's temporary WAL and shared-memory files in the limit."""
    return sum(
        path.stat().st_size
        for path in (
            DATABASE,
            Path(f"{DATABASE}-wal"),
            Path(f"{DATABASE}-shm"),
        )
        if path.exists()
    )


def check_database_size():
    """Fail closed when storage usage cannot be checked or reaches its cap."""
    try:
        size = database_size_bytes()
    except OSError as error:
        request_shutdown(f"cannot inspect database size: {error}")
        return False
    if size >= MAX_DATABASE_BYTES:
        request_shutdown(
            f"database size limit reached ({size} of {MAX_DATABASE_BYTES} bytes)"
        )
        return False
    return True


def open_database():
    """Open one short-lived connection with a bounded SQLite lock wait."""
    connection = sqlite3.connect(DATABASE, timeout=DATABASE_BUSY_TIMEOUT_SECONDS)
    connection.execute(
        f"PRAGMA busy_timeout = {int(DATABASE_BUSY_TIMEOUT_SECONDS * 1000)}"
    )
    return connection


def run_database_write(operation, description):
    """Serialize writes and retry temporary SQLite lock contention."""
    with database_lock:
        if fatal_error_event.is_set() or not check_database_size():
            return False

        for attempt in range(DATABASE_RETRIES + 1):
            try:
                with closing(open_database()) as connection:
                    operation(connection)
                    connection.commit()
                try:
                    DATABASE.chmod(0o600)
                except OSError as error:
                    request_shutdown(f"cannot secure database permissions: {error}")
                    return False
                return check_database_size()
            except sqlite3.OperationalError as error:
                temporary_lock = any(
                    text in str(error).lower() for text in ("locked", "busy")
                )
                if temporary_lock and attempt < DATABASE_RETRIES:
                    time.sleep(0.05 * (2**attempt))
                    continue
                request_shutdown(f"database {description} failed: {error}")
                return False
            except (sqlite3.DatabaseError, OSError) as error:
                request_shutdown(f"database {description} failed: {error}")
                return False

        return False


def initialize_database():
    """Create the schema and remove expired rows before accepting clients."""
    try:
        DATABASE.parent.mkdir(parents=True, exist_ok=True)
    except OSError as error:
        request_shutdown(f"cannot create database directory: {error}")
        return False

    def create_schema(connection):
        # WAL permits readers while the serialized writer commits an event.
        connection.execute("PRAGMA journal_mode = WAL")
        connection.execute("PRAGMA synchronous = NORMAL")
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS events (
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
        # Retention cleanup runs at startup, before new sessions are accepted.
        if RETENTION_DAYS > 0:
            cutoff_timestamp = datetime.fromtimestamp(
                datetime.now(timezone.utc).timestamp()
                - RETENTION_DAYS * 24 * 60 * 60,
                timezone.utc,
            ).isoformat()
            connection.execute(
                "DELETE FROM events WHERE timestamp < ?", (cutoff_timestamp,)
            )

    return run_database_write(create_schema, "initialization")


def log_event(source_ip, event_type, username=None, password=None, command=None):
    """Sanitize and store one event, redacting passwords by default."""
    def insert_event(connection):
        # Use placeholders so input values are not treated as SQL code.
        connection.execute(
            """
            INSERT INTO events
                (timestamp, source_ip, username, password, command, event_type)
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            (
                datetime.now(timezone.utc).isoformat(),
                clean_for_log(source_ip),
                clean_for_log(username),
                clean_for_log(password) if STORE_PASSWORDS else None,
                clean_for_log(command),
                event_type,
            ),
        )

    return run_database_write(insert_event, f"write for {event_type}")


def fake_command_output(command):
    # A dictionary keeps fixed replies easy to read and extend.
    # These strings describe an imaginary Linux server, never this computer.
    replies = {
        "ls": "backups  notes.txt  scripts",
        "ls /": "bin  boot  dev  etc  home  lib  opt  proc  root  run  sbin  sys  tmp  usr  var",
        "ls -a": ".  ..  .bashrc  .ssh  backups  notes.txt  scripts",
        "ls -la": (
            "total 12\n"
            "drwx------ 2 root root 4096 Oct  1 09:00 .ssh\n"
            "drwxr-xr-x 2 root root 4096 Oct  1 09:00 backups\n"
            "-rw-r--r-- 1 root root   42 Oct  1 09:00 notes.txt\n"
            "drwxr-xr-x 2 root root 4096 Oct  1 09:00 scripts"
        ),
        "whoami": "root",
        "pwd": "/root",
        "hostname": "server",
        "id": "uid=0(root) gid=0(root) groups=0(root)",
        "uname": "Linux",
        "uname -a": "Linux server 5.15.0-91-generic #101-Ubuntu SMP x86_64 GNU/Linux",
        "uptime": "10:00:00 up 12 days, 3:42, 1 user, load average: 0.01, 0.03, 0.00",
        "df -h": "Filesystem      Size  Used Avail Use% Mounted on\n/dev/sda1        40G   12G   28G  30% /",
        "free -h": "              total  used  free\nMem:           2.0Gi 512Mi 1.5Gi\nSwap:          1.0Gi    0B 1.0Gi",
        "ps": "    PID TTY          TIME CMD\n   1042 pts/0    00:00:00 bash\n   1043 pts/0    00:00:00 ps",
        "ps aux": (
            "USER       PID %CPU %MEM    VSZ   RSS TTY      STAT START   TIME COMMAND\n"
            "root         1  0.0  0.3 167000  6400 ?        Ss   Oct01   0:02 /sbin/init\n"
            "root       812  0.0  0.2  15400  4200 ?        Ss   Oct01   0:00 sshd: /usr/sbin/sshd -D\n"
            "root      1042  0.0  0.1   8200  3100 pts/0    Ss   10:00   0:00 bash\n"
            "root      1043  0.0  0.1  10000  2400 pts/0    R+   10:00   0:00 ps aux"
        ),
        # The interface address and MAC are fictional; no host information is read.
        "ip addr": (
            "1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 state UNKNOWN\n"
            "    inet 127.0.0.1/8 scope host lo\n"
            "2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 state UP\n"
            "    link/ether 02:00:00:00:00:10 brd ff:ff:ff:ff:ff:ff\n"
            "    inet 10.0.0.10/24 scope global eth0"
        ),
        "ss -tuln": (
            "Netid State  Recv-Q Send-Q Local Address:Port Peer Address:Port\n"
            "tcp   LISTEN 0      128    0.0.0.0:22        0.0.0.0:*"
        ),
        "cat /etc/hostname": "server",
        "cat /etc/shadow": "cat: /etc/shadow: Permission denied",
        # This is a canned example, not the current client's actual history.
        "history": "    1  whoami\n    2  pwd\n    3  ls\n    4  hostname",
        "cat /etc/passwd": (
            "root:x:0:0:root:/root:/bin/bash\n"
            "www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin"
        ),
        "cat /etc/os-release": 'NAME="Ubuntu"\nVERSION="22.04.3 LTS (Jammy Jellyfish)"',
        "cat notes.txt": "Reminder: check backups before the next maintenance window.",
    }
    if command in replies:
        return replies[command]

    if command == "help":
        return "Available commands:\n" + "\n".join(replies) + "\necho <text>\nhelp"
    if command == "echo" or command.startswith("echo "):
        return command[5:]
    if command.startswith("cat "):
        return f"cat: {command[4:]}: No such file or directory"
    return f"bash: {command}: command not found"


def response_for(line, logged_in=False):
    """Interpret one custom-protocol request without executing host commands."""
    parts = line.split(" ", 2)
    request = parts[0].upper()

    # The shell is imaginary; valid-looking credentials only flip local session state.
    if request == "LOGIN" and len(parts) == 3 and parts[1] and parts[2]:
        return f"Welcome to Ubuntu 22.04.3 LTS\n{PROMPT}\n", False

    if request == "CMD" and len(parts) >= 2 and line[4:].strip():
        if not logged_in:
            return f"Please send LOGIN <user> <pass> first.\n{PROMPT}\n", False
        command = line[4:].strip()  # Preserve spaces inside command arguments.
        return f"{fake_command_output(command)}\n{PROMPT}\n", False

    if line.upper() == "LOGOUT":
        return "Goodbye.\n", True

    return f"Invalid request.\n{PROMPT}\n", False


def read_request(client_socket, pending_bytes):
    """Read one bounded newline-terminated request from a client socket."""
    while b"\n" not in pending_bytes:
        if len(pending_bytes) > MAX_REQUEST_BYTES:
            raise ValueError("request exceeded the byte limit")
        chunk_size = min(1024, MAX_REQUEST_BYTES + 1 - len(pending_bytes))
        chunk = client_socket.recv(chunk_size)
        if not chunk:
            return None, pending_bytes
        pending_bytes.extend(chunk)

    raw_line, _, remaining = pending_bytes.partition(b"\n")
    if len(raw_line) > MAX_REQUEST_BYTES:
        raise ValueError("request exceeded the byte limit")
    return raw_line.rstrip(b"\r").decode("utf-8", errors="replace"), bytearray(remaining)


def handle_client(client_socket, client_address):
    """Serve one isolated fake-shell session and record its activity."""
    print(f"Connected by {client_address}")
    source_ip = client_address[0]
    logged_in = False  # Each client starts with its own simulated login state.

    try:
        with client_socket:
            # Stop serving if an event cannot be stored; silent data loss is unsafe.
            if not log_event(source_ip, "CONNECT"):
                return
            client_socket.settimeout(IDLE_TIMEOUT_SECONDS)
            pending_bytes = bytearray()
            session_started = time.monotonic()
            request_count = 0

            while (
                request_count < MAX_REQUESTS_PER_SESSION
                and not shutdown_event.is_set()
            ):
                # Monotonic time cannot jump when the system clock is adjusted.
                elapsed = time.monotonic() - session_started
                remaining_session = MAX_SESSION_SECONDS - elapsed
                if remaining_session <= 0:
                    print(f"Session time limit reached: {client_address}")
                    break
                client_socket.settimeout(
                    min(IDLE_TIMEOUT_SECONDS, remaining_session)
                )

                line, pending_bytes = read_request(client_socket, pending_bytes)
                if line is None:
                    break
                request_count += 1

                parts = line.split(" ", 2)
                request = parts[0].upper()
                print(f"Request type: {request}")

                # Close real SSH attempts: this exercise uses a text protocol.
                if line.startswith("SSH-"):
                    client_socket.sendall(
                        (json.dumps("SSH protocol is not supported.") + "\n").encode()
                    )
                    break

                if request == "LOGIN":
                    username = parts[1] if len(parts) > 1 else None
                    password = parts[2] if len(parts) > 2 else None
                    valid_login = bool(username and password)
                    logged_in = logged_in or valid_login
                    if not log_event(
                        source_ip,
                        "LOGIN_FAKE" if valid_login else "LOGIN_FAIL",
                        username=username,
                        password=password,
                    ):
                        break

                if request == "CMD":
                    command = line[4:] if len(line) >= 4 else ""
                    if not log_event(source_ip, "CMD", command=command):
                        break

                response, should_close = response_for(line, logged_in)
                # JSON keeps multiline fake output framed as one response line.
                client_socket.sendall((json.dumps(response) + "\n").encode("utf-8"))

                if should_close:
                    break
            else:
                print(f"Request limit reached: {client_address}")
    except socket.timeout:
        print(f"Client idle timeout: {client_address}")
    except ValueError as error:
        print(f"Client request rejected: {error}")
    except (ConnectionError, OSError, UnicodeError) as error:
        # Treat an unexpected client exit or malformed data as one session ending.
        print(f"Client session ended: {error}")
    finally:
        if not fatal_error_event.is_set():
            log_event(source_ip, "DISCONNECT")
        with active_clients_lock:
            active_clients.discard(client_socket)
            active_threads.discard(threading.current_thread())
        client_slots.release()

        print(f"Disconnected: {client_address}")


def close_active_connections():
    """Wake blocked client threads by closing a snapshot of active sockets."""
    with active_clients_lock:
        clients = list(active_clients)
    for client_socket in clients:
        try:
            client_socket.shutdown(socket.SHUT_RDWR)
        except OSError:
            pass
        try:
            client_socket.close()
        except OSError:
            pass


def wait_for_client_threads():
    """Wait only up to the configured grace period for workers to finish."""
    deadline = time.monotonic() + SHUTDOWN_GRACE_SECONDS
    while True:
        with active_clients_lock:
            threads = list(active_threads)
        if not threads:
            return True
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            print(
                f"Shutdown grace period expired with {len(threads)} client thread(s).",
                file=sys.stderr,
            )
            return False
        for thread in threads:
            thread.join(timeout=min(remaining, 0.25))


def handle_shutdown_signal(signum, _frame):
    """Convert SIGINT or SIGTERM into the server's coordinated stop path."""
    try:
        signal_name = signal.Signals(signum).name
    except ValueError:
        signal_name = str(signum)
    request_shutdown(f"received {signal_name}", fatal=False)


def main():
    global DATABASE
    global MAX_REQUEST_BYTES
    global IDLE_TIMEOUT_SECONDS
    global MAX_SESSION_SECONDS
    global MAX_REQUESTS_PER_SESSION
    global MAX_CLIENTS
    global RETENTION_DAYS
    global STORE_PASSWORDS
    global MAX_DATABASE_BYTES
    global DATABASE_BUSY_TIMEOUT_SECONDS
    global DATABASE_RETRIES
    global SHUTDOWN_GRACE_SECONDS
    global client_slots
    global shutdown_reason

    parser = argparse.ArgumentParser(description="Run the SSH honeypot server")
    parser.add_argument("--host", default=HOST)
    parser.add_argument("--port", type=int, default=PORT)
    parser.add_argument("--database", type=Path, default=DATABASE)
    parser.add_argument("--max-request-bytes", type=int, default=MAX_REQUEST_BYTES)
    parser.add_argument("--idle-timeout", type=float, default=IDLE_TIMEOUT_SECONDS)
    parser.add_argument("--max-session-seconds", type=float, default=MAX_SESSION_SECONDS)
    parser.add_argument("--max-requests", type=int, default=MAX_REQUESTS_PER_SESSION)
    parser.add_argument("--max-clients", type=int, default=MAX_CLIENTS)
    parser.add_argument("--retention-days", type=int, default=RETENTION_DAYS)
    parser.add_argument("--max-database-bytes", type=int, default=MAX_DATABASE_BYTES)
    parser.add_argument(
        "--database-busy-timeout",
        type=float,
        default=DATABASE_BUSY_TIMEOUT_SECONDS,
    )
    parser.add_argument("--database-retries", type=int, default=DATABASE_RETRIES)
    parser.add_argument(
        "--shutdown-grace-seconds", type=float, default=SHUTDOWN_GRACE_SECONDS
    )
    parser.add_argument(
        "--store-passwords",
        action="store_true",
        help="INSECURE: retain submitted passwords in the database",
    )
    args = parser.parse_args()

    if any(
        value <= 0
        for value in (
            args.max_request_bytes,
            args.idle_timeout,
            args.max_session_seconds,
            args.max_requests,
            args.max_clients,
            args.max_database_bytes,
            args.database_busy_timeout,
            args.shutdown_grace_seconds,
        )
    ) or args.retention_days < 0 or args.database_retries < 0:
        parser.error(
            "limits must be positive; retention-days and database-retries "
            "cannot be negative"
        )

    shutdown_event.clear()
    fatal_error_event.clear()
    shutdown_reason = None
    # New database and sidecar files should be readable only by the service user.
    os.umask(0o077)

    DATABASE = args.database
    MAX_REQUEST_BYTES = args.max_request_bytes
    IDLE_TIMEOUT_SECONDS = args.idle_timeout
    MAX_SESSION_SECONDS = args.max_session_seconds
    MAX_REQUESTS_PER_SESSION = args.max_requests
    MAX_CLIENTS = args.max_clients
    RETENTION_DAYS = args.retention_days
    STORE_PASSWORDS = args.store_passwords
    MAX_DATABASE_BYTES = args.max_database_bytes
    DATABASE_BUSY_TIMEOUT_SECONDS = args.database_busy_timeout
    DATABASE_RETRIES = args.database_retries
    SHUTDOWN_GRACE_SECONDS = args.shutdown_grace_seconds
    client_slots = threading.BoundedSemaphore(MAX_CLIENTS)

    if args.host == "0.0.0.0":
        print("WARNING: the server is exposed on every IPv4 interface.")

    if not initialize_database():
        return 1

    signal.signal(signal.SIGTERM, handle_shutdown_signal)
    signal.signal(signal.SIGINT, handle_shutdown_signal)

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server_socket:
        server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

        server_socket.bind((args.host, args.port))

        server_socket.listen(MAX_CLIENTS)
        # A short accept timeout lets the loop notice shutdown requests promptly.
        server_socket.settimeout(1)
        print(f"Server listening on {args.host}:{args.port}")

        try:
            while not shutdown_event.is_set():
                try:
                    client_socket, client_address = server_socket.accept()
                except socket.timeout:
                    continue

                # Reject excess clients instead of creating unbounded threads.
                if not client_slots.acquire(blocking=False):
                    client_socket.close()
                    print(f"Connection limit reached: {client_address}")
                    continue

                client_thread = threading.Thread(
                    target=handle_client,
                    args=(client_socket, client_address),
                    daemon=False,
                )
                # Register before start so shutdown cannot miss a new worker.
                with active_clients_lock:
                    active_clients.add(client_socket)
                    active_threads.add(client_thread)

                try:
                    client_thread.start()
                except RuntimeError:
                    with active_clients_lock:
                        active_clients.discard(client_socket)
                        active_threads.discard(client_thread)
                    client_socket.close()
                    client_slots.release()
                    raise
        finally:
            # Close sockets first, then wait for their worker cleanup to complete.
            shutdown_event.set()
            close_active_connections()
            threads_finished = wait_for_client_threads()

    if not threads_finished:
        return 1
    return 1 if fatal_error_event.is_set() else 0


if __name__ == "__main__":
    raise SystemExit(main())
