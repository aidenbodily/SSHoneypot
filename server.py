"""Threaded socket server for the CSE310 networking exercise."""

import json
import socket
import sqlite3
import threading
from contextlib import closing
from datetime import datetime, timezone
from pathlib import Path

HOST = "127.0.0.1"
PORT = 2222
DATABASE = Path(__file__).resolve().parent / "attacks.db"
PROMPT = "root@server:~$"  # Display a believable prompt for the imaginary shell.

def initialize_database():
    with closing(sqlite3.connect(DATABASE)) as connection:
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
        connection.commit()

def log_event(source_ip, event_type, username=None, password=None, command=None):
    # Use a separate short-lived connection so threads do not share a connection.
    with closing(sqlite3.connect(DATABASE)) as connection:
        # Use placeholders so input values are not treated as SQL code.
        connection.execute(
            """
            INSERT INTO events
                (timestamp, source_ip, username, password, command, event_type)
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            (
                datetime.now(timezone.utc).isoformat(),
                source_ip,
                username,
                password,
                command,
                event_type,
            ),
        )
        connection.commit()

def fake_command_output(command):
    # A dictionary keeps fixed replies easy to read and extend.
    # These strings describe an imaginary Linux server, never this computer.
    replies = {
        "ls": "backups  notes.txt  scripts",
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

def handle_client(client_socket, client_address):
    print(f"Connected by {client_address}")
    source_ip = client_address[0]
    logged_in = False  # Each client starts with its own simulated login state.

    try:
        with client_socket:
            log_event(source_ip, "CONNECT")  # Capture the start of this session.
            with client_socket.makefile(
                "r", encoding="utf-8", errors="replace"
            ) as reader:

                for raw_line in reader:
                    line = raw_line.rstrip("\r\n")

                    print(f"Client request: {line}")
                    parts = line.split(" ", 2)  # Match exact protocol words.
                    request = parts[0].upper()  # Accept LOGIN or login.

                    # Close real SSH attempts: this exercise uses a text protocol.
                    if line.startswith("SSH-"):
                        client_socket.sendall(b"SSH protocol is not supported.\n")
                        break

                    if request == "LOGIN":
                        username = parts[1] if len(parts) > 1 else None
                        password = parts[2] if len(parts) > 2 else None
                        valid_login = bool(username and password)
                        logged_in = logged_in or valid_login
                        log_event(
                            source_ip,
                            "LOGIN_FAKE" if valid_login else "LOGIN_FAIL",
                            username=username,
                            password=password,
                        )

                    if request == "CMD":
                        command = line[4:] if len(line) >= 4 else ""
                        log_event(source_ip, "CMD", command=command)

                    response, should_close = response_for(line, logged_in)

                    # JSON escapes internal newlines so one line holds any reply.
                    # This also lets echo return a prompt without confusing framing.
                    client_socket.sendall((json.dumps(response) + "\n").encode("utf-8"))

                    if should_close:
                        break
    except (ConnectionError, OSError, UnicodeError) as error:
        # Treat an unexpected client exit or malformed data as one session ending.
        print(f"Client session ended: {error}")
    finally:
        log_event(source_ip, "DISCONNECT")

        print(f"Disconnected: {client_address}")

def main():
    initialize_database()

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server_socket:
        server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

        server_socket.bind((HOST, PORT))

        server_socket.listen(1)
        print(f"Server listening on {HOST}:{PORT}")

        while True:
            client_socket, client_address = server_socket.accept()

            client_thread = threading.Thread(
                target=handle_client,
                args=(client_socket, client_address),
                daemon=True,
            )

            client_thread.start()

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\nServer stopped.")  # Stop with Ctrl+C without a traceback.
