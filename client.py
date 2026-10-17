"""Legacy JSON-line demo client for `server.py --protocol legacy`."""

import argparse
import json
import socket

def send_request(client_socket, reader, request):
    print(f">>> {request}")

    client_socket.sendall((request + "\n").encode("utf-8"))

    # The server wraps each response in one JSON line, even for multiline output.
    line = reader.readline()  # Wait for one complete response.
    if not line:
        raise ConnectionError("Server disconnected before completing its response.")
    print(json.loads(line), end="")  # Restore the original text and its newlines.

def run_session(host, port, session_name, requests):
    print(f"\n--- {session_name} ---")

    with socket.create_connection((host, port)) as client_socket:
        with client_socket.makefile("r", encoding="utf-8") as reader:

            for request in requests:
                send_request(client_socket, reader, request)

def main():
    parser = argparse.ArgumentParser(description="Test the SSH honeypot server")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=2222)
    args = parser.parse_args()

    run_session(
        args.host,
        args.port,
        "First connection",
        [
            "LOGIN root password",
            "CMD whoami",
            "CMD ls",
            "CMD ls -la",
            "CMD hostname",
            "CMD id",
            "CMD uname -a",
            "CMD cat /etc/passwd",
            "CMD cat /etc/os-release",
            "CMD echo hello from the fake shell",
            "LOGOUT",
        ],
    )

    run_session(
        args.host,
        args.port,
        "Second connection",
        [
            "LOGIN admin admin",
            "CMD pwd",
            "LOGOUT",
        ],
    )

    print("\nClient test complete.")


if __name__ == "__main__":
    main()
