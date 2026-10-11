# SSH Honeypot

This project is an educational SSH honeypot demonstration written in Python.
It accepts connections through a small custom text protocol, returns safe fake
Linux shell responses, and records session activity in a local SQLite database.
The program never executes client commands on the host computer.

## Instructions for Build and Use

Steps to build or run the software:

1. Install Python 3.11 or newer.
2. Clone or download this project.
3. No external packages need to be installed because the project uses only the
   Python standard library.

Instructions for using the software:

1. Open a terminal in the `SSHoneypot` directory and start the server:
   `python3 server.py`
2. Open a second terminal in the same directory and run the client:
   `python3 client.py`
3. Review the terminal output and inspect the generated `attacks.db` file if
   you want to review the recorded events. The database is intentionally
   ignored by Git and is recreated locally by the server.

Run the automated safety and integration tests with:

```bash
python3 -m unittest -v test_server.py
```

The server listens on `127.0.0.1:2222`. The client demonstrates the custom
protocol messages `LOGIN`, `CMD`, and `LOGOUT`, followed by a second connection.

## Development Environment

To recreate the development environment, you need the following software and/or libraries with the specified versions:

* Python 3.11 or newer
* Python standard-library modules only, including `socket`, `threading`,
  `sqlite3`, `json`, `argparse`, `signal`, and `datetime`
* A terminal capable of running two local processes

## Useful Websites to Learn More

I found these websites useful in developing this software:

* [Python socket documentation](https://docs.python.org/3/library/socket.html)
* [Python Socket Programming HOWTO](https://docs.python.org/3/howto/sockets.html)
* [Python threading documentation](https://docs.python.org/3/library/threading.html)
* [Python sqlite3 documentation](https://docs.python.org/3/library/sqlite3.html)

## Future Work

The following items I plan to fix, improve, and/or add to this project in the future:

* [x] Add configurable command-line options for the host and port.
* [x] Add bounded request sizes, session timeouts, and connection limits.
* [x] Add safer redaction and retention controls for captured event data.
* [x] Harden the server for a short, supervised traffic-collection experiment.
* [x] Deploy it to an isolated AWS environment after approval and EC2 testing.

## Additional Project Information

This project imitates the behavior of an SSH server but does not implement the
real SSH protocol. Real SSH clients are recognized and disconnected. The
included `client.py` communicates with the server through the custom `LOGIN`,
`CMD`, and `LOGOUT` messages used for the project demonstration.

All simulated command output is stored as fixed text in `server.py`. Client
commands are never passed to the host operating system. The server also limits
request size, idle time, total session time, requests per session, simultaneous
clients, and database growth. Submitted passwords are redacted by default.

The automated tests cover normal sessions, reconnects, concurrent clients,
malformed and oversized requests, idle timeouts, password redaction, database
failure handling, and graceful shutdown.

The hardened server has been deployed to an isolated Amazon EC2 environment
for a supervised experiment. The live endpoint and collected database are not
published. Runtime databases, SQLite sidecar files, Python cache files, private
keys, AWS credentials, and captured traffic should never be committed to Git.

Run `python3 server.py --help` to view the configurable network, timeout,
connection, database, retention, and shutdown options.
