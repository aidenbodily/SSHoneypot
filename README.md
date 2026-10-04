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

The server listens on `127.0.0.1:2222`. The client demonstrates the custom
protocol messages `LOGIN`, `CMD`, and `LOGOUT`, followed by a second connection.

## Development Environment

To recreate the development environment, you need the following software and/or libraries with the specified versions:

* Python 3.11 or newer
* Python standard-library modules: `socket`, `threading`, `sqlite3`, `json`, and `datetime`
* A terminal capable of running two local processes

## Useful Websites to Learn More

I found these websites useful in developing this software:

* [Python socket documentation](https://docs.python.org/3/library/socket.html)
* [Python Socket Programming HOWTO](https://docs.python.org/3/howto/sockets.html)
* [Python threading documentation](https://docs.python.org/3/library/threading.html)
* [Python sqlite3 documentation](https://docs.python.org/3/library/sqlite3.html)

## Future Work

The following items I plan to fix, improve, and/or add to this project in the future:

* [ ] Add configurable command-line options for the host and port.
* [ ] Add bounded request sizes, session timeouts, and connection limits.
* [ ] Add safer redaction and retention controls for captured event data.
* [ ] Harden the server and deploy it to an isolated AWS environment for a
  short, supervised traffic-collection experiment.
