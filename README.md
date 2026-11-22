# sqllook

A read-only browser for large MySQL/MariaDB `.sql` dumps, for when the
dump is too big for your SQL client's GUI to open without running out of
memory.

Python standard library only. No dependencies to install beyond MariaDB
itself.

Every command prints a small ASCII banner (blue magnifying glass, white
"SQLLOOK" lettering) when run in a terminal; it's skipped automatically
when output isn't a tty (e.g. piped or redirected).

## Why

Opening a multi-gigabyte `.sql` dump directly in a GUI SQL client's text
editor (instead of actually importing it into a database) can exhaust
the client's memory, since it tries to load the whole file as text.
sqllook imports the dump into a real database engine instead, and lets
you browse it a page at a time.

## How it works

sqllook runs its own disposable MariaDB instance — a private data
directory, a unix socket, one `mariadbd` process — entirely under
`~/.local/share/sqllook/`. It does not touch any other database or
service on your machine:

- No sudo, no systemd, no system package configuration changes.
- No TCP port opened for the database (`--skip-networking`, unix socket
  only).
- The web UI binds to `127.0.0.1` only.
- A dedicated `viewer` account is granted `SELECT` only, one database at
  a time, exactly the ones you imported through sqllook — never a
  blanket grant on everything.

Delete `~/.local/share/sqllook` at any time to remove it completely.

## Requirements

- Python 3.8+
- `mariadb-server` and `mariadb-client` (or the equivalent `mysql-server`
  / `mysql-client` packages) installed and available in `PATH`.

## Usage

`sqllook.py` is already executable; optionally link it onto your `PATH`
(e.g. `ln -s "$PWD/sqllook.py" ~/.local/bin/sqllook`) to run it as `sqllook`
instead of `python3 sqllook.py` below.

```bash
# Import a dump (auto-detects the database name from the dump's own
# CREATE DATABASE statement when possible)
python3 sqllook.py import /path/to/dump.sql

# ...or force a name if the dump doesn't create its own database
python3 sqllook.py import /path/to/dump.sql --name mydb

# Re-import, replacing an existing database of the same name
python3 sqllook.py import /path/to/dump.sql --replace

# Start the web UI
python3 sqllook.py serve
# -> open http://127.0.0.1:8765

# Stop the private database instance
python3 sqllook.py stop

# Check whether it's running
python3 sqllook.py status
```

Import as many dumps as you like; `serve` lists every database you've
imported so far.

## What the web UI lets you do

- Browse every imported database and its tables, paginated.
- Run free-form `SELECT` / `SHOW` / `DESCRIBE` / `EXPLAIN` queries.

That's it — no editing, no admin features. Enforced both in the app
(query validation, single-statement only, forbidden-keyword list,
system-schema access blocked) and at the database level (the `viewer`
account genuinely only has `SELECT`, so even a bypass of the app-level
checks cannot write anything).

## A note on "full instance" dumps

Some `.sql` dumps (typically produced with `--all-databases`) bundle the
source server's own `mysql` system schema — including its user accounts
and grants — alongside the application data. Importing that verbatim
would silently overwrite accounts inside sqllook's private instance.

sqllook detects the standard mysqldump `-- Current Database: `name``
markers and imports only the section for the database you asked for,
specifically to avoid this. If a dump doesn't use that marker format (a
plain single-database dump), it's imported as-is — which is safe in that
case, since such dumps don't touch the `mysql` schema.

## Limitations

- MySQL/MariaDB dump syntax only (not PostgreSQL, SQLite, etc.).
- Query results are capped (500 rows, 15 second statement timeout) —
  this is a browser, not a full SQL client.
- The web UI binds to `127.0.0.1` (hardcoded) and, on top of that,
  requires the access token `serve` prints at startup on every single
  request — opening `http://127.0.0.1:8765` without `?t=<token>` gets a
  403. This also stops another local account on a shared machine, or
  another browser tab/site, from reading your data.
- Importing a `.sql` dump runs its content through a dedicated,
  minimally-privileged account scoped to just that one database for the
  duration of the import (never as the private instance's admin), and
  the private MariaDB's file I/O (`INTO OUTFILE`/`LOAD_FILE`) is confined
  to one empty, disposable directory while `LOAD DATA LOCAL INFILE` is
  disabled outright — so even a malicious dump can't write, read, or
  pull in files from anywhere else on your system.
- `--replace` requires passing `--name` explicitly; it refuses to
  replace a database whose name was only auto-detected from the dump
  itself, since that name isn't something you chose.

## Tests

```bash
python3 -m unittest test_sqllook -v
```

Pure logic tests (query/identifier validation, dump parsing) on
synthetic fixtures — no database connection required.

## License

All rights reserved. No license is granted to use, copy, modify, or
distribute this software.
