#!/usr/bin/env python3
"""sqllook - read-only browser for large MySQL/MariaDB .sql dumps.

Python standard library only. Does not touch any existing database or
service: it runs its own disposable MariaDB instance (data directory,
unix socket, process) entirely under ~/.local/share/sqllook/, started as
the current user (no sudo, no systemd, no TCP port - unix socket only).

Usage:
  sqllook.py import <dump.sql> [--name NAME] [--replace]
  sqllook.py serve [--port 8765]
  sqllook.py stop
  sqllook.py status

Full removal: rm -rf ~/.local/share/sqllook
"""
import argparse
import functools
import html
import json
import os
import re
import secrets
import shutil
import subprocess
import sys
import tempfile
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlparse

HOME = Path.home() / ".local" / "share" / "sqllook"
DATA_DIR = HOME / "data"
FILE_PRIV_JAIL = HOME / "file-priv-jail"
SOCKET = HOME / "mysqld.sock"
PID_FILE = HOME / "mysqld.pid"
LOG_FILE = HOME / "mysqld.log"
CRED_FILE = HOME / "viewer.cred"
IMPORTER_CRED_FILE = HOME / "importer.cred"
MANIFEST_FILE = HOME / "imported.json"

MARIADBD = None
INSTALL_DB = None
MYSQL_CLIENT = None
MYSQLADMIN = None

PAGE_SIZE = 50
MAX_ROWS = 500
MAX_STATEMENT_TIME_MS = 15000

_RESET = "\033[0m"
_BOLD = "\033[1m"
_WHITE = "\033[97m"
_BLUE = "\033[94m"

_GLASS = [
    "     .----.",
    "    /      \\",
    "   |   ..   |",
    "    \\      /",
    "     '.__.'",
    "         \\  \\",
    "          \\  \\",
]

_FONT = {
    "S": [" ### ", "#    ", " ### ", "    #", " ### "],
    "Q": [" ### ", "#   #", "#  ##", "#   #", " ####"],
    "L": ["#    ", "#    ", "#    ", "#    ", "#####"],
    "O": [" ### ", "#   #", "#   #", "#   #", " ### "],
    "K": ["#   #", "#  # ", "###  ", "#  # ", "#   #"],
}


def print_banner():
    if not sys.stdout.isatty():
        return
    print(_BLUE + _BOLD + "\n".join(_GLASS) + _RESET)
    word = "SQLLOOK"
    for row in range(5):
        print(_WHITE + _BOLD + " ".join(_FONT[letter][row] for letter in word) + _RESET)
    print()


STYLE = """
<style>
  :root { color-scheme: dark; }
  body { background:#0b0f0c; color:#c9f7d6; font-family: ui-monospace, "JetBrains Mono", Consolas, monospace;
         margin: 0; padding: 24px; }
  a { color:#5eead4; text-decoration:none; }
  a:hover { text-decoration:underline; }
  h1,h2 { color:#7CFC9A; font-weight:600; }
  .wrap { max-width: 1100px; margin: 0 auto; }
  nav { margin-bottom: 20px; opacity:.85; }
  table { border-collapse: collapse; width:100%; font-size: 13px; margin-top: 12px; }
  th, td { border:1px solid #1e3324; padding:4px 8px; text-align:left; white-space:pre-wrap; word-break:break-word; }
  th { background:#102418; color:#7CFC9A; position:sticky; top:0; }
  tr:nth-child(even) td { background:#0e1511; }
  textarea { width:100%; height:120px; background:#0e1511; color:#c9f7d6; border:1px solid #1e3324;
             font-family: inherit; font-size: 13px; padding:8px; box-sizing:border-box; }
  button { background:#123820; color:#7CFC9A; border:1px solid #2a5a38; padding:8px 16px;
           cursor:pointer; font-family: inherit; margin-top:8px; }
  button:hover { background:#1a4a2a; }
  .err { color:#ff8080; white-space:pre-wrap; }
  .muted { opacity:.6; font-size: 12px; }
  .pager { margin-top: 14px; }
  .pager a { margin-right: 14px; }
</style>
"""


_CONTROL_CHARS_RE = re.compile(r"[\x00-\x08\x0b-\x1f\x7f-\x9f]")


def sanitize_for_terminal(text):
    """Strips control/escape bytes (keeps tab and newline) before printing
    text that may come from an untrusted .sql dump or echo it back (table
    names, error messages quoting the offending SQL...) - otherwise a
    malicious dump could inject terminal escape sequences into what looks
    like a plain status message."""
    return _CONTROL_CHARS_RE.sub("", text)


def die(msg):
    print(f"Error: {sanitize_for_terminal(msg)}", file=sys.stderr)
    sys.exit(1)


def find_bin(candidates, what):
    for c in candidates:
        p = shutil.which(c)
        if p:
            return p
    die(f"{what} not found in PATH (candidates: {', '.join(candidates)}). Install mariadb-server and mariadb-client.")


def resolve_binaries():
    global MARIADBD, INSTALL_DB, MYSQL_CLIENT, MYSQLADMIN
    MARIADBD = find_bin(("mariadbd", "mysqld"), "mariadbd/mysqld")
    INSTALL_DB = find_bin(("mariadb-install-db", "mysql_install_db"), "mariadb-install-db")
    MYSQL_CLIENT = find_bin(("mysql", "mariadb"), "mysql client")
    MYSQLADMIN = find_bin(("mysqladmin", "mariadb-admin"), "mysqladmin")


def is_running():
    if not SOCKET.exists():
        return False
    proc = subprocess.run(
        [MYSQLADMIN, f"--socket={SOCKET}", "-u", "root", "ping"],
        capture_output=True,
    )
    return proc.returncode == 0


def ensure_initialized():
    if (DATA_DIR / "mysql").exists():
        return
    HOME.mkdir(parents=True, exist_ok=True)
    HOME.chmod(0o700)
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    print("First-time setup of the private sqllook instance...")
    proc = subprocess.run(
        [
            INSTALL_DB,
            "--no-defaults",
            f"--datadir={DATA_DIR}",
            "--auth-root-authentication-method=normal",
            "--skip-test-db",
        ],
        capture_output=True,
    )
    if proc.returncode != 0:
        die(proc.stderr.decode(errors="replace"))


def start():
    resolve_binaries()
    ensure_initialized()
    if is_running():
        return
    # A .sql dump is untrusted SQL: a malicious one can run INTO OUTFILE /
    # LOAD_FILE() as the private instance's root. Confine that to one
    # disposable, empty directory instead of leaving file I/O unrestricted
    # (the default), so the worst case is a stray file in there, never an
    # arbitrary write anywhere this OS account can reach (~/.bashrc, SSH
    # keys...). local-infile=0 closes the matching client-side read path.
    FILE_PRIV_JAIL.mkdir(parents=True, exist_ok=True)
    FILE_PRIV_JAIL.chmod(0o700)
    log = open(LOG_FILE, "a")
    subprocess.Popen(
        [
            MARIADBD,
            "--no-defaults",
            f"--datadir={DATA_DIR}",
            f"--socket={SOCKET}",
            f"--pid-file={PID_FILE}",
            "--skip-networking",
            f"--secure-file-priv={FILE_PRIV_JAIL}",
            "--local-infile=0",
            # A SUPER account (import runs as one no longer, but this is
            # belt-and-suspenders) could otherwise redirect the general/slow
            # query log to an arbitrary path via SET GLOBAL and write
            # attacker-chosen content there - fix these at startup so no SQL
            # statement can move them.
            "--general-log=0",
            f"--general-log-file={LOG_FILE}",
            "--slow-query-log=0",
            f"--slow-query-log-file={LOG_FILE}",
        ],
        stdout=log,
        stderr=log,
        start_new_session=True,
    )
    for _ in range(60):
        if is_running():
            break
        time.sleep(0.5)
    else:
        die(f"private instance failed to start, see {LOG_FILE}")
    ensure_viewer_user()
    ensure_importer_user()


def ensure_viewer_user():
    """Create the read-only 'viewer' account with NO privileges yet.
    Privileges are granted per database at import time (least privilege),
    never a blanket GRANT ... ON *.* - this keeps the viewer from ever
    reading the instance's own mysql.* system tables.
    """
    if CRED_FILE.exists():
        return
    reset_viewer_user()


def _reset_user(username, cred_file):
    """(Re)create a no-privilege account unconditionally, with a fresh
    password. Shared by 'viewer' and 'importer'.

    Some .sql dumps are full-instance dumps that include the mysql system
    schema itself (CREATE USER/GRANT statements, a rewritten mysql.user
    table...). Importing such a dump silently wipes out any account we
    created earlier. Calling this again right after every import keeps
    both accounts valid regardless of what the dump did.
    """
    pwd = secrets.token_urlsafe(24)
    sql = (
        f"DROP USER IF EXISTS '{username}'@'localhost';"
        f"CREATE USER '{username}'@'localhost' IDENTIFIED BY '{pwd}';"
        "FLUSH PRIVILEGES;"
    )
    proc = subprocess.run(
        [MYSQL_CLIENT, f"--socket={SOCKET}", "-u", "root"],
        input=sql.encode(),
        capture_output=True,
    )
    if proc.returncode != 0:
        die(proc.stderr.decode(errors="replace"))
    cred_file.write_text(pwd)
    cred_file.chmod(0o600)


def reset_viewer_user():
    _reset_user("viewer", CRED_FILE)


def ensure_importer_user():
    """Create the 'importer' account with NO privileges yet. Like 'viewer',
    it only ever gets scoped per-database grants, and only for the
    duration of one import - see cmd_import. It never has SUPER, FILE, or
    any global privilege, so untrusted dump SQL executed through it (the
    whole point of importing a dump is running SQL we don't fully trust)
    cannot do anything beyond create/alter/read/write objects in the one
    database it was granted for that import.
    """
    if IMPORTER_CRED_FILE.exists():
        return
    reset_importer_user()


def reset_importer_user():
    _reset_user("importer", IMPORTER_CRED_FILE)


def importer_password():
    return IMPORTER_CRED_FILE.read_text().strip()


def stop():
    resolve_binaries()
    if not is_running():
        print("Already stopped.")
        return
    proc = subprocess.run([MYSQLADMIN, f"--socket={SOCKET}", "-u", "root", "shutdown"], capture_output=True)
    if proc.returncode != 0 or is_running():
        die("failed to stop the private instance (root access inside it may have been changed by an imported dump)")
    print("Stopped.")


def status():
    resolve_binaries()
    print("Running." if is_running() else "Stopped.")


def read_manifest():
    if not MANIFEST_FILE.exists():
        return []
    try:
        return json.loads(MANIFEST_FILE.read_text())
    except (json.JSONDecodeError, OSError):
        return []


def add_to_manifest(name):
    names = read_manifest()
    if name not in names:
        names.append(name)
    MANIFEST_FILE.write_text(json.dumps(names))
    MANIFEST_FILE.chmod(0o600)


def regrant_manifest_databases():
    """Re-apply SELECT grants for every database sqllook has ever imported.

    Needed after reset_viewer_user(): a dump that resets the mysql schema
    wipes the viewer account's grants too, not just the account itself.
    Only grants on databases this tool itself tracked (the manifest), never
    on every schema that happens to exist - a full-instance dump can leave
    behind other schemas we never asked to expose.
    """
    for name in read_manifest():
        if _IDENT_RE.match(name) and name.lower() not in RESERVED_SCHEMAS:
            run_as_root(f"GRANT SELECT ON `{escape_sql_pattern(name)}`.* TO 'viewer'@'localhost';")
    run_as_root("FLUSH PRIVILEGES;")


def run_as_root(sql_text, db=None):
    args = [
        MYSQL_CLIENT, f"--socket={SOCKET}", "-u", "root", "--batch", "--silent",
        "--sandbox", "--local-infile=0",
    ]
    if db:
        args.append(db)
    proc = subprocess.run(args, input=sql_text.encode(), capture_output=True)
    if proc.returncode != 0:
        die(proc.stderr.decode(errors="replace").strip())
    return proc.stdout.decode(errors="replace")


_IDENT_RE = re.compile(r"^[A-Za-z0-9_]+$")
RESERVED_SCHEMAS = {"mysql", "information_schema", "performance_schema", "sys"}


def escape_sql_pattern(name):
    """Escapes '_'/'%' before a name goes into a GRANT ... ON `name`.* or a
    SHOW DATABASES LIKE check. Both match the name as a LIKE pattern even
    though it's backtick/quote-delimited - an unescaped '_' (allowed by
    _IDENT_RE, and present in real names like 'agarthi_prod') is a
    wildcard for "any one character", so without this, importing a
    database whose name contains '_' would also grant/match every other
    database differing only in that one character."""
    return name.replace("\\", "\\\\").replace("_", "\\_").replace("%", "\\%")


def detect_db_name(dump_path: Path):
    pattern = re.compile(r"CREATE DATABASE[^;]*`([^`]+)`", re.IGNORECASE)
    with open(dump_path, "r", errors="replace") as f:
        for _ in range(2000):  # the CREATE DATABASE line is always near the top of a dump
            line = f.readline()
            if not line:
                break
            m = pattern.search(line)
            if m:
                return m.group(1)
    return None


def extract_database_section(dump_path: Path, name: str):
    """Pull out only the slice of a mysqldump --all-databases file that
    belongs to one database (between its '-- Current Database: `name`'
    marker and the next one), streamed line by line - never the whole
    dump held in memory at once.

    Some dumps bundle the mysql system schema itself (CREATE USER/GRANT
    statements, a rewritten mysql.user table) alongside the application
    data. Importing that verbatim overwrites the private instance's own
    accounts, including the one sqllook relies on. Restricting the import
    to just the target database's section avoids that entirely.

    Returns a temp file path on success, or None if the dump does not use
    this per-database marker format (plain single-database dumps don't -
    they are imported as-is).
    """
    start_marker = f"-- Current Database: `{name}`"
    tmp = HOME / "import.sql.tmp"
    found_start = False
    with open(dump_path, "r", errors="replace") as src, open(tmp, "w") as dst:
        # mysqldump disables these ahead of the per-database sections so
        # tables can be created out of foreign-key order; our slice starts
        # after that preamble, so restate them explicitly.
        dst.write("SET FOREIGN_KEY_CHECKS=0;\nSET UNIQUE_CHECKS=0;\nSET NAMES utf8mb4;\n")
        for line in src:
            if not found_start:
                if line.rstrip("\n") == start_marker:
                    found_start = True
                    dst.write(line)
                continue
            if line.startswith("-- Current Database:"):
                break
            dst.write(line)
        dst.write("SET FOREIGN_KEY_CHECKS=1;\nSET UNIQUE_CHECKS=1;\n")
    if not found_start:
        tmp.unlink(missing_ok=True)
        return None
    return tmp


_DEFINER_RE = re.compile(
    rb"\s*DEFINER\s*=\s*(?:`[^`]*`|'[^']*'|[^\s@`']+)@(?:`[^`]*`|'[^']*'|[^\s*`']+)",
    re.IGNORECASE,
)


def strip_definers(line: bytes) -> bytes:
    """Drop DEFINER=`user`@`host` from DDL lines (triggers, views, routines).

    The unprivileged 'importer' account has no SET USER/SUPER, so MySQL
    refuses any object created on behalf of another account (typically
    root@localhost) with ERROR 1227. For a read-only browser the definer
    is irrelevant. Only DDL-looking lines are touched, so a data row that
    happens to contain the text is never altered.
    """
    head = line[:12].lstrip().upper()
    if not (head.startswith(b"/*!") or head.startswith(b"CREATE")):
        return line
    return _DEFINER_RE.sub(b"", line)


def run_import_stream(source, import_args, env):
    """Feed `source` (binary file) to the mysql client line by line through
    strip_definers, without writing a second copy of a possibly huge dump."""
    with tempfile.TemporaryFile() as err:
        proc = subprocess.Popen(
            import_args, stdin=subprocess.PIPE, stdout=subprocess.DEVNULL,
            stderr=err, env=env,
        )
        try:
            for line in source:
                proc.stdin.write(strip_definers(line))
            proc.stdin.close()
        except BrokenPipeError:
            pass  # client stopped at the first error; its stderr says why
        returncode = proc.wait()
        err.seek(0)
        return returncode, err.read()


def cmd_import(args):
    dump_path = Path(args.dump).expanduser()
    if not dump_path.is_file():
        die(f"file not found: {dump_path}")
    start()
    name = args.name or detect_db_name(dump_path)
    if not name:
        die("could not detect a database name in the dump, pass --name NAME")
    if not _IDENT_RE.match(name):
        die("invalid database name (letters/digits/underscore only)")
    if name.lower() in RESERVED_SCHEMAS:
        die(f"'{name}' is a reserved system schema name, refusing to touch it")
    if args.replace and not args.name:
        # --replace drops an existing database first: that decision must
        # come from the name the user actually typed, never from a name
        # the dump's own (untrusted) content chose - otherwise a dump
        # could get itself auto-detected as, say, an existing database
        # you care about and have it silently dropped and replaced.
        die("--replace requires --name NAME: pass the name explicitly "
            "rather than relying on the one detected from the dump")

    existing = run_as_root(f"SHOW DATABASES LIKE '{escape_sql_pattern(name)}';").strip()
    if existing:
        if not args.replace:
            die(f"database '{name}' already exists in the private instance (use --replace to overwrite)")
        run_as_root(f"DROP DATABASE `{name}`;")

    # The dump's own SQL is untrusted, so it never runs as root: the shell
    # database is created here (root, trusted), and the dump's content is
    # imported as 'importer', scoped to only this one database for the
    # duration of this import (see ensure_importer_user()). A dump's own
    # `CREATE DATABASE IF NOT EXISTS`/`USE` statements for this same name,
    # if present, are then no-ops the scoped account is already allowed to
    # run - this is what lets both markerless and full-instance dumps work
    # unchanged.
    run_as_root(f"CREATE DATABASE `{name}` DEFAULT CHARACTER SET utf8mb4;")
    run_as_root(f"GRANT ALL PRIVILEGES ON `{escape_sql_pattern(name)}`.* TO 'importer'@'localhost';")
    run_as_root("FLUSH PRIVILEGES;")

    section = extract_database_section(dump_path, name)
    try:
        if section is not None:
            print(f"Importing {dump_path} (isolated to database '{name}', this can take several minutes)...")
            source = open(section, "rb")
        else:
            print(f"Importing {dump_path} into '{name}' (this can take several minutes)...")
            source = open(dump_path, "rb")

        import_args = [
            MYSQL_CLIENT, f"--socket={SOCKET}", "-u", "importer", "--sandbox",
            "--local-infile=0", name,
        ]
        returncode, stderr_bytes = run_import_stream(
            source, import_args, {"MYSQL_PWD": importer_password()},
        )
        source.close()
    finally:
        if section is not None:
            section.unlink(missing_ok=True)
        # Back to zero privileges the moment this import ends, success or
        # not - and fully reset in case the dump's own SQL tampered with
        # the account (same reasoning as reset_viewer_user()).
        reset_importer_user()

    if returncode != 0:
        die(stderr_bytes.decode(errors="replace"))

    add_to_manifest(name)
    # A dump can be a full-instance dump that rewrites the mysql schema
    # itself, wiping out the viewer account and all its grants. Always
    # recreate it and reapply every known grant, never assume it survived.
    reset_viewer_user()
    regrant_manifest_databases()

    known = set(read_manifest()) | {
        "information_schema", "performance_schema", "mysql", "sys",
    }
    extra = [d for d in run_as_root("SHOW DATABASES;").split() if d not in known]
    if extra:
        print(
            "Note: this dump also created other databases on the private "
            "instance that sqllook did not ask for (full-instance dump?): "
            + sanitize_for_terminal(", ".join(extra))
        )

    print(f"OK: '{name}' imported. Run 'sqllook.py serve' then open http://127.0.0.1:8765")


# ---------------------------------------------------------------------------
# Web UI (read-only)
# ---------------------------------------------------------------------------

class SqlError(Exception):
    pass


def viewer_password():
    return CRED_FILE.read_text().strip()


_FORBIDDEN_RE = re.compile(
    r"\b(insert|update|delete|drop|alter|create|replace|truncate|grant|revoke|set\s+global|load_file|into\s+outfile)\b",
    re.IGNORECASE,
)
_SYSTEM_SCHEMA_RE = re.compile(
    r"\b(mysql|information_schema|performance_schema|sys)`?\s*\.", re.IGNORECASE
)


def run_sql(query: str, db: str = None):
    args = [
        MYSQL_CLIENT, f"--socket={SOCKET}", "-u", "viewer", "--batch",
        "--sandbox", "--local-infile=0",
    ]
    if db:
        args.append(db)
    session_prefix = f"SET SESSION max_statement_time={MAX_STATEMENT_TIME_MS};\n"
    proc = subprocess.run(
        args,
        input=(session_prefix + query).encode(),
        capture_output=True,
        timeout=20,
        env={"MYSQL_PWD": viewer_password()},  # never on argv: avoids leaking the password via `ps`
    )
    if proc.returncode != 0:
        raise SqlError(proc.stderr.decode(errors="replace").strip())
    out = proc.stdout.decode(errors="replace")
    lines = out.splitlines()
    if not lines:
        return [], []
    header = lines[0].split("\t")
    rows = [line.split("\t") for line in lines[1:]]
    return header, rows


def list_databases():
    _, rows = run_sql("SHOW DATABASES;")
    skip = {"information_schema", "performance_schema", "mysql", "sys"}
    return [r[0] for r in rows if r[0] not in skip]


def list_tables(db):
    _, rows = run_sql("SHOW TABLES;", db=db)
    return [r[0] for r in rows]


def validate_ident(name, known, label):
    if name not in known or not _IDENT_RE.match(name):
        raise SqlError(f"Unknown {label}.")
    return name


def validate_select_query(q: str):
    q = q.strip()
    if not q:
        raise SqlError("Empty query.")
    body = q[:-1] if q.endswith(";") else q
    if ";" in body:
        raise SqlError("Only one statement at a time.")
    if not re.match(r"^(select|show|describe|desc|explain)\b", body, re.IGNORECASE):
        raise SqlError("Only SELECT/SHOW/DESCRIBE/EXPLAIN queries are allowed.")
    if _FORBIDDEN_RE.search(body):
        raise SqlError("Forbidden keyword in query.")
    if _SYSTEM_SCHEMA_RE.search(body):
        raise SqlError("Access to system schemas is not allowed.")
    return body


def render_table(header, rows, max_rows):
    if not header:
        return "<p class='muted'>No columns.</p>"
    truncated = len(rows) > max_rows
    rows = rows[:max_rows]
    out = ["<table><tr>"]
    for h in header:
        out.append(f"<th>{html.escape(h)}</th>")
    out.append("</tr>")
    for row in rows:
        out.append("<tr>")
        for cell in row:
            val = "<i>NULL</i>" if cell == "NULL" else html.escape(cell)
            out.append(f"<td>{val}</td>")
        out.append("</tr>")
    out.append("</table>")
    if truncated:
        out.append(f"<p class='muted'>Showing only the first {max_rows} rows.</p>")
    return "".join(out)


def _bare_shell(title, body):
    return f"""<!doctype html>
<html><head><meta charset="utf-8"><title>{html.escape(title)}</title>{STYLE}</head>
<body><div class="wrap">
{body}
</div></body></html>"""


def page_shell(title, body):
    # Only ever used for a response to a request that has already proven
    # it holds the access token (see do_GET) - otherwise the token in this
    # very page's own nav link would leak to whoever doesn't have it yet.
    return f"""<!doctype html>
<html><head><meta charset="utf-8"><title>{html.escape(title)}</title>{STYLE}</head>
<body><div class="wrap">
<nav><a href="/?t={_ACCESS_TOKEN}">&larr; Databases</a></nav>
{body}
</div></body></html>"""


# Required as the `t` query parameter on every single request - never a
# cookie. A cookie set for the bare host "127.0.0.1" is NOT scoped by port,
# so any other local service bound to a different 127.0.0.1 port (another
# of your own tools, or someone else's on a shared machine) would also see
# it. Checking the token itself on every request has no such leak and
# needs no session state at all.
_ACCESS_TOKEN = secrets.token_urlsafe(24)


class Handler(BaseHTTPRequestHandler):
    server_version = "sqllook/1.0"

    def log_message(self, fmt, *args):
        pass

    def _send_html(self, body, status=200):
        encoded = body.encode()
        self.send_response(status)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(encoded)))
        self.end_headers()
        self.wfile.write(encoded)

    def _valid_host(self):
        host = (self.headers.get("Host") or "").lower()
        port = self.server.server_port
        return host in (f"127.0.0.1:{port}", f"localhost:{port}")

    def _presents_access_token(self, qs):
        values = qs.get("t") or []
        return bool(values) and secrets.compare_digest(values[0], _ACCESS_TOKEN)

    def _reject_unauthorized(self):
        self._send_html(
            _bare_shell(
                "Unauthorized",
                "<p class='err'>Open the full URL (with its ?t= token) printed in the "
                "terminal where 'sqllook.py serve' is running.</p>",
            ),
            403,
        )

    def do_GET(self):
        if not self._valid_host():
            self._send_html(_bare_shell("Error", "<p class='err'>Invalid Host header.</p>"), 400)
            return
        parsed = urlparse(self.path)
        qs = parse_qs(parsed.query)
        if not self._presents_access_token(qs):
            self._reject_unauthorized()
            return
        try:
            if parsed.path == "/":
                self._index()
            elif parsed.path == "/db":
                self._db(qs)
            elif parsed.path == "/table":
                self._table(qs)
            elif parsed.path == "/query":
                self._query(qs)
            else:
                self._send_html(page_shell("404", "<p>Not found.</p>"), 404)
        except SqlError as e:
            self._send_html(page_shell("Error", f"<p class='err'>{html.escape(str(e))}</p>"), 400)
        except Exception:
            self._send_html(page_shell("Error", "<p class='err'>Internal error.</p>"), 500)

    def _index(self):
        dbs = list_databases()
        if not dbs:
            body = "<h1>sqllook</h1><p class='muted'>No database imported yet. From a terminal: sqllook.py import &lt;file.sql&gt;</p>"
            self._send_html(page_shell("sqllook", body))
            return
        items = "".join(
            f"<li><a href='/db?name={html.escape(d)}&t={_ACCESS_TOKEN}'>{html.escape(d)}</a></li>" for d in dbs
        )
        body = f"<h1>sqllook</h1><p class='muted'>Read-only. {len(dbs)} database(s).</p><ul>{items}</ul>"
        self._send_html(page_shell("sqllook", body))

    def _db(self, qs):
        dbs = list_databases()
        db = validate_ident((qs.get("name") or [""])[0], dbs, "database")
        tables = list_tables(db)
        items = "".join(
            f"<li><a href='/table?db={html.escape(db)}&name={html.escape(t)}&t={_ACCESS_TOKEN}'>"
            f"{html.escape(t)}</a></li>" for t in tables
        )
        body = f"""
<h1>{html.escape(db)}</h1>
<p class="muted">{len(tables)} tables.</p>
<ul>{items}</ul>
<h2>Free query (SELECT)</h2>
<form action="/query" method="get">
  <input type="hidden" name="db" value="{html.escape(db)}">
  <input type="hidden" name="t" value="{_ACCESS_TOKEN}">
  <textarea name="q" placeholder="SELECT * FROM ... LIMIT 20"></textarea>
  <br><button type="submit">Run on {html.escape(db)}</button>
</form>
"""
        self._send_html(page_shell(db, body))

    def _table(self, qs):
        dbs = list_databases()
        db = validate_ident((qs.get("db") or [""])[0], dbs, "database")
        tables = list_tables(db)
        name = validate_ident((qs.get("name") or [""])[0], tables, "table")
        try:
            page = max(0, int((qs.get("page") or ["0"])[0]))
        except ValueError:
            page = 0
        offset = page * PAGE_SIZE
        header, rows = run_sql(f"SELECT * FROM `{name}` LIMIT {PAGE_SIZE} OFFSET {offset};", db=db)
        nav = "<div class='pager'>"
        if page > 0:
            nav += (
                f"<a href='/table?db={html.escape(db)}&name={html.escape(name)}"
                f"&page={page-1}&t={_ACCESS_TOKEN}'>&larr; previous</a>"
            )
        if len(rows) == PAGE_SIZE:
            nav += (
                f"<a href='/table?db={html.escape(db)}&name={html.escape(name)}"
                f"&page={page+1}&t={_ACCESS_TOKEN}'>next &rarr;</a>"
            )
        nav += "</div>"
        body = (
            f"<nav><a href='/db?name={html.escape(db)}&t={_ACCESS_TOKEN}'>&larr; {html.escape(db)}</a></nav>"
            f"<h1>{html.escape(db)}.{html.escape(name)}</h1><p class='muted'>Page {page+1}</p>"
            f"{render_table(header, rows, MAX_ROWS)}{nav}"
        )
        self._send_html(page_shell(f"{db}.{name}", body))

    def _query(self, qs):
        dbs = list_databases()
        db = validate_ident((qs.get("db") or [""])[0], dbs, "database")
        raw = (qs.get("q") or [""])[0]
        if not raw.strip():
            self._send_html(page_shell("Query", "<p class='muted'>Enter a query from the database page.</p>"))
            return
        safe_q = validate_select_query(raw)
        header, rows = run_sql(safe_q + ";", db=db)
        body = f"""
<nav><a href="/db?name={html.escape(db)}&t={_ACCESS_TOKEN}">&larr; {html.escape(db)}</a></nav>
<h1>Result ({html.escape(db)})</h1>
<pre class="muted">{html.escape(raw)}</pre>
{render_table(header, rows, MAX_ROWS)}
"""
        self._send_html(page_shell("Result", body))


def cmd_serve(args):
    start()
    if not CRED_FILE.exists():
        die("viewer account missing, run 'sqllook.py import' once first")
    server = ThreadingHTTPServer(("127.0.0.1", args.port), Handler)
    print(f"Open this URL (anyone else, on this machine or elsewhere, is refused "
          f"without it): http://127.0.0.1:{args.port}/?t={_ACCESS_TOKEN}")
    print("(Ctrl+C stops the web UI only; the private instance keeps running, "
          "use 'sqllook.py stop' to shut it down)")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass


def main():
    if hasattr(os, "geteuid") and os.geteuid() == 0:
        die("don't run sqllook as root / with sudo - it stores its private instance "
            "under the home directory of whoever runs it, so sudo puts it under "
            "/root instead of your own account, and MariaDB then refuses to start "
            "as root. Run it as your normal user.")
    print_banner()
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = parser.add_subparsers(dest="cmd", required=True)

    p_import = sub.add_parser("import", help="import a .sql dump")
    p_import.add_argument("dump")
    p_import.add_argument("--name", default=None)
    p_import.add_argument("--replace", action="store_true")
    p_import.set_defaults(func=cmd_import)

    p_serve = sub.add_parser("serve", help="start the local web UI")
    p_serve.add_argument("--port", type=int, default=8765)
    p_serve.set_defaults(func=cmd_serve)

    p_stop = sub.add_parser("stop", help="stop the private instance")
    p_stop.set_defaults(func=lambda a: stop())

    p_status = sub.add_parser("status", help="private instance status")
    p_status.set_defaults(func=lambda a: status())

    args = parser.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
