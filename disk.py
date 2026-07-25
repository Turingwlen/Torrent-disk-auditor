#!/usr/bin/env python3
"""
disk.py — Disk audit with hardlink + qBittorrent analysis
==========================================================
Scans a directory tree on a single drive and produces an inode-centric report.

For every unique file (inode) on disk it shows:
  - The real size on disk (counted once regardless of hardlinks)
  - Every path (hardlink) that points to it
  - For each path, whether it is part of an active qBittorrent torrent

This lets you answer: "Is every hardlink serving a purpose, or are some
orphaned and wasting directory clutter?"

It also detects true duplicates — files with identical content but *different*
inodes, which genuinely waste disk space.

Usage:
    python3 disk.py /mount/point [OPTIONS]

Defaults (designed for minimal-arg usage):
    - Shows ALL files (use --top N to limit)
    - Interactive dedup is ON (use --no-fix to skip)
    - Orphan path cleanup is ON (use --no-cleanup-orphans to skip)
    - Empty folder cleanup is ON (use --no-cleanup-empty to skip)
    - Hash cache is ON at .disk_cache.db next to disk.py (use --no-cache to disable)
    - Configuration (qBittorrent URL/credentials, media dirs, path maps, ignored
      extensions, …) lives in an adjacent `.env` file — copy `.env.example` to
      `.env` and edit it. Nothing site-specific is hardcoded in this script.
    - Only ACTIVE torrents count (paused/errored ignored; use --all-torrents to include)

Output files (written next to disk.py — the script's own directory — after all
cleanup phases, NOT under the scanned path):
    diskreport.log       Full terminal output log
    diskreport.html      Interactive HTML report with sortable tables
    used_inodes.json     Inodes where ALL paths serve an active torrent
    unused_inodes.json   Inodes where NO paths serve a torrent
    mixed_inodes.json    Inodes where some paths have torrents and some don't
    duplicate_files.json True duplicate groups (different inodes, same content)

Options:
    --top N               Limit ranking lists to N entries (default: show all)
    --min-dup-mb N        Ignore files smaller than N MB for dup detection (default: 1)
    --one-filesystem      Stay on the same device as ROOT (skip mount points)
    --workers N           Threads for parallel hashing (default: 4)
    -q, --quiet           Suppress progress output
    --no-log              Don't write diskreport.log
    --no-fix              Skip interactive dedup (just report)
    --auto-fix            Consolidate all duplicates without prompting (use with caution)
    --dry-run             Show what dedup/cleanup would do, without touching files
    --hash-db FILE        Override hash cache location (default: .disk_cache.db next to script)
    --no-cache            Disable the hash cache entirely
    --rehash              Ignore cached hashes and re-hash everything (still updates DB)
    --media-dir DIR       Media folder: (1) mixed inodes whose only non-torrent
                          paths are inside this dir get reclassified as "used";
                          (2) a non-seeded file with no other hardlinks (st_nlink==1)
                          living only in this dir is also treated as "used"
                          (overrides MEDIA_DIR)
    --no-keep-unseeded-media  Disable (2) above: non-seeded single-link files in
                          --media-dir are classified "unused" (default: "used")
    --stale-days N        Flag inodes not accessed in N days as stale (uses atime; 0=off)
    --ignore-ext E,E      Comma-separated extensions to skip (e.g. nfo,txt,srt,jpg)
    --no-cleanup-orphans  Skip orphan path cleanup (on by default with --media-dir + qBt)
    --auto-cleanup        Remove all orphan paths without prompting
    --no-cleanup-empty    Skip empty folder cleanup (on by default after other cleanups)
    --auto-cleanup-empty  Remove all empty folders without prompting
    --cross-seed          Hardlink all unused files into ROOT/cross-seed-dir/ (requires qBt)

qBittorrent options (a command-line arg overrides the value from .env):
    --qbt-url URL         Web UI base URL (else QBT_URL in .env)
    --qbt-user USER       Username (else QBT_USER in .env)
    --qbt-pass PASS       Password (prefer .env or an env var to avoid ps exposure)
    --qbt-instance U|U|P  Add an EXTRA instance "url|user|pass" (repeatable). Torrents
                          from every instance (this, --qbt-url, and QBT_INSTANCES in
                          .env) are merged into one pool for evaluation
    --path-map LOCAL|QBT  Map an on-disk path prefix to the prefix qBittorrent reports
                          (repeatable; for Docker bind mounts, mergerfs, etc.).
                          E.g. "/mnt/disk1|/mnt/pool". Merges with PATH_MAPPINGS in .env
    --insecure            Disable SSL cert verification (for self-signed certs); all instances
    --all-torrents        Treat ALL torrents as active (default: only active ones count)
"""

import argparse
import getpass
import hashlib
import io
import json
import os
import queue
import shutil
import re
import signal
import sqlite3
import stat
import sys
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
import ssl
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor, as_completed
from http.cookiejar import CookieJar

# ── Attempt fast hash (xxhash) with fallback to sha256 ──────────────────────
try:
    import xxhash

    def _new_hasher():
        return xxhash.xxh128()

    HASH_NAME = "xxh128"
except ImportError:
    def _new_hasher():
        return hashlib.sha256()

    HASH_NAME = "sha256"

# ── Configuration (loaded from an adjacent .env file) ─────────────────────────
# Nothing site-specific is hardcoded below. All user configuration lives in a
# `.env` file next to this script — copy `.env.example` to `.env` and edit it.
# The `.env` file is git-ignored, so your paths and credentials never get
# committed. Values resolve as:
#     a real environment variable  >  the `.env` file  >  the built-in default.

def _load_env_file(path):
    """Minimal KEY=VALUE parser (stdlib only): ignores blank lines and `#`
    comments, tolerates a leading `export `, and strips one layer of matching
    surrounding quotes."""
    data = {}
    try:
        with open(path, encoding="utf-8") as fh:
            for raw in fh:
                line = raw.strip()
                if not line or line.startswith("#"):
                    continue
                if line.startswith("export "):
                    line = line[7:].lstrip()
                if "=" not in line:
                    continue
                key, val = line.split("=", 1)
                key, val = key.strip(), val.strip()
                if len(val) >= 2 and val[0] == val[-1] and val[0] in ("'", '"'):
                    val = val[1:-1]
                data[key] = val
    except OSError:
        pass
    return data

# Directory the script itself lives in. ALL generated output — the hash-cache
# DB, the log, the JSON reports and the HTML report — is written here, NOT under
# the directory being scanned. (The scanned path can be a read-only mount, a
# mergerfs union, or somewhere you don't want littered with report files.)
_SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))

_ENV_PATH = os.environ.get("DISK_ENV") or os.path.join(_SCRIPT_DIR, ".env")
_ENV = _load_env_file(_ENV_PATH)

def _cfg(key, default=None):
    """A real environment variable wins, then the .env file, then *default*."""
    if key in os.environ:
        return os.environ[key]
    return _ENV.get(key, default)

def _cfg_int(key, default):
    try:
        return int(_cfg(key))
    except (TypeError, ValueError):
        return default

def _cfg_list(key, default):
    """List value: a JSON array (best for paths with spaces/odd chars) or a
    plain comma-separated string."""
    v = _cfg(key)
    if v is None:
        return list(default)
    v = v.strip()
    if not v:
        return []
    if v.startswith("["):
        try:
            return list(json.loads(v))
        except ValueError:
            pass
    return [x.strip() for x in v.split(",") if x.strip()]

def _cfg_json(key, default):
    v = _cfg(key)
    if not v or not v.strip():
        return default
    try:
        return json.loads(v)
    except ValueError:
        return default

# ── Fixed internals (not site-specific; override in .env only if you must) ──
PARTIAL_BYTES = _cfg_int("PARTIAL_BYTES", 8192)     # head+tail bytes for the quick filter
READ_CHUNK    = _cfg_int("READ_CHUNK", 1 << 17)     # 128 KiB per read()
W             = _cfg_int("REPORT_WIDTH", 90)        # terminal report width

# ── User configuration (all sourced from .env — see .env.example) ──
QBT_URL       = _cfg("QBT_URL", "")
QBT_USER      = _cfg("QBT_USER", "")
QBT_PASS      = _cfg("QBT_PASS", "")
QBT_INSTANCES = _cfg_json("QBT_INSTANCES", [])      # extra instances, merged into one pool
MEDIA_DIR     = _cfg_list("MEDIA_DIRS", [])         # media folder(s); one per branch on mergerfs
PATH_MAPPINGS = _cfg_json("PATH_MAPPINGS", {})      # {on-disk prefix: qBittorrent prefix}
IGNORE_EXT    = _cfg_list("IGNORE_EXT", [])         # extensions to skip during the scan

# ── Media type classification by extension ────────────────────────────────────
MEDIA_TYPES = {
    "video":    {"mkv", "mp4", "avi", "wmv", "flv", "mov", "webm", "m4v",
                 "mpg", "mpeg", "ts", "vob", "divx", "3gp", "ogv", "rmvb"},
    "disc":     {"m2ts", "jar", "otf", "clpi", "bdmv", "pcm", "mpls", "lst",
                 "inf", "upt", "xml", "crl", "cci", "crt", "properties", "tbl",
                 "md5", "bdjo", "sig", "version", "bin", "fontindex", "cer", "ini"},
    "audio":    {"flac", "mp3", "ogg", "opus", "aac", "m4a", "wav", "wma",
                 "ape", "alac", "aiff", "dsf", "dff", "wv"},
    "books":    {"epub", "pdf", "mobi", "azw", "azw3", "djvu", "cbr", "cbz",
                 "fb2", "lit", "lrf", "opf", "rtf"},
    "subtitle": {"srt", "ass", "ssa", "sub", "idx", "vtt", "sup"},
    "image":    {"jpg", "jpeg", "png", "gif", "bmp", "tiff", "webp", "svg",
                 "ico"},
    "nzbs":     {"nzb", "password"},
    "metadata": {"nfo", "txt", "torrent", "sfv", "cue", "log", "m3u",
                 "m3u8", "pls"},
}

# qBittorrent states considered "active" (seeding, downloading, checking, queued, …).
# Torrents NOT in this set (e.g. pausedUP, pausedDL, error) are treated as inactive
# unless --all-torrents is passed. Override via ACTIVE_TORRENT_STATES in .env.
ACTIVE_TORRENT_STATES = frozenset(_cfg_list("ACTIVE_TORRENT_STATES", [
    "uploading", "stalledUP", "forcedUP", "checkingUP", "queuedUP",
    "downloading", "stalledDL", "forcedDL", "checkingDL", "queuedDL",
    "moving", "allocating", "metaDL", "forcedMetaDL",
]))

# ── Graceful interruption state ──────────────────────────────────────────────
# Updated by _run() at key milestones so the SIGINT handler can write partial results.
_run_state = {
    "root": None,       # scanned-root label (first path the user gave)
    "out_dir": None,    # where report/JSON files are written (the script's dir)
    "inodes": None,
    "dupes": None,
    "errors": None,
    "qbt_files": None,
    "args": None,
}
_interrupted = False

# Resolved path-prefix mappings (list of (local_prefix, qbt_prefix) tuples),
# published by _run() so the torrent-lookup helpers can translate an on-disk path
# to the path qBittorrent reports. Empty = no translation. See --path-map / PATH_MAPPINGS.
_PATH_MAPPINGS = []


def _sigint_handler(signum, frame):
    """Handle Ctrl+C: write partial results if scan data is available."""
    global _interrupted
    if _interrupted:
        # Second Ctrl+C → force exit
        print("\n\n  Forced exit.", file=sys.stderr)
        sys.exit(1)
    _interrupted = True
    print("\n\n  ⚠ Interrupted! Writing partial results …", file=sys.stderr)

    st = _run_state
    if st["inodes"] and st["root"]:
        try:
            root = st["root"]
            out_dir = st.get("out_dir") or _SCRIPT_DIR
            args = st["args"]
            active_only = not args.all_torrents if args else False
            media_dirs = args.media_dirs if args else None
            stale_days = args.stale_days if args else 0
            dupes = st["dupes"] or []
            errors = st["errors"] or []

            write_reports(root, st["inodes"], dupes, errors,
                          st["qbt_files"], media_dirs, active_only,
                          stale_days=stale_days, out_dir=out_dir)
            write_html_report(root, st["inodes"], dupes,
                              st["qbt_files"], media_dirs, active_only,
                              stale_days=stale_days, out_dir=out_dir)
            print(f"  Partial results saved to {out_dir}", file=sys.stderr)
        except Exception as exc:
            print(f"  ⚠ Failed to write partial results: {exc}", file=sys.stderr)
    else:
        print("  No scan data collected yet — nothing to save.", file=sys.stderr)
    sys.exit(130)


# ── Tee logger (stdout + file) ────────────────────────────────────────────────

class TeeWriter:
    """Write to both a terminal stream and a log file simultaneously."""

    def __init__(self, terminal, log_file):
        self.terminal = terminal
        self.log_file = log_file

    def write(self, data):
        self.terminal.write(data)
        if self.log_file:
            # Strip ANSI escape codes for the log file
            import re
            clean = re.sub(r'\033\[[^m]*m|\033\[K|\r', '', data)
            self.log_file.write(clean)

    def flush(self):
        self.terminal.flush()
        if self.log_file:
            self.log_file.flush()

    # Pass through other attributes to terminal (for isatty, etc.)
    def __getattr__(self, name):
        return getattr(self.terminal, name)


# ── Hash cache (SQLite) ──────────────────────────────────────────────────────

class HashCache:
    """
    Persistent cache mapping (path, inode, size, mtime) → hash digest.

    On a 40 TB drive, the hashing phase dominates runtime.  stat() is ~1000x
    faster than reading file contents, so if a file's metadata hasn't changed
    we can safely reuse the cached hash and skip all I/O on that file.

    The cache key includes inode + size + mtime so that:
      - renamed files are re-hashed (path changed)
      - modified files are re-hashed (mtime and/or size changed)
      - replaced files are re-hashed (inode changed)

    Thread safety: one connection per thread via threading.local().
    """

    SCHEMA_VERSION = 1

    def __init__(self, db_path: str, force_rehash: bool = False):
        self.db_path = db_path
        self.force_rehash = force_rehash
        self._local = threading.local()
        self.hits = 0
        self.misses = 0
        self._lock = threading.Lock()  # for stats counters
        self._init_db()

    def _get_conn(self) -> sqlite3.Connection:
        """Return a per-thread connection."""
        conn = getattr(self._local, "conn", None)
        if conn is None:
            conn = sqlite3.connect(self.db_path, timeout=10)
            conn.execute("PRAGMA journal_mode=WAL")
            conn.execute("PRAGMA synchronous=NORMAL")
            self._local.conn = conn
        return conn

    def _init_db(self):
        conn = self._get_conn()
        conn.execute("""
            CREATE TABLE IF NOT EXISTS hash_cache (
                path       TEXT NOT NULL,
                inode      INTEGER NOT NULL,
                size       INTEGER NOT NULL,
                mtime_ns   INTEGER NOT NULL,
                hash_type  TEXT NOT NULL,
                digest     TEXT NOT NULL,
                updated_at REAL NOT NULL,
                PRIMARY KEY (path, hash_type)
            )
        """)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS meta (
                key   TEXT PRIMARY KEY,
                value TEXT
            )
        """)
        # Check schema version
        row = conn.execute(
            "SELECT value FROM meta WHERE key='schema_version'"
        ).fetchone()
        if row is None:
            conn.execute(
                "INSERT INTO meta (key, value) VALUES ('schema_version', ?)",
                (str(self.SCHEMA_VERSION),)
            )
        conn.commit()

    def get(self, path: str, inode: int, size: int,
            mtime_ns: int, hash_type: str) -> str | None:
        """Return cached digest if metadata matches, else None."""
        if self.force_rehash:
            with self._lock:
                self.misses += 1
            return None

        conn = self._get_conn()
        row = conn.execute(
            """SELECT digest FROM hash_cache
               WHERE path = ? AND hash_type = ?
                 AND inode = ? AND size = ? AND mtime_ns = ?""",
            (path, hash_type, inode, size, mtime_ns),
        ).fetchone()

        with self._lock:
            if row:
                self.hits += 1
            else:
                self.misses += 1
        return row[0] if row else None

    def put(self, path: str, inode: int, size: int,
            mtime_ns: int, hash_type: str, digest: str):
        """Store or update a hash in the cache."""
        conn = self._get_conn()
        conn.execute(
            """INSERT OR REPLACE INTO hash_cache
               (path, inode, size, mtime_ns, hash_type, digest, updated_at)
               VALUES (?, ?, ?, ?, ?, ?, ?)""",
            (path, inode, size, mtime_ns, hash_type, digest, time.time()),
        )
        conn.commit()

    def prune_missing(self, valid_paths: set):
        """Remove entries for paths that no longer exist on disk."""
        conn = self._get_conn()
        cursor = conn.execute("SELECT DISTINCT path FROM hash_cache")
        to_delete = [row[0] for row in cursor if row[0] not in valid_paths]
        if to_delete:
            conn.executemany(
                "DELETE FROM hash_cache WHERE path = ?",
                [(p,) for p in to_delete],
            )
            conn.commit()
        return len(to_delete)

    @property
    def total_lookups(self):
        return self.hits + self.misses


class NoCache:
    """Null-object stand-in when no --hash-db is given."""
    hits = 0
    misses = 0
    total_lookups = 0
    force_rehash = False

    def get(self, *a, **kw):
        return None

    def put(self, *a, **kw):
        pass

    def prune_missing(self, *a, **kw):
        return 0


# ── Helpers ──────────────────────────────────────────────────────────────────

# Build reverse lookup: extension → media type (cached at import time)
_EXT_TO_MEDIA_TYPE = {}
for _mt, _exts in MEDIA_TYPES.items():
    for _ext in _exts:
        _EXT_TO_MEDIA_TYPE[_ext] = _mt


def classify_media_type(path: str) -> str:
    """Return the media type category for a file path based on its extension."""
    ext = os.path.splitext(path)[1].lstrip(".").lower()
    return _EXT_TO_MEDIA_TYPE.get(ext, "other")


def hr(size_bytes: int) -> str:
    """Bytes → human-readable string."""
    if size_bytes < 0:
        return f"-{hr(-size_bytes)}"
    for unit in ("B", "KB", "MB", "GB", "TB", "PB", "EB"):
        if size_bytes < 1024:
            return f"{size_bytes:.1f} {unit}"
        size_bytes /= 1024
    return f"{size_bytes:.1f} ZB"


def _partial_hash_raw(path: str, size: int) -> str:
    """Hash the first + last PARTIAL_BYTES of a file (fast pre-filter)."""
    h = _new_hasher()
    try:
        with open(path, "rb") as f:
            head = f.read(PARTIAL_BYTES)
            h.update(head)
            if size > PARTIAL_BYTES * 2:
                f.seek(-PARTIAL_BYTES, 2)
                h.update(f.read(PARTIAL_BYTES))
    except (PermissionError, OSError):
        return None
    return h.hexdigest()


def _full_hash_raw(path: str) -> str:
    """Hash the entire file content."""
    h = _new_hasher()
    try:
        with open(path, "rb") as f:
            while True:
                chunk = f.read(READ_CHUNK)
                if not chunk:
                    break
                h.update(chunk)
    except (PermissionError, OSError):
        return None
    return h.hexdigest()


def partial_hash(path: str, size: int, inode: int, mtime_ns: int,
                 cache: "HashCache | NoCache") -> str:
    """Partial hash with cache support."""
    ht = f"partial-{HASH_NAME}"
    cached = cache.get(path, inode, size, mtime_ns, ht)
    if cached is not None:
        return cached
    digest = _partial_hash_raw(path, size)
    if digest is not None:
        cache.put(path, inode, size, mtime_ns, ht, digest)
    return digest


def full_hash(path: str, size: int, inode: int, mtime_ns: int,
              cache: "HashCache | NoCache") -> str:
    """Full hash with cache support."""
    ht = f"full-{HASH_NAME}"
    cached = cache.get(path, inode, size, mtime_ns, ht)
    if cached is not None:
        return cached
    digest = _full_hash_raw(path)
    if digest is not None:
        cache.put(path, inode, size, mtime_ns, ht, digest)
    return digest


class ProgressPrinter:
    """Throttled progress line on stderr."""

    def __init__(self, quiet: bool = False):
        self._quiet = quiet
        self._last = 0.0
        self._interval = 0.25  # seconds

    def update(self, msg: str):
        if self._quiet:
            return
        now = time.monotonic()
        if now - self._last >= self._interval:
            sys.stderr.write(f"\r\033[K  {msg}")
            sys.stderr.flush()
            self._last = now

    def clear(self):
        if not self._quiet:
            sys.stderr.write("\r\033[K")
            sys.stderr.flush()


# ── Utility: sanitise URLs for safe logging ──────────────────────────────────

def _sanitize_url(url: str) -> str:
    """Strip credentials from a URL for safe display in logs."""
    return re.sub(r'(https?://)([^@]+@)', r'\1***@', url)


# ── qBittorrent WebAPI client ────────────────────────────────────────────────

class QBittorrentClient:
    """Minimal qBittorrent Web API client using only stdlib."""

    def __init__(self, base_url: str, username: str, password: str,
                 insecure: bool = False):
        self.base_url = base_url.rstrip("/")
        self.username = username
        self.password = password
        # SSL context — verify certs by default, --insecure to bypass
        self._ssl_ctx = ssl.create_default_context()
        if insecure:
            self._ssl_ctx.check_hostname = False
            self._ssl_ctx.verify_mode = ssl.CERT_NONE
        # Cookie jar to persist the SID session cookie
        self._cookie_jar = CookieJar()
        self._opener = urllib.request.build_opener(
            urllib.request.HTTPCookieProcessor(self._cookie_jar),
            urllib.request.HTTPSHandler(context=self._ssl_ctx),
        )
        self._logged_in = False

    def _request(self, endpoint: str, data: dict = None,
                 _retry: bool = True) -> bytes:
        """Make a request to the qBittorrent API, with automatic re-auth on 401/403."""
        url = f"{self.base_url}/api/v2/{endpoint}"
        if data is not None:
            encoded = urllib.parse.urlencode(data).encode("utf-8")
            req = urllib.request.Request(url, data=encoded)
        else:
            req = urllib.request.Request(url)
        try:
            resp = self._opener.open(req, timeout=30)
            return resp.read()
        except urllib.error.HTTPError as e:
            if e.code in (401, 403) and _retry and endpoint != "auth/login":
                self._logged_in = False
                self.login()
                return self._request(endpoint, data, _retry=False)
            raise

    def login(self):
        """Authenticate and store the session cookie."""
        body = self._request("auth/login", {
            "username": self.username,
            "password": self.password,
        })
        text = body.decode("utf-8", errors="replace").strip()
        if text.lower().startswith("fail"):
            raise RuntimeError("qBittorrent login failed — check credentials")
        self._logged_in = True

    def get_all_torrent_files(self, progress: ProgressPrinter = None) -> dict:
        """
        Return a dict mapping every absolute file path known to qBittorrent
        to a list of torrent associations (a file can belong to multiple
        torrents via hardlinks or identical paths):
            { "/abs/path/to/file": [{"torrent_name": str, "torrent_hash": str}, …] }
        """
        if not self._logged_in:
            self.login()

        raw = self._request("torrents/info")
        torrents = json.loads(raw)

        # path -> list of torrent associations (one file can serve multiple torrents)
        file_map = defaultdict(list)
        for idx, torrent in enumerate(torrents):
            t_hash = torrent.get("hash", "")
            t_name = torrent.get("name", "")
            t_state = torrent.get("state", "unknown")
            save_path = torrent.get("save_path") or torrent.get("content_path", "")
            save_path = save_path.rstrip("/").rstrip("\\")

            if progress:
                progress.update(
                    f"qBittorrent: torrent {idx + 1}/{len(torrents)} — {t_name[:50]}"
                )

            try:
                files_raw = self._request("torrents/files", {"hash": t_hash})
                files = json.loads(files_raw)
            except Exception:
                continue

            for f in files:
                rel_name = f.get("name", "")
                abs_path = os.path.normpath(os.path.join(save_path, rel_name))
                file_map[abs_path].append({
                    "torrent_name": t_name,
                    "torrent_hash": t_hash,
                    "torrent_state": t_state,
                })

        if progress:
            progress.clear()

        return dict(file_map)


# ── Torrent lookup helpers ───────────────────────────────────────────────────

def _merge_qbt_file_maps(maps: list) -> dict:
    """Merge several {path: [associations]} maps (one per qBittorrent instance)
    into a single pooled map. Source instance is NOT recorded — torrents from
    all instances are treated identically for evaluation.

    Within a path, associations referring to the same torrent (same non-empty
    torrent_hash) are de-duplicated so an identical torrent seeded on two
    instances isn't listed twice. Associations with no hash, and distinct
    torrents that legitimately share a path, are all kept.
    """
    merged = defaultdict(list)
    for fmap in maps:
        if not fmap:
            continue
        for path, assocs in fmap.items():
            bucket = merged[path]
            seen_hashes = {a.get("torrent_hash") for a in bucket
                           if a.get("torrent_hash")}
            for a in assocs:
                h = a.get("torrent_hash")
                if h and h in seen_hashes:
                    continue
                bucket.append(a)
                if h:
                    seen_hashes.add(h)
    return dict(merged)


def _mapped_lookup_keys(path: str) -> list:
    """Return the qBittorrent lookup key(s) for an on-disk *path*.

    Always includes the path itself (normalised). If a path mapping applies
    (``_PATH_MAPPINGS``: on-disk prefix → qBittorrent prefix), also includes the
    rewritten path using the LONGEST matching local prefix. This lets the script
    match a scanned file like ``/mnt/disk1/x.mkv`` against a torrent qBittorrent
    reports as ``/mnt/pool/x.mkv`` (Docker bind mounts, mergerfs, etc.).

    The on-disk path is matched literally (no realpath) so a union/overlay mount
    prefix isn't resolved to its underlying branch before mapping.
    """
    norm = os.path.normpath(path)
    keys = [norm]
    if _PATH_MAPPINGS:
        best = None  # (local_prefix, qbt_prefix) with the longest matching local
        for local, qbt in _PATH_MAPPINGS:
            if norm == local or norm.startswith(local + os.sep):
                if best is None or len(local) > len(best[0]):
                    best = (local, qbt)
        if best:
            local, qbt = best
            rewritten = os.path.normpath(qbt + norm[len(local):])
            if rewritten not in keys:
                keys.append(rewritten)
    return keys


def _qbt_lookup(path: str, qbt_files: dict, active_only: bool = False):
    """Return list of torrent associations for a path, or None if qbt not connected.

    The path is looked up under every key from ``_mapped_lookup_keys`` (the path
    itself plus any path-mapping rewrite), so files whose qBittorrent path differs
    from the on-disk path are still matched. Associations found via more than one
    key that refer to the same torrent (same non-empty torrent_hash) are de-duped.

    If *active_only* is True, only return associations whose torrent_state is
    in ACTIVE_TORRENT_STATES (filtering out paused/errored torrents).
    """
    if qbt_files is None:
        return None
    keys = _mapped_lookup_keys(path)
    if len(keys) == 1:
        associations = qbt_files.get(keys[0], [])
    else:
        associations = []
        seen_hashes = set()
        for key in keys:
            for a in qbt_files.get(key, []):
                h = a.get("torrent_hash")
                if h and h in seen_hashes:
                    continue
                associations.append(a)
                if h:
                    seen_hashes.add(h)
    if active_only and associations:
        associations = [a for a in associations
                        if a.get("torrent_state", "") in ACTIVE_TORRENT_STATES]
    return associations


def _torrent_tag(path: str, qbt_files: dict) -> str:
    """Short display tag for terminal output."""
    if qbt_files is None:
        return ""
    torrents = _qbt_lookup(path, qbt_files)
    if torrents:
        names = ", ".join(t["torrent_name"][:35] for t in torrents)
        return f" [T: {names}]"
    return " [no torrent]"


def _path_torrent_symbol(path: str, qbt_files: dict) -> str:
    """Return a status symbol for a hardlink path."""
    if qbt_files is None:
        return "│"
    torrents = _qbt_lookup(path, qbt_files)
    if torrents:
        has_active = any(t.get("torrent_state", "") in ACTIVE_TORRENT_STATES
                         for t in torrents)
        return "T" if has_active else "P"  # T=active, P=paused/inactive
    return "·"      # orphan (no torrent)


# ── Argument parsing ─────────────────────────────────────────────────────────

def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(
        description="Disk audit: find duplicates, list hardlinks, check qBittorrent."
    )
    p.add_argument("roots", metavar="PATH", nargs="+",
                   help="Top-level director(y|ies) to scan. Pass MORE THAN ONE to "
                        "compare across drives — e.g. 'disk.py /mnt/disk1 "
                        "/mnt/disk2' scans both drives in one run so the same "
                        "file present on different drives can be detected (see "
                        "cross_drive_duplicates.json). Reports, the log and the hash "
                        "cache are written next to disk.py itself (the script's own "
                        "directory), not under the scanned path(s); the first path is "
                        "recorded as the scanned root inside the reports.")
    p.add_argument("--top", type=int, default=0,
                   help="Limit ranking lists to N entries (default: show all)")
    p.add_argument("--min-dup-mb", type=int, default=1,
                   help="Min file size in MB for dup detection (default 1)")
    p.add_argument("--one-filesystem", action="store_true",
                   help="Do not cross filesystem boundaries (DEFAULT: on). Kept "
                        "for back-compat; the default is now on, so this is a "
                        "no-op reaffirming it. Use --cross-filesystem to disable.")
    p.add_argument("--cross-filesystem", action="store_true",
                   help="Allow the scan to cross filesystem boundaries. Off by "
                        "default: staying on one filesystem is safer for branch "
                        "scans (e.g. /mnt/disk1) so the walk never wanders "
                        "into a nested mount, and it keeps inode identity sane.")

    mfs = p.add_argument_group("mergerfs",
                               "Point at a mergerfs UNION and the tool scans the "
                               "real disks underneath it")
    mfs.add_argument("--no-mergerfs-expand", action="store_true",
                     help="Don't auto-expand a mergerfs union into its branches. "
                          "By default, passing a union path (e.g. /mnt/pool) "
                          "discovers the underlying branches, scans them directly, "
                          "auto-derives branch→union path mappings for qBittorrent, "
                          "and expands union --media-dir paths to each branch. With "
                          "this flag the union tree is scanned as-is instead.")
    mfs.add_argument("--mergerfs-branches", metavar="P1,P2,…", default=None,
                     help="Override auto-discovery: comma/colon-separated branch "
                          "base paths to use for any union root (e.g. "
                          "'/mnt/disk1,/mnt/disk2'). Normally unnecessary — "
                          "branches are read from mergerfs automatically.")
    mfs.add_argument("--no-repair-skeleton", action="store_true",
                     help="Don't mirror the directory skeleton across branches after "
                          "empty-folder cleanup. By default, when a union is expanded, "
                          "any directory present under one branch's scanned subtree but "
                          "missing on another is created there (repairing "
                          "func.mkdir=epall gaps so file placement stays correct). "
                          "Only creates directories; never files or deletions.")
    p.add_argument("--workers", type=int, default=4,
                   help="Max full-hash readers PER non-rotational (SSD/NVMe) drive "
                        "(default 4). Spinning disks always get exactly ONE reader "
                        "regardless of this value — reading two files at once from "
                        "one platter just causes seek thrashing. Different drives "
                        "are always read in parallel (one reader each), so on an "
                        "N-HDD setup the hashing phase uses N readers and drops to "
                        "1 as drives finish. Set 1 to force fully sequential.")
    p.add_argument("-q", "--quiet", action="store_true",
                   help="Suppress progress output")
    p.add_argument("--no-log", action="store_true",
                   help="Don't write diskreport.log")
    p.add_argument("--stale-days", type=int, default=0, metavar="N",
                   help="Flag inodes not accessed in N days as stale (uses atime; 0=off)")
    p.add_argument("--ignore-ext", metavar="EXT,...", default=None,
                   help="Comma-separated extensions to skip (e.g. nfo,txt,srt,jpg). "
                        "Replaces the hardcoded IGNORE_EXT list if provided.")

    qbt = p.add_argument_group("qBittorrent", "Check files against qBittorrent torrents")
    qbt.add_argument("--qbt-url", metavar="URL", default=None,
                     help="qBittorrent Web UI URL (overrides QBT_URL constant / env)")
    qbt.add_argument("--qbt-user", metavar="USER", default=None,
                     help="qBittorrent username (overrides QBT_USER constant / env)")
    qbt.add_argument("--qbt-pass", metavar="PASS", default=None,
                     help="qBittorrent password (overrides QBT_PASS constant / env). "
                          "Prefer QBT_PASS in .env or an env var to avoid exposing in ps output")
    qbt.add_argument("--qbt-instance", metavar="URL|USER|PASS", action="append",
                     default=None,
                     help="Add an EXTRA qBittorrent instance (repeatable). Format "
                          "'url|user|pass' (user/pass optional). Torrents from every "
                          "instance — including the --qbt-url one and any QBT_INSTANCES "
                          "constant — are merged into a single pool for evaluation.")
    qbt.add_argument("--insecure", action="store_true",
                     help="Disable SSL certificate verification for qBittorrent "
                          "(required for self-signed certs). Applies to ALL instances "
                          "(per-instance override possible via QBT_INSTANCES' 'insecure' key)")
    qbt.add_argument("--all-torrents", action="store_true",
                     help="Treat ALL torrents as active (default: only count actively "
                          "seeding/downloading torrents; paused/errored are ignored)")
    qbt.add_argument("--path-map", metavar="LOCAL|QBT", action="append", default=None,
                     help="Map an on-disk path prefix to the prefix qBittorrent reports "
                          "(repeatable). Use when qBittorrent sees different paths than "
                          "the real filesystem (Docker bind mounts, mergerfs/union mounts, "
                          "etc.). Format 'local|qbt', e.g. '/mnt/disk1|/mnt/pool'. Several "
                          "local prefixes may map to the same qBittorrent prefix. Merges "
                          "with the PATH_MAPPINGS constant.")

    p.add_argument("--media-dir", metavar="DIR", action="append", default=None,
                   help="Media folder path (REPEATABLE — pass once per branch on a "
                        "mergerfs setup). (1) Mixed inodes whose only non-torrent "
                        "paths are inside a media dir get reclassified as 'used'. "
                        "(2) A non-seeded file whose only filesystem link is inside "
                        "a media dir (st_nlink == 1) is also treated as 'used' rather "
                        "than unused. Overrides the hardcoded MEDIA_DIR list.")
    p.add_argument("--no-keep-unseeded-media", action="store_true",
                   help="Disable behavior (2) above: a non-seeded file with no other "
                        "hardlinks inside --media-dir is classified 'unused' instead "
                        "of 'used'. (Default: keep such files as 'used'.) Behavior (1), "
                        "the mixed-inode reclassification, is unaffected.")

    hdb = p.add_argument_group("Hash cache",
                               "Cache file hashes in SQLite for faster re-runs")
    hdb.add_argument("--hash-db", metavar="FILE", default=None,
                     help="SQLite file to cache hashes (default: .disk_cache.db "
                          "next to disk.py — the script's own directory)")
    hdb.add_argument("--no-cache", action="store_true",
                     help="Disable the hash cache entirely")
    hdb.add_argument("--rehash", action="store_true",
                     help="Ignore cached hashes and re-hash everything (updates DB)")

    fix = p.add_argument_group("Deduplication",
                               "Consolidate true duplicates into hardlinks (on by default)")
    fix.add_argument("--no-fix", action="store_true",
                     help="Skip interactive dedup (just report, don't offer to fix)")
    fix.add_argument("--auto-fix", action="store_true",
                     help="Consolidate all duplicate groups without prompting")
    fix.add_argument("--dry-run", action="store_true",
                     help="Show what dedup/cleanup would do without changing files")
    fix.add_argument("--consolidate-cross-drive", action="store_true",
                     help="Reclaim duplicates whose copies live on DIFFERENT drives "
                          "by MIGRATING the redundant copy onto the kept copy's drive: "
                          "recreate it as a hardlink to the kept inode at the same "
                          "relative path, then remove the source (no cross-drive "
                          "hardlink is created — that's impossible). On mergerfs the "
                          "union path is unchanged and the redundant copy is freed. "
                          "Always prompts per group; no --auto; respects --dry-run. "
                          "Cross-drive dupes are always REPORTED regardless.")

    orp = p.add_argument_group("Orphan cleanup",
                               "Remove orphan hardlink paths from mixed inodes "
                               "(on by default when --media-dir and qBittorrent are set)")
    orp.add_argument("--no-cleanup-orphans", action="store_true",
                     help="Skip orphan path cleanup (don't remove non-torrent paths "
                          "outside --media-dir from mixed inodes)")
    orp.add_argument("--auto-cleanup", action="store_true",
                     help="Remove all orphan paths without prompting (use with caution)")

    emp = p.add_argument_group("Empty folder cleanup",
                               "Remove empty directories after cleanup phases "
                               "(on by default)")
    emp.add_argument("--no-cleanup-empty", action="store_true",
                     help="Skip empty folder cleanup")
    emp.add_argument("--auto-cleanup-empty", action="store_true",
                     help="Remove all empty folders without prompting")

    xseed = p.add_argument_group("Cross-seed",
                                  "Hardlink unused files into a single directory "
                                  "for cross-seed tools")
    xseed.add_argument("--cross-seed", action="store_true",
                       help="Create a cross-seed-dir/ in ROOT with hardlinks to all "
                            "files classified as unused (requires qBittorrent)")

    args = p.parse_args()

    # ── Resolve qBittorrent defaults (command-line arg → .env / environment) ──
    # QBT_URL/USER/PASS already came from `.env` or a real environment variable.
    if args.qbt_url is None:
        args.qbt_url = QBT_URL
    if args.qbt_user is None:
        args.qbt_user = QBT_USER
    if args.qbt_pass is None:
        args.qbt_pass = QBT_PASS

    # ── Build the list of qBittorrent instances to query ──────────────────
    # Sources (all merged into one pool): the single --qbt-url/env/constant
    # instance, each repeatable --qbt-instance flag, and the QBT_INSTANCES
    # constant. De-duplicated by URL so the same instance isn't queried twice.
    instances = []
    seen_urls = set()

    def _add_instance(url, user, pass_, insecure):
        url = (url or "").strip().rstrip("/")
        if not url or url in seen_urls:
            return
        seen_urls.add(url)
        instances.append({"url": url, "user": user or "",
                          "pass": pass_ or "", "insecure": bool(insecure)})

    # Primary single instance (back-compatible).
    if args.qbt_url:
        _add_instance(args.qbt_url, args.qbt_user, args.qbt_pass, args.insecure)

    # Extra instances from --qbt-instance "url|user|pass" (repeatable).
    for spec in (args.qbt_instance or []):
        parts = spec.split("|")
        url = parts[0] if len(parts) > 0 else ""
        user = parts[1] if len(parts) > 1 else ""
        pass_ = parts[2] if len(parts) > 2 else ""
        if not url.strip():
            p.error(f"--qbt-instance entry has no URL: {spec!r} "
                    f"(expected 'url|user|pass')")
        _add_instance(url, user, pass_, args.insecure)

    # Extra instances hardcoded in the QBT_INSTANCES constant.
    for inst in QBT_INSTANCES:
        _add_instance(inst.get("url", ""), inst.get("user", ""),
                      inst.get("pass", ""), inst.get("insecure", args.insecure))

    args.qbt_instances = instances

    # ── Resolve path mappings (on-disk prefix → qBittorrent-visible prefix) ─
    # Keyed by normalised local prefix → normalised qbt prefix (one qbt prefix per
    # local prefix; several local prefixes may share a qbt prefix). The constant is
    # applied first, then --path-map flags override/extend per local prefix.
    path_map = {}
    _const_pairs = (PATH_MAPPINGS.items() if isinstance(PATH_MAPPINGS, dict)
                    else list(PATH_MAPPINGS))
    for local, qbt in _const_pairs:
        if local and qbt:
            path_map[os.path.normpath(local)] = os.path.normpath(qbt)
    for spec in (args.path_map or []):
        parts = spec.split("|")
        if len(parts) != 2 or not parts[0].strip() or not parts[1].strip():
            p.error(f"--path-map needs 'local|qbt' (both non-empty): {spec!r}")
        path_map[os.path.normpath(parts[0].strip())] = os.path.normpath(parts[1].strip())
    args.path_mappings = list(path_map.items())

    # ── Resolve media dirs (hardcoded MEDIA_DIR → --media-dir override) ──
    # Both the constant and the flag may be a single path or a list. Normalise
    # to a list of realpaths in args.media_dirs (the old single-string
    # args.media_dir is gone). Empty list = no media-dir behavior.
    if args.media_dir is not None:          # one or more --media-dir flags
        _raw_media = args.media_dir
    elif MEDIA_DIR:                          # fall back to the constant
        _raw_media = MEDIA_DIR
    else:
        _raw_media = []
    if isinstance(_raw_media, str):
        _raw_media = [_raw_media]
    args.media_dirs = [os.path.realpath(m) for m in _raw_media if m]

    # ── One-filesystem is now ON by default; --cross-filesystem disables it ─
    args.one_filesystem = not args.cross_filesystem

    # ── mergerfs union expansion (on by default) ─────────────────────────────
    args.mergerfs_expand = not args.no_mergerfs_expand
    args.repair_skeleton = not args.no_repair_skeleton
    if args.mergerfs_branches:
        args.mergerfs_branches = [os.path.normpath(b.strip())
                                  for b in re.split(r"[,:]", args.mergerfs_branches)
                                  if b.strip()]
    else:
        args.mergerfs_branches = []

    # ── Keep-unseeded-media is on by default (--no-keep-unseeded-media off) ─
    args.keep_unseeded_media = not args.no_keep_unseeded_media

    # ── Resolve ignore-ext (arg overrides hardcoded, else use hardcoded) ─
    if args.ignore_ext is not None:
        args.ignore_ext_set = frozenset(
            e.strip().lower().lstrip(".") for e in args.ignore_ext.split(",") if e.strip()
        )
    elif IGNORE_EXT:
        args.ignore_ext_set = frozenset(e.lower() for e in IGNORE_EXT)
    else:
        args.ignore_ext_set = frozenset()

    # ── Resolve hash-db default (script dir / .disk_cache.db) ───────────
    # The cache lives next to the script, not under the scanned root, so a
    # read-only or union mount can still be scanned and re-runs share one cache.
    if args.no_cache:
        args.hash_db = None
    elif args.hash_db is None:
        args.hash_db = os.path.join(_SCRIPT_DIR, ".disk_cache.db")

    # ── Fix is on by default (--no-fix to disable) ────────────────────────
    args.fix = not args.no_fix

    # ── Orphan cleanup is on by default (--no-cleanup-orphans to disable) ─
    args.cleanup_orphans = not args.no_cleanup_orphans

    # ── Empty folder cleanup is on by default (--no-cleanup-empty to skip)
    args.cleanup_empty = not args.no_cleanup_empty

    return args


# ── Scan phase ───────────────────────────────────────────────────────────────

# mergerfs (and FUSE unions generally) break the tool's core assumption that
# st_ino uniquely identifies a file. FUSE lets the server set st_ino but NOT
# st_dev (the kernel forces a single device id on the whole mount), and mergerfs
# with `inodecalc=passthrough` returns the raw underlying-filesystem inode. Two
# separate XFS branches reuse the same low inode numbers, so DIFFERENT files on
# different branches can report the SAME (st_dev, st_ino) through the union. If
# we grouped them together we'd treat two unrelated files as hardlinks of one
# inode — and orphan cleanup would then delete one "path" believing the bytes
# survive via the other, destroying real data. mergerfs' own docs warn that
# passthrough "could confuse file deduplication software as inodes from
# different filesystems can be the same".
#
# Fix: when the scan root is under a mergerfs mount, ask mergerfs which BRANCH
# each file physically lives on (the `user.mergerfs.basepath` pseudo-xattr) and
# key inodes by (branch, st_ino) instead of st_ino alone. Two hardlinks of one
# file share a branch AND an inode → grouped; two collided files on different
# branches differ in branch → kept separate. This works under any `inodecalc`
# (passthrough or the hash-based defaults) because it never trusts the union's
# inode number on its own.

def _mergerfs_root(root: str) -> bool:
    """True if *root* is under a mergerfs/FUSE-union mount that answers the
    mergerfs per-file xattr interface. Probed once; the probe is cheap and also
    tells us whether per-file branch resolution is even possible."""
    if not hasattr(os, "getxattr"):
        return False  # non-Linux (e.g. macOS) — no xattr API; caller falls back
    try:
        os.getxattr(root, "user.mergerfs.basepath")
        return True
    except OSError:
        return False


def _mergerfs_basepath(path: str):
    """Return the mergerfs BRANCH base path a file physically lives on (e.g.
    '/mnt/disk1'), or None if it can't be determined. Uses the documented
    `user.mergerfs.basepath` pseudo-xattr (see mergerfs Runtime Interface)."""
    try:
        return os.fsdecode(os.getxattr(path, "user.mergerfs.basepath"))
    except OSError:
        return None


def _mergerfs_discover(path: str):
    """Given any path, find the mergerfs mountpoint above it and the list of its
    underlying branch base paths. Returns (mountpoint, [branches]) or (None, []).

    Walks up from *path* looking for the mergerfs control pseudo-file
    ``<mountpoint>/.mergerfs`` that answers the ``user.mergerfs.branches`` query
    (documented Runtime Interface). The branches string looks like
    ``/mnt/disk1=RW:/mnt/disk2=RW`` — colon-separated, with an optional
    ``=MODE`` suffix that we strip. This is how the tool turns a single union
    path into the real disks underneath it."""
    if not hasattr(os, "getxattr"):
        return None, []
    p = os.path.abspath(path)
    while True:
        ctrl = os.path.join(p, ".mergerfs")
        try:
            raw = os.fsdecode(os.getxattr(ctrl, "user.mergerfs.branches"))
        except OSError:
            raw = None
        if raw is not None:
            branches = []
            for part in raw.split(":"):
                part = part.strip()
                if part:
                    branches.append(os.path.normpath(part.split("=", 1)[0]))
            return p, branches
        parent = os.path.dirname(p)
        if parent == p:
            return None, []
        p = parent


def scan(root: str, one_fs: bool, progress: ProgressPrinter,
         ignore_ext: frozenset = frozenset(), branch_label: str = None):
    """Walk the tree, collecting inode info.  Returns (inodes, dir_sizes, errors).

    Inodes are keyed by a collision-proof *identity*, NOT by st_ino alone:
      • mergerfs union → (branch_basepath, st_ino), resolved per file via xattr;
        if the branch can't be resolved, a unique per-path identity is used so
        the file is never grouped with another (safe: no phantom hardlinks).
      • everything else → (st_dev, st_ino).
    Each entry still records the raw st_ino as info["ino"] (for TOCTOU checks and
    the JSON "inode" field) and the branch as info["branch"]."""
    inodes = {}        # identity -> {size, dev, ino, branch, nlink, ..., paths}
    dir_sizes = defaultdict(int)
    errors = []
    root_dev = os.lstat(root).st_dev
    file_count = 0
    skipped_ext = 0

    # If the caller already knows which mergerfs branch this root IS (because it
    # expanded a union into branches), every file here belongs to that branch —
    # use it directly and skip per-file xattr resolution. Otherwise, detect a
    # union scan root and resolve each file's branch individually.
    is_mergerfs = (branch_label is None) and _mergerfs_root(root)
    if is_mergerfs:
        print("  Detected a mergerfs union at the scan root — resolving each "
              "file's real branch via xattr to avoid cross-branch inode "
              "collisions.")
        print("  (Tip: point at the union and let the tool expand to branches, "
              "or pass branches directly; see the mergerfs note in claude.md.)")

    for dirpath, dirnames, filenames in os.walk(root, topdown=True,
                                                  followlinks=False,
                                                  onerror=lambda e: errors.append(str(e))):
        dirnames[:] = [
            d for d in dirnames
            if not os.path.islink(os.path.join(dirpath, d))
        ]
        if one_fs:
            dirnames[:] = [
                d for d in dirnames
                if os.lstat(os.path.join(dirpath, d)).st_dev == root_dev
            ]

        for fname in filenames:
            # Skip ignored extensions
            if ignore_ext:
                ext = os.path.splitext(fname)[1].lstrip(".").lower()
                if ext in ignore_ext:
                    skipped_ext += 1
                    continue

            path = os.path.join(dirpath, fname)
            try:
                st = os.lstat(path)
            except (PermissionError, OSError) as exc:
                errors.append(f"{path}: {exc}")
                continue

            if not stat.S_ISREG(st.st_mode):
                continue
            if one_fs and st.st_dev != root_dev:
                continue

            raw_ino = st.st_ino
            # Build the collision-proof identity (see scan() docstring / the
            # mergerfs note above). On a mergerfs union we trust the branch, not
            # the union's inode number, to decide what is the "same file".
            if branch_label is not None:
                # Caller told us the branch (expanded-union scan): use it for both
                # identity and drive attribution. Robust even if two branches
                # happened to share an st_dev.
                branch = branch_label
                identity = (branch, raw_ino)
            elif is_mergerfs:
                branch = _mergerfs_basepath(path)
                if branch is None:
                    # Can't tell which branch this file is on → give it a unique
                    # identity so it is never grouped with anything else. Worst
                    # case a genuine hardlink group is split into singletons,
                    # which only means dedup/cleanup won't act on it — never data
                    # loss.
                    identity = ("__unresolved__", path)
                else:
                    identity = (branch, raw_ino)
            else:
                branch = None
                identity = (st.st_dev, raw_ino)

            if identity not in inodes:
                inodes[identity] = {"size": st.st_size, "dev": st.st_dev,
                               # Raw st_ino: used for TOCTOU verification during
                               # dedup and for the JSON "inode" field. NOT the
                               # dict key (which is the identity above).
                               "ino": raw_ino,
                               # Branch base path on a mergerfs union (else None).
                               "branch": branch,
                               "mtime_ns": st.st_mtime_ns,
                               "atime_ns": st.st_atime_ns,
                               # True hardlink count from the filesystem. This is
                               # NOT len(paths): paths only counts links found under
                               # the scanned root, whereas st_nlink counts every link
                               # on the device (including any outside the scan). Used
                               # by _classify_inode to recognise standalone files
                               # (nlink == 1) that have no other hardlinks anywhere,
                               # and as a safety backstop (len(paths) must never
                               # exceed nlink for a genuine hardlink group).
                               "nlink": st.st_nlink,
                               "paths": [path]}
                dir_sizes[dirpath] += st.st_size
            else:
                # Keep the most recent atime across all hardlink paths
                existing = inodes[identity]
                existing["paths"].append(path)
                if st.st_atime_ns > existing["atime_ns"]:
                    existing["atime_ns"] = st.st_atime_ns
                if st.st_mtime_ns > existing["mtime_ns"]:
                    existing["mtime_ns"] = st.st_mtime_ns

            file_count += 1
            progress.update(f"Scanned {file_count:,} paths … ({dirpath[-60:]})")

    progress.clear()
    if skipped_ext:
        print(f"  Skipped {skipped_ext:,} files by extension filter")
    return inodes, dir_sizes, errors


def scan_roots(roots: list, one_fs: bool, progress: ProgressPrinter,
               ignore_ext: frozenset = frozenset(), root_branches: dict = None):
    """Scan one or more roots and merge them into a single inode map.

    *root_branches* optionally maps a scan root → the mergerfs branch base path it
    represents (from union expansion); passed to scan() as `branch_label` so
    identity/drive attribution use the real branch.

    Each root is scanned by scan() (identity-keyed, so nothing collides across
    branches), then merged. When the same identity turns up under two roots
    (only possible if the roots overlap) its paths are unioned. Returns the same
    (inodes, dir_sizes, errors) triple as scan()."""
    merged = {}
    dir_sizes = defaultdict(int)
    errors = []
    root_branches = root_branches or {}
    for r in roots:
        ino_map, ds, errs = scan(r, one_fs, progress, ignore_ext,
                                 branch_label=root_branches.get(r))
        for identity, info in ino_map.items():
            if identity in merged:
                ex = merged[identity]
                for p in info["paths"]:
                    if p not in ex["paths"]:
                        ex["paths"].append(p)
                ex["atime_ns"] = max(ex["atime_ns"], info["atime_ns"])
                ex["mtime_ns"] = max(ex["mtime_ns"], info["mtime_ns"])
            else:
                merged[identity] = info
        for d, s in ds.items():
            dir_sizes[d] += s
        errors.extend(errs)
    return merged, dir_sizes, errors


# ── Drive attribution (for cross-drive duplicate detection) ──────────────────

def _drive_key(info: dict):
    """A stable key for the physical drive an inode lives on. On a mergerfs
    union that's the resolved branch base path; otherwise the filesystem's
    st_dev (each XFS branch is its own device, so branch scans differ too)."""
    return info.get("branch") or info.get("dev")


def _drive_label(info: dict) -> str:
    """Human-readable drive tag for reports."""
    b = info.get("branch")
    if b:
        return b
    return f"dev:{info.get('dev')}"


_ROTATIONAL_CACHE = {}   # st_dev -> bool

def _drive_is_rotational(info: dict) -> bool:
    """True if the inode lives on a spinning disk (so it should get exactly one
    reader). Reads Linux's ``/sys/dev/block/MAJOR:MINOR/queue/rotational`` for the
    filesystem's device (a dm-crypt/XFS device inherits the flag from the physical
    disk underneath). Unknown → True, i.e. assume spinning: the safe choice, since
    one reader per drive never thrashes — it only under-parallelises an SSD we
    failed to recognise."""
    dev = info.get("dev")
    if dev is None:
        return True
    if dev in _ROTATIONAL_CACHE:
        return _ROTATIONAL_CACHE[dev]
    rot = True
    try:
        with open(f"/sys/dev/block/{os.major(dev)}:{os.minor(dev)}/queue/rotational") as fh:
            rot = fh.read().strip() == "1"
    except (OSError, ValueError):
        rot = True
    _ROTATIONAL_CACHE[dev] = rot
    return rot


# ── mergerfs union expansion (point at the union, scan the disks) ────────────

def _expand_mergerfs_roots(orig_roots: list, args) -> tuple:
    """Make the tool 'mergerfs-aware' when the user simply points at the union.

    For each root that sits under a mergerfs mount, discover the underlying
    branches and replace the union root with the matching sub-path on EACH branch
    (so scanning happens on the real disks, where inode identity, st_nlink and
    hardlink creation are all exact). Also, without any manual config:

      • auto-derive branch→union path mappings (so qBittorrent — which reports
        union paths — still matches), merged with any user PATH_MAPPINGS;
      • expand any --media-dir given as a union path into its per-branch
        equivalents (so media reclassification works on the branch scan).

    Branch discovery is automatic (``user.mergerfs.branches`` via
    `_mergerfs_discover`); ``--mergerfs-branches`` overrides it, and
    ``--no-mergerfs-expand`` turns the whole thing off (scan the union tree
    as-is — still safe thanks to per-file branch resolution in scan()).

    Returns (scan_roots, expansion_info) and MUTATES args.path_mappings /
    args.media_dirs with the derived additions. Falls back to the original roots
    if nothing could be discovered."""
    if not getattr(args, "mergerfs_expand", True):
        return list(orig_roots), []

    scan_roots = []
    info = []              # list of (union_root, mountpoint, branches, added_roots)
    auto_maps = {}         # branch base path -> union mountpoint
    root_branches = {}     # scan root -> the branch base path it represents

    def _discover(path):
        mp, branches = _mergerfs_discover(path)
        if args.mergerfs_branches:          # manual override
            branches = list(args.mergerfs_branches)
            if not mp:
                mp = os.path.abspath(path)  # treat the given path as the union root
        return mp, branches

    for r in orig_roots:
        mp, branches = _discover(r)
        if mp and branches:
            rel = os.path.relpath(r, mp)
            added = []
            for b in branches:
                bpath = b if rel == "." else os.path.normpath(os.path.join(b, rel))
                auto_maps[os.path.normpath(b)] = os.path.normpath(mp)
                if os.path.isdir(bpath) and bpath not in scan_roots:
                    scan_roots.append(bpath)
                    root_branches[bpath] = os.path.normpath(b)
                    added.append(bpath)
            info.append((r, mp, branches, added))
        elif r not in scan_roots:
            scan_roots.append(r)

    args._mergerfs_root_branches = root_branches

    # Merge auto path mappings — a user-configured prefix always wins.
    if auto_maps:
        merged = {os.path.normpath(l): q for l, q in args.path_mappings}
        for b, mpp in auto_maps.items():
            merged.setdefault(b, mpp)
        args.path_mappings = list(merged.items())

    # Expand any media dir that lives under a union into per-branch equivalents.
    if args.media_dirs:
        expanded = list(args.media_dirs)
        for md in args.media_dirs:
            mp, branches = _discover(md)
            if mp and branches:
                rel = os.path.relpath(md, mp)
                for b in branches:
                    bmd = os.path.realpath(b if rel == "." else os.path.join(b, rel))
                    if bmd not in expanded:
                        expanded.append(bmd)
        args.media_dirs = expanded

    return (scan_roots or list(orig_roots)), info


# ── Duplicate detection (two-phase hashing) ──────────────────────────────────

def find_duplicates(inodes: dict, min_bytes: int, workers: int,
                    progress: ProgressPrinter, cache: "HashCache | NoCache" = None):
    """Return a list of duplicate groups sorted by wasted space (desc)."""
    if cache is None:
        cache = NoCache()

    size_groups = defaultdict(list)
    # NOTE: inodes is keyed by a composite identity (see scan()), but everything
    # downstream of here — the hash cache key, dedup's TOCTOU inode check, and
    # display — wants the RAW st_ino. Carry info["ino"] as the tuple's first
    # element so callers never see the composite key.
    for _identity, info in inodes.items():
        if info["size"] >= min_bytes:
            size_groups[info["size"]].append((info["ino"], info))

    candidates = {sz: grp for sz, grp in size_groups.items() if len(grp) >= 2}
    total_candidates = sum(len(g) for g in candidates.values())
    progress.update(f"Dup phase 0: {total_candidates:,} candidates in {len(candidates):,} size buckets")

    # Phase 1: partial hash
    partial_groups = defaultdict(list)
    done = 0
    for sz, grp in candidates.items():
        for ino, info in grp:
            ph = partial_hash(info["paths"][0], sz, ino,
                              info["mtime_ns"], cache)
            if ph is not None:
                partial_groups[(sz, ph)].append((ino, info))
            done += 1
            progress.update(f"Dup phase 1 (partial hash): {done:,}/{total_candidates:,}")

    phase2_groups = {k: v for k, v in partial_groups.items() if len(v) >= 2}
    phase2_total = sum(len(g) for g in phase2_groups.values())

    # ── Phase 2: full hash, scheduled PER DRIVE ──────────────────────────────
    # Reading two files at once from the SAME spinning disk makes the head seek
    # back and forth and destroys throughput, so a rotational drive gets exactly
    # ONE reader. Different drives are independent spindles, so they run in
    # PARALLEL — one reader each. As a drive runs out of files its reader exits,
    # so concurrency falls automatically (down to a single reader once only one
    # drive still has work). SSD/NVMe drives aren't seek-bound, so they may use
    # up to `workers` readers each. This generalises to any number of drives.
    dupes = []
    done = 0
    done_lock = threading.Lock()

    # Flatten candidates, remembering each item's (size, partial-hash) bucket so
    # only files in the same bucket are ever compared by full hash.
    by_drive = defaultdict(list)          # drive_key -> [(bucket_key, ino, info)]
    for bkey, grp in phase2_groups.items():
        for ino, info in grp:
            by_drive[_drive_key(info)].append((bkey, ino, info))

    results = []                          # (bucket_key, ino, info, digest)
    results_lock = threading.Lock()

    def _run_drive_queue(q):
        """One reader: drain a single drive's queue sequentially."""
        nonlocal done
        local = []
        while True:
            try:
                bkey, ino, info = q.get_nowait()
            except queue.Empty:
                break
            digest = full_hash(info["paths"][0], info["size"], ino,
                               info["mtime_ns"], cache)
            if digest is not None:
                local.append((bkey, ino, info, digest))
            with done_lock:
                done += 1
                progress.update(f"Dup phase 2 (full hash):    {done:,}/{phase2_total:,}")
        with results_lock:
            results.extend(local)

    # Decide readers per drive (1 for spinning disks; up to `workers` for SSDs)
    # and build one queue per drive shared by that drive's readers.
    readers = []                          # each entry is a queue to drain
    n_rot = n_ssd = 0
    for drive, drive_items in by_drive.items():
        q = queue.Queue()
        for it in drive_items:
            q.put(it)
        if _drive_is_rotational(drive_items[0][2]):
            permits = 1
            n_rot += 1
        else:
            permits = max(1, workers)
            n_ssd += 1
        permits = min(permits, len(drive_items))
        readers.extend([q] * permits)

    if readers:
        if len(by_drive) > 1 or n_ssd:
            plan = f"{len(readers)} reader(s) across {len(by_drive)} drive(s)"
            if n_rot:
                plan += f"; {n_rot} spinning drive(s) get 1 reader each"
            progress.update("")
            print(f"  Full-hash plan: {plan}")
        with ThreadPoolExecutor(max_workers=len(readers)) as pool:
            futs = [pool.submit(_run_drive_queue, q) for q in readers]
            for f in as_completed(futs):
                f.result()

    # Group results by (bucket, full digest); a group of ≥2 inodes is a dupe set.
    grouped = defaultdict(list)
    for bkey, ino, info, digest in results:
        grouped[(bkey, digest)].append((ino, info))
    for (bkey, _digest), copies in grouped.items():
        if len(copies) >= 2:
            sz = bkey[0]
            wasted = sz * (len(copies) - 1)
            drives = {_drive_key(info) for _ino, info in copies}
            dupes.append({
                "size": sz,
                "copies": copies,   # list of (ino, info)
                "wasted": wasted,
                # True when the identical copies live on >1 physical drive/branch.
                # These CANNOT be consolidated by hardlink (os.link is EXDEV across
                # branches); they're reported in cross_drive_duplicates.json so
                # they can be consolidated by removing a redundant copy instead.
                "cross_drive": len(drives) > 1,
            })

    progress.clear()
    dupes.sort(key=lambda d: d["wasted"], reverse=True)
    return dupes


# ── Report: build per-path annotations ──────────────────────────────────────

def _annotate_paths(paths: list, qbt_files: dict) -> list:
    """
    For a list of paths (hardlinks to the same inode), return a list of dicts:
        [{"path": str, "torrents": [...]|None}, ...]
    """
    result = []
    for p in paths:
        entry = {"path": p}
        if qbt_files is not None:
            entry["torrents"] = _qbt_lookup(p, qbt_files)
        else:
            entry["torrents"] = None
        result.append(entry)
    return result


# ── Report printing ──────────────────────────────────────────────────────────

def _limit(collection, top_n):
    """Slice a list; 0 means unlimited."""
    if top_n == 0:
        return collection
    return collection[:top_n]


def _print_inode_entry(rank: int, info: dict, qbt_files: dict, indent: str = "  "):
    """Print one inode's details: size, path count, each hardlink path + torrent status."""
    paths = info["paths"]
    n_links = len(paths)
    link_label = f"{n_links} path(s)" if n_links > 1 else "1 path"

    print(f"{indent}{rank:>4}. {hr(info['size']):>10}   [{link_label}]")

    for p in paths:
        sym = _path_torrent_symbol(p, qbt_files)
        t_detail = ""
        if qbt_files is not None:
            torrents = _qbt_lookup(p, qbt_files)
            if torrents:
                names = ", ".join(
                    f"{t['torrent_name'][:45]} ({t['torrent_state']})"
                    for t in torrents
                )
                t_detail = f"  ← {names}"
            else:
                t_detail = "  ← (no torrent)"
        print(f"{indent}       [{sym}] {p}{t_detail}")


def print_report(root, inodes, dir_sizes, dupes, errors, top_n, qbt_files,
                 stale_days=0):
    total_real = sum(i["size"] for i in inodes.values())
    total_apparent = sum(i["size"] * len(i["paths"]) for i in inodes.values())
    total_paths = sum(len(i["paths"]) for i in inodes.values())
    hl_groups = sum(1 for i in inodes.values() if len(i["paths"]) > 1)
    hl_paths = sum(len(i["paths"]) for i in inodes.values() if len(i["paths"]) > 1)
    saved = total_apparent - total_real
    limit_label = "ALL" if top_n == 0 else f"TOP {top_n}"

    # ── Summary ──────────────────────────────────────────────────────────────
    print(f"\n{'=' * W}")
    print(f"  DISK REPORT — {root}")
    print(f"{'=' * W}")
    print(f"  Unique files (inodes)  : {len(inodes):>12,}")
    print(f"  Total paths (hardlinks): {total_paths:>12,}")
    print(f"  Hardlinked groups      : {hl_groups:>12,}  ({hl_paths:,} paths)")
    print(f"  Apparent size          : {hr(total_apparent):>12}  (hardlinks counted per path)")
    print(f"  Real disk usage        : {hr(total_real):>12}  (each inode counted once)")
    print(f"  Saved via hardlinks    : {hr(saved):>12}")
    print(f"  Hash algorithm         : {HASH_NAME}")
    if qbt_files is not None:
        total_qbt_files = sum(len(v) for v in qbt_files.values()) if isinstance(next(iter(qbt_files.values()), None), list) else len(qbt_files)
        print(f"  qBittorrent paths      : {len(qbt_files):>12,}  (across {total_qbt_files:,} torrent associations)")

    # ── Media type breakdown ─────────────────────────────────────────────────
    type_stats = defaultdict(lambda: {"count": 0, "bytes": 0})
    for info in inodes.values():
        if not info["paths"]:
            continue
        mt = classify_media_type(info["paths"][0])
        type_stats[mt]["count"] += 1
        type_stats[mt]["bytes"] += info["size"]
    sorted_types = sorted(type_stats.items(), key=lambda x: x[1]["bytes"], reverse=True)
    print(f"\n{'─' * W}")
    print(f"  CONTENT TYPE BREAKDOWN (by real disk usage)")
    print(f"{'─' * W}")
    for mt, stats in sorted_types:
        pct = (stats["bytes"] / total_real * 100) if total_real > 0 else 0
        print(f"  {mt:<12}  {hr(stats['bytes']):>10}  {stats['count']:>8,} inodes  ({pct:5.1f}%)")

    # ── Legend ────────────────────────────────────────────────────────────────
    if qbt_files is not None:
        print(f"\n  Legend:  [T] = active torrent  [P] = paused/inactive torrent  "
              f"[·] = no torrent (orphan)")

    # ── Largest files ────────────────────────────────────────────────────────
    all_files_sorted = sorted(inodes.values(), key=lambda x: x["size"], reverse=True)
    display_files = _limit(all_files_sorted, top_n)

    print(f"\n{'─' * W}")
    print(f"  {limit_label} LARGEST FILES — by real size, with all hardlink paths")
    print(f"{'─' * W}")
    for rank, info in enumerate(display_files, 1):
        _print_inode_entry(rank, info, qbt_files)
    if top_n and len(all_files_sorted) > top_n:
        print(f"\n  … {len(all_files_sorted) - top_n:,} more inodes. Omit --top to show everything.")

    # ── Hardlinked files only ────────────────────────────────────────────────
    hl_sorted = sorted(
        [i for i in inodes.values() if len(i["paths"]) > 1],
        key=lambda x: x["size"] * len(x["paths"]),
        reverse=True,
    )
    display_hl = _limit(hl_sorted, top_n)

    if display_hl:
        print(f"\n{'─' * W}")
        print(f"  {limit_label} HARDLINKED FILES — sorted by apparent footprint")
        print(f"  (Review each path: is every hardlink serving a purpose?)")
        print(f"{'─' * W}")
        for rank, info in enumerate(display_hl, 1):
            _print_inode_entry(rank, info, qbt_files)
        if top_n and len(hl_sorted) > top_n:
            print(f"\n  … {len(hl_sorted) - top_n:,} more hardlinked groups. Omit --top to show all.")

    # ── Largest directories ──────────────────────────────────────────────────
    rolled = defaultdict(int)
    for d, sz in dir_sizes.items():
        rolled[d] += sz
        parent = d
        while True:
            parent = os.path.dirname(parent)
            if parent == root or len(parent) < len(root):
                break
            rolled[parent] += sz

    all_dirs = sorted(rolled.items(), key=lambda x: x[1], reverse=True)
    display_dirs = _limit(all_dirs, top_n)

    print(f"\n{'─' * W}")
    print(f"  {limit_label} LARGEST DIRECTORIES (unique inode bytes)")
    print(f"{'─' * W}")
    for rank, (d, sz) in enumerate(display_dirs, 1):
        print(f"  {rank:>4}. {hr(sz):>10}   {d}")
    if top_n and len(all_dirs) > top_n:
        print(f"  … {len(all_dirs) - top_n:,} more directories. Omit --top to show everything.")

    # ── True duplicates ──────────────────────────────────────────────────────
    print(f"\n{'─' * W}")
    print(f"  TRUE DUPLICATES  (same content, different inodes — wasted space)")
    print(f"{'─' * W}")

    if dupes:
        total_wasted = sum(d["wasted"] for d in dupes)
        print(f"\n  ⚠  {len(dupes):,} duplicate group(s) found")
        print(f"  ⚠  Recoverable space: {hr(total_wasted)}\n")
        display_dupes = _limit(dupes, top_n)
        for d in display_dupes:
            copies = d["copies"]  # list of (ino, info)
            total_copies = len(copies)
            total_paths_in_group = sum(len(info["paths"]) for _, info in copies)
            xd = " ⇄ CROSS-DRIVE" if d.get("cross_drive") else ""
            print(f"  [{hr(d['size'])} x {total_copies} inodes, "
                  f"{total_paths_in_group} total paths — wasted: {hr(d['wasted'])}]{xd}")
            for ci, (ino, info) in enumerate(copies):
                marker = "KEEP" if ci == 0 else "DUP "
                n_links = len(info["paths"])
                link_note = f" ({n_links} hardlinks)" if n_links > 1 else ""
                drive_note = f"  @ {_drive_label(info)}" if d.get("cross_drive") else ""
                print(f"    [{marker}] inode {ino}{link_note}{drive_note}:")
                for p in info["paths"]:
                    sym = _path_torrent_symbol(p, qbt_files)
                    t_detail = ""
                    if qbt_files is not None:
                        torrents = _qbt_lookup(p, qbt_files)
                        if torrents:
                            names = ", ".join(
                                f"{t['torrent_name'][:40]} ({t['torrent_state']})"
                                for t in torrents
                            )
                            t_detail = f"  ← {names}"
                        else:
                            t_detail = "  ← (no torrent)"
                    print(f"           [{sym}] {p}{t_detail}")
            print()
        if top_n and len(dupes) > top_n:
            print(f"  … and {len(dupes) - top_n:,} more group(s). Omit --top to show all. See duplicate_files.json for full list.")
    else:
        print(f"\n  No duplicates found above threshold. ✓\n")

    # ── Orphan summary (qbt only) ───────────────────────────────────────────
    if qbt_files is not None:
        orphan_paths = 0
        orphan_inodes = 0
        for info in inodes.values():
            has_orphan = False
            for p in info["paths"]:
                if not _qbt_lookup(p, qbt_files):
                    orphan_paths += 1
                    has_orphan = True
            if has_orphan:
                orphan_inodes += 1

        torrent_paths = total_paths - orphan_paths
        print(f"{'─' * W}")
        print(f"  TORRENT COVERAGE SUMMARY")
        print(f"{'─' * W}")
        print(f"  Paths serving a torrent     : {torrent_paths:>10,}")
        print(f"  Paths with no torrent        : {orphan_paths:>10,}")
        print(f"  Inodes with ≥1 orphan path  : {orphan_inodes:>10,}")

    # ── Stale files summary ─────────────────────────────────────────────────
    if stale_days > 0:
        cutoff_ns = (time.time() - stale_days * 86400) * 1e9
        stale_inodes = 0
        stale_bytes = 0
        for info in inodes.values():
            last_access = info.get("atime_ns", info["mtime_ns"])
            if last_access < cutoff_ns:
                stale_inodes += 1
                stale_bytes += info["size"]
        print(f"\n{'─' * W}")
        print(f"  STALE FILES (not accessed in {stale_days} days)")
        print(f"{'─' * W}")
        print(f"  Stale inodes               : {stale_inodes:>10,}")
        print(f"  Stale disk usage           : {hr(stale_bytes):>10}")
        fresh = len(inodes) - stale_inodes
        print(f"  Recently accessed inodes   : {fresh:>10,}")

    # ── Errors ───────────────────────────────────────────────────────────────
    if errors:
        print(f"\n{'─' * W}")
        print(f"  SKIPPED — {len(errors):,} access error(s)")
        for e in errors[:10]:
            print(f"  ! {e}")
        if len(errors) > 10:
            print(f"  … and {len(errors) - 10} more.")

    print(f"\n{'=' * W}\n")


# ── Deduplication engine ─────────────────────────────────────────────────────

def _consolidate_group(dup_group: dict, dry_run: bool, qbt_files: dict) -> dict:
    """
    Consolidate one duplicate group: keep the first inode, replace all paths
    from other inodes with hardlinks to the kept inode.

    Strategy for each duplicate inode (not the kept one):
        1. Pick the kept inode's first path as the link source.
        2. For every path P belonging to the duplicate inode:
           a. Preserve ownership & permissions of P (for the parent dir).
           b. Delete P.
           c. Create a hardlink:  P → source.
        This means every path that existed before still exists after,
        but they all point to the same inode, freeing the duplicate blocks.

    Returns a result dict with stats.
    """
    copies = dup_group["copies"]  # list of (ino, info)
    keep_ino, keep_info = copies[0]
    source_path = keep_info["paths"][0]

    keep_drive = _drive_key(keep_info)
    result = {
        "kept_inode": keep_ino,
        "source_path": source_path,
        "replaced_paths": [],
        "errors": [],
        "bytes_freed": 0,
        "cross_drive_skipped": [],   # copies on another drive — can't hardlink
    }

    for dup_ino, dup_info in copies[1:]:
        # Cross-drive copies can't be hardlinked to the keeper — os.link would
        # return EXDEV. Skip them here (attempting + rolling back is just noise)
        # and surface them so run_dedup can point the user at the cross-drive
        # report / consolidation instead.
        if _drive_key(dup_info) != keep_drive:
            result["cross_drive_skipped"].append({
                "inode": dup_info.get("ino", dup_ino),
                "drive": _drive_label(dup_info),
                "paths": list(dup_info["paths"]),
            })
            continue
        # Safety backstop: for a genuine hardlink group the number of paths found
        # under the scan root can never exceed the inode's true link count. If it
        # does, the grouping is corrupt (e.g. an inode-number collision that
        # slipped past branch resolution) and consolidating it could unlink a
        # path whose data ISN'T kept alive elsewhere. Skip it.
        _nlink = dup_info.get("nlink", len(dup_info["paths"]))
        if len(dup_info["paths"]) > _nlink:
            result["errors"].append(
                f"inode {dup_info.get('ino', dup_ino)}: {len(dup_info['paths'])} "
                f"paths but st_nlink={_nlink} — refusing to consolidate "
                f"(possible inode collision)")
            continue
        for p in dup_info["paths"]:
            action_desc = f"  rm {p}  &&  ln {source_path} {p}"
            if dry_run:
                result["replaced_paths"].append({"path": p, "action": action_desc, "status": "dry-run"})
                continue

            try:
                # Preserve the original file's stat for verification
                orig_st = os.lstat(p)
                if not stat.S_ISREG(orig_st.st_mode):
                    result["errors"].append(f"{p}: not a regular file, skipping")
                    result["replaced_paths"].append({"path": p, "action": action_desc, "status": "error"})
                    continue

                # Atomic-ish replace: rename old file to .bak, create hardlink,
                # then remove .bak.  If hardlink fails, restore from .bak.
                bak_path = p + ".__dedup_bak__"

                # Step 1: rename original out of the way
                os.rename(p, bak_path)

                # Verify the renamed file is what we expected (TOCTOU guard)
                bak_st = os.lstat(bak_path)
                if bak_st.st_ino != orig_st.st_ino:
                    os.rename(bak_path, p)
                    result["errors"].append(f"{p}: inode changed during operation, skipping")
                    result["replaced_paths"].append({"path": p, "action": action_desc, "status": "error"})
                    continue

                try:
                    # Verify source is still the expected inode
                    src_st = os.lstat(source_path)
                    if src_st.st_ino != keep_ino or not stat.S_ISREG(src_st.st_mode):
                        os.rename(bak_path, p)
                        result["errors"].append(f"{p}: source inode changed, skipping")
                        result["replaced_paths"].append({"path": p, "action": action_desc, "status": "error"})
                        continue
                    # Step 2: create hardlink in its place
                    os.link(source_path, p)
                except OSError as link_err:
                    # Hardlink failed — restore the original
                    os.rename(bak_path, p)
                    result["errors"].append(f"hardlink failed for {p}: {link_err}")
                    result["replaced_paths"].append({"path": p, "action": action_desc, "status": "error"})
                    continue

                # Step 3: remove the backup (the old duplicate data)
                os.unlink(bak_path)
                result["replaced_paths"].append({"path": p, "action": action_desc, "status": "ok"})

            except OSError as exc:
                result["errors"].append(f"{p}: {exc}")
                result["replaced_paths"].append({"path": p, "action": action_desc, "status": "error"})

        # Count space freed: one copy of this inode's blocks
        result["bytes_freed"] += dup_info["size"]

        # Update the in-memory inode data so reports reflect the consolidation:
        # Move successfully replaced paths from the DUP inode to the KEEP inode.
        if not dry_run:
            for p in list(dup_info["paths"]):
                # Check if this path was successfully re-linked
                if any(rp["path"] == p and rp["status"] == "ok"
                       for rp in result["replaced_paths"]):
                    dup_info["paths"].remove(p)
                    if p not in keep_info["paths"]:
                        keep_info["paths"].append(p)

    return result


def _print_dup_group_summary(idx: int, dup: dict, qbt_files: dict):
    """Print a compact summary of one duplicate group for the fix prompt."""
    copies = dup["copies"]
    total_paths = sum(len(info["paths"]) for _, info in copies)
    print(f"\n  Group {idx}: {hr(dup['size'])} x {len(copies)} inodes, "
          f"{total_paths} total paths — recoverable: {hr(dup['wasted'])}")

    for ci, (ino, info) in enumerate(copies):
        marker = "KEEP" if ci == 0 else "DUP "
        n_links = len(info["paths"])
        link_note = f" ({n_links} hardlinks)" if n_links > 1 else ""
        print(f"    [{marker}] inode {ino}{link_note}:")
        for p in info["paths"]:
            sym = _path_torrent_symbol(p, qbt_files)
            t_detail = ""
            if qbt_files is not None:
                torrents = _qbt_lookup(p, qbt_files)
                if torrents:
                    names = ", ".join(t["torrent_name"][:40] for t in torrents)
                    t_detail = f"  ← {names}"
                else:
                    t_detail = "  ← (no torrent)"
            print(f"           [{sym}] {p}{t_detail}")

    print(f"    Action: delete DUP inodes, re-create their paths as hardlinks to KEEP inode")


def run_dedup(dupes: list, interactive: bool, dry_run: bool, qbt_files: dict,
              inodes: dict = None):
    """
    Run the deduplication process.
      interactive=True  → prompt per group (--fix)
      interactive=False → fix all without prompting (--auto-fix)
    """
    if not dupes:
        print(f"\n  No duplicates to fix.")
        return

    # Only groups where at least two copies live on the SAME drive can be
    # hardlink-consolidated here. A group whose copies are each on a different
    # drive has nothing to do in this phase (a hardlink can't cross drives) —
    # "fixing" it would be a no-op — so it's left to the cross-drive report /
    # --consolidate-cross-drive instead of cluttering the prompt.
    actionable = []
    xd_only = 0
    for d in dupes:
        drv = [_drive_key(info) for _ino, info in d["copies"]]
        if len(drv) != len(set(drv)):
            actionable.append(d)
        else:
            xd_only += 1

    if not actionable:
        print(f"\n  No same-drive duplicates to fix"
              + (f" ({xd_only:,} cross-drive-only group(s) → see cross_drive_"
                 f"duplicates.json / --consolidate-cross-drive)." if xd_only else "."))
        return

    total_wasted = sum(d["wasted"] for d in actionable)
    mode_label = "DRY RUN" if dry_run else "LIVE"

    print(f"\n{'=' * W}")
    print(f"  DUPLICATE CONSOLIDATION ({mode_label})")
    print(f"{'=' * W}")
    print(f"  {len(actionable):,} same-drive duplicate group(s), {hr(total_wasted)} recoverable")
    if xd_only:
        print(f"  ({xd_only:,} cross-drive-only group(s) not shown here — reclaim them "
              f"with --consolidate-cross-drive; they're in cross_drive_duplicates.json)")
    if dry_run:
        print(f"  (dry-run mode — no files will be modified)")
    print()

    total_freed = 0
    total_fixed = 0
    total_skipped = 0
    total_errors = 0

    for idx, dup in enumerate(actionable, 1):
        _print_dup_group_summary(idx, dup, qbt_files)

        if interactive and not dry_run:
            while True:
                try:
                    answer = input(f"\n    Fix this group? [y]es / [n]o / [a]ll remaining / [q]uit: ").strip().lower()
                except (EOFError, KeyboardInterrupt):
                    print("\n  Aborted.")
                    return
                if answer in ("y", "yes"):
                    break
                elif answer in ("n", "no"):
                    print(f"    Skipped.")
                    total_skipped += 1
                    break
                elif answer in ("a", "all"):
                    interactive = False  # fix all remaining without asking
                    break
                elif answer in ("q", "quit"):
                    print(f"\n  Stopped. Fixed {total_fixed} group(s), freed {hr(total_freed)}.")
                    return
                else:
                    print(f"    Please enter y, n, a, or q.")
                    continue

            if answer in ("n", "no"):
                continue

        # Perform the consolidation
        result = _consolidate_group(dup, dry_run, qbt_files)

        if dry_run:
            print(f"\n    Would do:")
            for rp in result["replaced_paths"]:
                print(f"     {rp['action']}")
            print(f"    Would free: {hr(dup['wasted'])}")
        else:
            ok_count = sum(1 for rp in result["replaced_paths"] if rp["status"] == "ok")
            err_count = sum(1 for rp in result["replaced_paths"] if rp["status"] == "error")
            if ok_count:
                print(f"\n    ✓ Consolidated {ok_count} path(s) → inode {result['kept_inode']}")
                print(f"      Freed: {hr(result['bytes_freed'])}")
            if err_count:
                print(f"    ⚠ {err_count} error(s):")
                for e in result["errors"]:
                    print(f"      ! {e}")
            total_errors += err_count
        # Cross-drive copies (if any) can't be hardlinked — report, don't attempt.
        if result.get("cross_drive_skipped"):
            for cd in result["cross_drive_skipped"]:
                print(f"    ⇄ cross-drive copy on {cd['drive']} NOT hardlinked "
                      f"(different filesystem): {cd['paths'][0]}")
            print(f"      → see cross_drive_duplicates.json, or "
                  f"--consolidate-cross-drive to remove a redundant copy.")

        total_freed += result["bytes_freed"]
        total_fixed += 1

    # ── Remove fully-emptied inodes from the main dict so reports stay accurate
    if inodes is not None and not dry_run:
        empty_inos = [ino for ino, info in inodes.items()
                      if not info["paths"]]
        for ino in empty_inos:
            del inodes[ino]

    # ── Summary ──────────────────────────────────────────────────────────────
    print(f"\n{'─' * W}")
    print(f"  DEDUP SUMMARY ({mode_label})")
    print(f"{'─' * W}")
    action_word = "Would fix" if dry_run else "Fixed"
    skip_word = "Would skip" if dry_run else "Skipped"
    print(f"  {action_word}   : {total_fixed:,} group(s)")
    if total_skipped:
        print(f"  {skip_word} : {total_skipped:,} group(s)")
    if total_errors:
        print(f"  Errors  : {total_errors:,}")
    freed_word = "Would free" if dry_run else "Freed"
    print(f"  {freed_word}   : {hr(total_freed)}")
    print(f"{'=' * W}\n")


# ── Orphan path cleanup (mixed inodes) ───────────────────────────────────────

def _find_orphan_candidates(inodes: dict, qbt_files: dict, media_dirs: list,
                            active_only: bool) -> list:
    """
    Find paths eligible for orphan cleanup.

    For every *mixed* inode (has both torrent and non-torrent paths), collect
    the non-torrent paths that are OUTSIDE the media_dir.  These are directory
    entries that aren't serving an active torrent and aren't in a media library
    the user has blessed — in other words, clutter.

    Returns a list of dicts:
        [{"inode": int, "info": dict, "orphan_paths": [str, …],
          "kept_paths": [str, …]}, …]

    Safety invariant: we NEVER list a path for removal if it would leave the
    inode with zero paths (link count 0 = data loss).
    """
    if qbt_files is None:
        return []

    results = []

    for ino, info in sorted(inodes.items(), key=lambda x: x[1]["size"],
                            reverse=True):
        # Safety backstop against corrupt hardlink grouping (e.g. an inode
        # collision that slipped past branch resolution): a genuine hardlink
        # group can never have more paths under the scan root than its true
        # st_nlink. If it does, removing an "orphan" path could delete data that
        # is NOT actually kept alive by a sibling path. Never touch such a group.
        _nlink = info.get("nlink", len(info["paths"]))
        if len(info["paths"]) > _nlink:
            continue
        # Only mixed inodes are candidates
        torrent_paths = []
        orphan_paths = []      # no torrent AND outside every media dir
        media_paths = []       # no torrent BUT inside a media dir
        for p in info["paths"]:
            if _qbt_lookup(p, qbt_files, active_only=active_only):
                torrent_paths.append(p)
            elif _path_in_media_dirs(p, media_dirs):
                media_paths.append(p)
            else:
                orphan_paths.append(p)

        # Only proceed if this is a mixed inode with removable orphans
        if not torrent_paths or not orphan_paths:
            continue

        # kept_paths = everything we're NOT offering to delete
        kept_paths = torrent_paths + media_paths

        # Safety: never remove ALL paths — at least one must survive
        if not kept_paths:
            # Edge case: if media_dir is not set, torrent_paths IS the kept set
            # This is already guaranteed by the check above (torrent_paths is non-empty)
            continue

        results.append({
            "inode": ino,
            "info": info,
            "orphan_paths": orphan_paths,
            "kept_paths": kept_paths,
        })

    return results


def run_orphan_cleanup(inodes: dict, qbt_files: dict, media_dirs: list,
                       active_only: bool, interactive: bool = True,
                       dry_run: bool = False):
    """
    Interactively offer to remove orphan hardlink paths from mixed inodes.

    An "orphan" path is one that:
      - Belongs to a mixed inode (at least one path serves an active torrent)
      - Does NOT have an active torrent association
      - Is NOT inside any media dir

    Since these are hardlinks, removing a path only removes the directory entry;
    the actual file data persists via the remaining paths (torrent paths, media
    paths, etc.).
    """
    candidates = _find_orphan_candidates(inodes, qbt_files, media_dirs,
                                         active_only)
    if not candidates:
        print(f"\n  No orphan paths to clean up.\n")
        return

    total_orphan_paths = sum(len(c["orphan_paths"]) for c in candidates)
    mode_label = "DRY RUN" if dry_run else "LIVE"

    print(f"\n{'=' * W}")
    print(f"  ORPHAN PATH CLEANUP ({mode_label})")
    print(f"{'=' * W}")
    print(f"  {len(candidates):,} mixed inode(s) with {total_orphan_paths:,} orphan path(s) outside media dir")
    print(f"  These paths have no active torrent and are not in your media library.")
    print(f"  Since other paths (torrent/media) keep the data alive, removing these")
    print(f"  only deletes the directory entry — no file content is lost.")
    if dry_run:
        print(f"  (dry-run mode — no files will be modified)")
    print()

    total_removed = 0
    total_skipped = 0
    total_errors = 0

    for idx, cand in enumerate(candidates, 1):
        ino = cand["inode"]
        info = cand["info"]
        orphans = cand["orphan_paths"]
        kept = cand["kept_paths"]

        print(f"  Inode {idx}/{len(candidates)}: {hr(info['size'])} — "
              f"{len(info['paths'])} total paths, "
              f"{len(orphans)} orphan(s) to remove")

        # Show kept paths
        for p in kept:
            torrents = _qbt_lookup(p, qbt_files, active_only=active_only)
            if torrents:
                names = ", ".join(t["torrent_name"][:40] for t in torrents)
                print(f"    [T] {p}  ← {names}")
            else:
                print(f"    [M] {p}  ← (media dir)")

        # Show orphan paths (to be removed)
        for p in orphans:
            # Check if there's a paused torrent (show it for context)
            all_torrents = _qbt_lookup(p, qbt_files, active_only=False)
            if all_torrents and not _qbt_lookup(p, qbt_files, active_only=True):
                names = ", ".join(f"{t['torrent_name'][:30]} ({t['torrent_state']})"
                                 for t in all_torrents)
                print(f"    [×] {p}  ← {names} (inactive)")
            else:
                print(f"    [×] {p}  ← (no torrent)")

        if interactive and not dry_run:
            while True:
                try:
                    answer = input(f"\n    Remove {len(orphans)} orphan path(s)? "
                                   f"[y]es / [n]o / [a]ll remaining / [q]uit: ").strip().lower()
                except (EOFError, KeyboardInterrupt):
                    print("\n  Aborted.")
                    return
                if answer in ("y", "yes"):
                    break
                elif answer in ("n", "no"):
                    print(f"    Skipped.")
                    total_skipped += len(orphans)
                    break
                elif answer in ("a", "all"):
                    interactive = False  # auto-approve remaining
                    break
                elif answer in ("q", "quit"):
                    print(f"\n  Stopped. Removed {total_removed} path(s).")
                    return
                else:
                    print(f"    Please enter y, n, a, or q.")
                    continue

            if answer in ("n", "no"):
                print()
                continue

        # Remove orphan paths
        for p in orphans:
            if dry_run:
                print(f"    Would remove: {p}")
                total_removed += 1
                continue
            try:
                os.unlink(p)
                print(f"    ✓ Removed: {p}")
                total_removed += 1
                # Also remove from the inode's path list so reports stay accurate
                if p in info["paths"]:
                    info["paths"].remove(p)
            except OSError as exc:
                print(f"    ⚠ Error removing {p}: {exc}")
                total_errors += 1

        print()

    # ── Summary ──────────────────────────────────────────────────────────────
    print(f"{'─' * W}")
    print(f"  ORPHAN CLEANUP SUMMARY ({mode_label})")
    print(f"{'─' * W}")
    action_word = "Would remove" if dry_run else "Removed"
    print(f"  {action_word} : {total_removed:,} path(s)")
    if total_skipped:
        skip_word = "Would skip" if dry_run else "Skipped"
        print(f"  {skip_word}  : {total_skipped:,} path(s)")
    if total_errors:
        print(f"  Errors   : {total_errors:,}")
    print(f"{'=' * W}\n")


def run_empty_dir_cleanup(mirror_roots, interactive: bool = True,
                          dry_run: bool = False):
    """
    Offer to remove directories that are empty ACROSS ALL mirror roots.

    *mirror_roots* is a list of the per-branch versions of one subtree. On a
    mergerfs union the directory skeleton is mirrored across branches
    (``func.mkdir=epall``), so the SAME relative directory can be empty on one
    branch while it holds files on another — the union is NOT empty, and that
    empty branch copy must stay put so mergerfs' create/action policies keep an
    "existing path" to target. Deleting it per-branch would corrupt the skeleton
    and mis-place future files. So a directory is treated as empty only when it
    is empty on EVERY mirror root (i.e. the union sees it empty), and it is then
    removed from every root together to keep them consistent.

    Pass a single-element list for an ordinary (non-mirrored) directory and this
    behaves like plain empty-dir cleanup. A string is accepted for convenience.

    Processing is deepest-first with a live re-check, so nested empties cascade:
    once a child is removed from all branches, its parent can become empty too.
    """
    if isinstance(mirror_roots, str):
        mirror_roots = [mirror_roots]
    mirror_roots = [os.path.realpath(r) for r in mirror_roots if os.path.isdir(r)]
    if not mirror_roots:
        return
    root_set = set(mirror_roots)
    multi = len(mirror_roots) > 1

    mode_label = "DRY RUN" if dry_run else "LIVE"
    total_subtrees = 0     # maximal empty subtrees removed
    total_dirs = 0         # directories actually removed (summed across branches)
    total_skipped = 0
    total_errors = 0
    header_printed = False

    def _print_header():
        nonlocal header_printed
        if header_printed:
            return
        header_printed = True
        print(f"\n{'=' * W}")
        print(f"  EMPTY FOLDER CLEANUP ({mode_label})")
        print(f"{'=' * W}")
        if multi:
            print(f"  (mirrored across {len(mirror_roots)} drives — a folder is only "
                  f"removed when it's empty on ALL of them)")
        print(f"  A folder whose ENTIRE subtree is empty (no files anywhere) is shown "
              f"once, at its top — approving removes the whole nested tree.")
        if dry_run:
            print(f"  (dry-run mode — no directories will be removed)")
        print()

    # ── Find MAXIMAL empty subtrees ──────────────────────────────────────────
    # A directory's subtree is "empty" when, across ALL branches, it holds no
    # files and no symlinks anywhere beneath it — only (recursively empty) real
    # directories. We then collapse to the TOPMOST such directory, so a deeply
    # nested all-empty tree is ONE prompt for its top rather than one per folder.
    rel_dirs = set()
    nonempty = set()       # rel dirs that (transitively) contain a file/symlink
    def _mark_nonempty(rel):
        while True:
            nonempty.add(rel)
            if rel == ".":
                break
            rel = os.path.dirname(rel) or "."
    for root in mirror_roots:
        for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
            rel = os.path.relpath(dirpath, root)
            if rel != ".":
                rel_dirs.add(rel)
            # "Content" = any file, or any symlink (a symlink-to-dir appears in
            # dirnames but is NOT an empty directory and must not be rmtree'd
            # through). Such a dir — and all its ancestors — are non-empty.
            has_content = bool(filenames) or any(
                os.path.islink(os.path.join(dirpath, dn)) for dn in dirnames)
            if has_content:
                _mark_nonempty(rel)

    def _parent(rel):
        return os.path.dirname(rel) or "."
    # Topmost empty-subtree dirs: empty themselves, with a parent that is a root
    # or that has content (so this dir isn't contained in a larger empty subtree).
    maximal = sorted(rel for rel in rel_dirs
                     if rel not in nonempty
                     and (_parent(rel) == "." or _parent(rel) in nonempty))

    def _copies(rel):
        return [os.path.join(root, rel) for root in mirror_roots
                if os.path.isdir(os.path.join(root, rel))]
    def _union_dir_count(rel):
        pref = rel + os.sep
        return 1 + sum(1 for r in rel_dirs if r.startswith(pref))
    def _safe_to_remove(path):
        # Defensive re-check right before deleting: refuse if any file/symlink
        # turns up under it (nothing with data is ever removed).
        for dp, dns, fns in os.walk(path, followlinks=False):
            if fns or any(os.path.islink(os.path.join(dp, d)) for d in dns):
                return False
        return True

    for rel in maximal:
        copies = _copies(rel)
        if not copies:
            continue
        _print_header()
        idx = total_subtrees + total_skipped + total_errors + 1
        ndirs = _union_dir_count(rel)
        where = f", on {len(copies)} drive(s)" if multi else ""
        nested = (f"  (empty subtree: {ndirs:,} folder{'s' if ndirs != 1 else ''}{where})"
                  if ndirs > 1 else (f"  (on {len(copies)} drive(s))" if multi else ""))
        print(f"  [{idx}]  {rel}/{nested}")

        if interactive and not dry_run:
            while True:
                try:
                    prompt = ("    Remove this empty subtree? " if ndirs > 1
                              else "    Remove empty folder? ")
                    answer = input(prompt + "[y]es / [n]o / [a]ll remaining / [q]uit: ").strip().lower()
                except (EOFError, KeyboardInterrupt):
                    print("\n  Aborted.")
                    return
                if answer in ("y", "yes"):
                    break
                elif answer in ("n", "no"):
                    total_skipped += 1
                    break
                elif answer in ("a", "all"):
                    interactive = False
                    break
                elif answer in ("q", "quit"):
                    print(f"\n  Stopped. Removed {total_subtrees} subtree(s), {total_dirs} folder(s).")
                    return
                else:
                    print(f"    Please enter y, n, a, or q.")
                    continue
            if answer in ("n", "no"):
                continue

        if dry_run:
            print(f"    Would remove: {rel}/" +
                  (f" and everything under it ({ndirs:,} folders)" if ndirs > 1 else ""))
            total_subtrees += 1
            total_dirs += ndirs
            continue

        # Remove the whole subtree from EVERY branch (keeps the skeleton mirrored).
        errs = []
        removed_here = 0
        branch_dirs = 0
        for bp in copies:
            if not _safe_to_remove(bp):
                errs.append(f"{bp}: no longer empty (a file appeared) — skipped")
                continue
            try:
                branch_dirs += sum(1 for _ in os.walk(bp))   # dirs incl bp
                shutil.rmtree(bp)
                removed_here += 1
            except OSError as exc:
                errs.append(f"{bp}: {exc}")
        if removed_here and not errs:
            bits = []
            if ndirs > 1:
                bits.append(f"{ndirs:,} folders")
            if multi:
                bits.append(f"from {removed_here} drive(s)")
            suffix = f"  ({', '.join(bits)})" if bits else ""
            print(f"    ✓ Removed: {rel}/{suffix}")
            total_subtrees += 1
            total_dirs += branch_dirs
        else:
            for e in errs:
                print(f"    ⚠ Error removing {e}")
            total_errors += 1

    if not header_printed:
        print(f"\n  No empty directories found.\n")
        return

    # ── Summary ──────────────────────────────────────────────────────────────
    print(f"\n{'─' * W}")
    print(f"  EMPTY FOLDER CLEANUP SUMMARY ({mode_label})")
    print(f"{'─' * W}")
    action_word = "Would remove" if dry_run else "Removed"
    print(f"  {action_word} : {total_subtrees:,} empty subtree(s) "
          f"({total_dirs:,} folder{'s' if total_dirs != 1 else ''} total)")
    if total_skipped:
        skip_word = "Would skip" if dry_run else "Skipped"
        print(f"  {skip_word}  : {total_skipped:,} subtree(s)")
    if total_errors:
        print(f"  Errors   : {total_errors:,}")
    print(f"{'=' * W}\n")


def run_mergerfs_skeleton_repair(subroots: list, dry_run: bool = False):
    """Mirror the directory skeleton across all branches of a mergerfs union.

    mergerfs' `func.mkdir=epall` is supposed to create every new directory on
    every branch so its create policies always have an "existing path" to target
    (and so a folder is present wherever a file might later be placed). If that
    ever missed a branch — a directory exists under one branch's subtree but not
    another's — file placement can go wrong. This repairs it: every directory
    that exists under any branch's copy of the scanned subtree is created on the
    branches that lack it.

    *subroots* is the per-branch version of the scanned subtree (e.g.
    `/mnt/disk1/Data`, `/mnt/disk2/Data`). Only **directories** are created
    — never files, never deletions. New dirs copy the source dir's mode/owner
    where possible. A path occupied by a file/symlink on some branch is a union
    conflict and is left untouched. Runs AFTER empty-dir cleanup, so directories
    just removed as empty-everywhere are not recreated. Idempotent."""
    subroots = [os.path.normpath(r) for r in subroots]
    if len(subroots) < 2:
        return
    existing = [r for r in subroots if os.path.isdir(r)]
    if not existing:
        return

    mode_label = "DRY RUN" if dry_run else "LIVE"
    # Union of relative directory paths across branches ("." = the subroot itself)
    rel_dirs = {"."}
    for r in existing:
        for dp, dns, fns in os.walk(r, followlinks=False):
            rel_dirs.add(os.path.relpath(dp, r))
    # Shallow-first so a parent is created before its children.
    ordered = sorted(rel_dirs, key=lambda x: (0 if x == "." else x.count(os.sep) + 1, x))

    def _first_existing(rel):
        for r in subroots:
            p = r if rel == "." else os.path.join(r, rel)
            if os.path.isdir(p):
                return p
        return None

    total_created = 0
    total_conflicts = 0
    header_printed = False

    def _hdr():
        nonlocal header_printed
        if header_printed:
            return
        header_printed = True
        print(f"\n{'=' * W}")
        print(f"  MERGERFS SKELETON REPAIR ({mode_label})")
        print(f"{'=' * W}")
        print(f"  Ensuring every directory exists on all {len(subroots)} branches "
              f"(repairing any func.mkdir=epall gaps).")
        if dry_run:
            print(f"  (dry-run mode — no directories will be created)")
        print()

    for rel in ordered:
        src = _first_existing(rel)
        if src is None:
            continue
        for r in subroots:
            target = r if rel == "." else os.path.join(r, rel)
            if os.path.isdir(target):
                continue
            if os.path.lexists(target):
                _hdr()
                print(f"    ⚠ Conflict (a non-directory exists here): {target}")
                total_conflicts += 1
                continue
            _hdr()
            if dry_run:
                print(f"    Would create: {target}/")
                total_created += 1
                continue
            try:
                os.makedirs(target, exist_ok=True)
                try:
                    shutil.copystat(src, target)      # mode + times
                except OSError:
                    pass
                try:
                    st = os.stat(src)
                    os.chown(target, st.st_uid, st.st_gid)   # best-effort (may need root)
                except (OSError, AttributeError):
                    pass
                print(f"    ✓ Created: {target}/")
                total_created += 1
            except OSError as exc:
                print(f"    ⚠ Error creating {target}: {exc}")
                total_conflicts += 1

    if not header_printed:
        print(f"\n  mergerfs skeleton already consistent across branches.\n")
        return

    print(f"\n{'─' * W}")
    print(f"  SKELETON REPAIR SUMMARY ({mode_label})")
    print(f"{'─' * W}")
    action = "Would create" if dry_run else "Created"
    print(f"  {action} : {total_created:,} director{'y' if total_created == 1 else 'ies'}")
    if total_conflicts:
        print(f"  Conflicts/errors : {total_conflicts:,}")
    print(f"{'=' * W}\n")


def run_cross_seed_links(root: str, inodes: dict, qbt_files: dict,
                         media_dirs: list = None, active_only: bool = False,
                         dry_run: bool = False,
                         keep_unseeded_media: bool = True):
    """
    Create hardlinks in ROOT/cross-seed-dir/ for every path belonging to
    inodes classified as "unused" (no active torrent on any path).

    The relative directory structure is preserved inside cross-seed-dir/ so
    that torrent content keeps its expected layout:
        /root/torrents/complete/SomeMovie/file.mkv
        → /root/cross-seed-dir/torrents/complete/SomeMovie/file.mkv

    Only hardlinks are created — no file data is copied.
    """
    cross_dir = os.path.join(root, "cross-seed-dir")
    mode_label = "DRY RUN" if dry_run else "LIVE"

    # Identify unused inodes
    unused_paths: list[str] = []
    for ino, info in inodes.items():
        if not info["paths"]:
            continue
        cat = _classify_inode(info, qbt_files, media_dirs, active_only,
                              keep_unseeded_media=keep_unseeded_media)
        if cat == "unused":
            for p in info["paths"]:
                unused_paths.append(p)

    if not unused_paths:
        print(f"\n  No unused files to cross-seed.\n")
        return

    print(f"\n{'=' * W}")
    print(f"  CROSS-SEED HARDLINKS ({mode_label})")
    print(f"{'=' * W}")
    print(f"  {len(unused_paths):,} unused file(s) → {cross_dir}/")
    if dry_run:
        print(f"  (dry-run mode — no hardlinks will be created)")
    print()

    total_linked = 0
    total_skipped = 0
    total_errors = 0

    for p in sorted(unused_paths):
        # Compute relative path from root so we preserve directory structure
        rel = os.path.relpath(p, root)
        dest = os.path.join(cross_dir, rel)

        if dry_run:
            print(f"    Would link: {rel}")
            total_linked += 1
            continue

        # Create parent directories as needed
        dest_dir = os.path.dirname(dest)
        try:
            os.makedirs(dest_dir, exist_ok=True)
        except OSError as exc:
            print(f"    ⚠ Cannot create dir {dest_dir}: {exc}")
            total_errors += 1
            continue

        if os.path.exists(dest):
            # Already linked (e.g. re-run)
            try:
                if os.lstat(dest).st_ino == os.lstat(p).st_ino:
                    total_skipped += 1
                    continue
            except OSError:
                pass
            # Different file at that path — skip to avoid data loss
            print(f"    ⚠ Destination already exists (different file): {rel}")
            total_skipped += 1
            continue

        try:
            os.link(p, dest)
            total_linked += 1
        except OSError as exc:
            print(f"    ⚠ Error linking {rel}: {exc}")
            total_errors += 1

    # ── Summary ──────────────────────────────────────────────────────────────
    print(f"{'─' * W}")
    print(f"  CROSS-SEED SUMMARY ({mode_label})")
    print(f"{'─' * W}")
    action_word = "Would link" if dry_run else "Linked"
    print(f"  {action_word}  : {total_linked:,} file(s)")
    if total_skipped:
        skip_word = "Would skip" if dry_run else "Skipped"
        print(f"  {skip_word} : {total_skipped:,} (already linked or conflict)")
    if total_errors:
        print(f"  Errors  : {total_errors:,}")
    if not dry_run and total_linked:
        print(f"  Output  : {cross_dir}/")
    print(f"{'=' * W}\n")


# ── Cross-drive duplicates (same content on different drives) ────────────────

def _cross_drive_groups(dupes: list) -> list:
    """Return only the duplicate groups whose copies span more than one drive."""
    return [d for d in dupes if d.get("cross_drive")]


def _copy_status_tag(info: dict, qbt_files: dict, media_dirs: list,
                     active_only: bool) -> str:
    """Short tag describing whether a copy is seeded / in a media dir / loose."""
    seeded = any(_qbt_lookup(p, qbt_files, active_only=active_only)
                 for p in info["paths"]) if qbt_files is not None else False
    in_media = any(_path_in_media_dirs(p, media_dirs) for p in info["paths"])
    bits = []
    if seeded:
        bits.append("seeding")
    if in_media:
        bits.append("in media dir")
    return ", ".join(bits) if bits else "loose copy"


def write_cross_drive_report(root: str, dupes: list, qbt_files: dict,
                             out_dir: str = None):
    """Write cross_drive_duplicates.json + print a summary. These are identical
    files living on more than one drive/branch — they can't be hardlinked
    together (EXDEV), so the way to reclaim the space is to delete a redundant
    copy (see --consolidate-cross-drive).

    *out_dir* is where the JSON is written (defaults to *root*; callers pass the
    script's own directory)."""
    groups = _cross_drive_groups(dupes)
    out_path = os.path.join(out_dir or root, "cross_drive_duplicates.json")

    export = []
    total_reclaimable = 0
    for d in groups:
        copies = [(ino, info) for ino, info in d["copies"] if info["paths"]]
        if len(copies) < 2:
            continue
        reclaimable = d["size"] * (len(copies) - 1)
        total_reclaimable += reclaimable
        copy_entries = []
        for ino, info in copies:
            entry = _build_inode_entry(info["ino"], info, qbt_files)
            entry["drive"] = _drive_label(info)
            copy_entries.append(entry)
        export.append({
            "size_bytes": d["size"],
            "size_human": hr(d["size"]),
            "reclaimable_bytes": reclaimable,
            "reclaimable_human": hr(reclaimable),
            "drives": sorted({_drive_label(info) for _ino, info in copies}),
            "copies": copy_entries,
        })

    _write_json_file(out_path, {
        "description": "Identical files present on more than one drive/branch. "
                       "Cannot be hardlinked across drives (EXDEV); reclaim by "
                       "deleting a redundant copy (--consolidate-cross-drive).",
        "cross_drive_groups": len(export),
        "total_reclaimable_bytes": total_reclaimable,
        "total_reclaimable_human": hr(total_reclaimable),
        "groups": export,
    })

    print(f"\n{'─' * W}")
    print(f"  CROSS-DRIVE DUPLICATES  (same file on >1 drive — can't hardlink)")
    print(f"{'─' * W}")
    if not export:
        print(f"  None found.")
        print(f"  Wrote {out_path}  (0 groups)")
        return
    print(f"  ⇄  {len(export):,} group(s) span multiple drives")
    print(f"  ⇄  Reclaimable by removing redundant copies: {hr(total_reclaimable)}")
    print(f"     (hardlink consolidation can't cross drives — use "
          f"--consolidate-cross-drive to delete a redundant copy)")
    for g in export[:20]:
        print(f"\n    {g['size_human']}  across {', '.join(g['drives'])}  "
              f"(reclaim {g['reclaimable_human']}):")
        for c in g["copies"]:
            first = c["paths"][0]["path"] if c["paths"] else "?"
            print(f"      @ {c['drive']}: {first}")
    if len(export) > 20:
        print(f"\n    … and {len(export) - 20:,} more. Full list in {os.path.basename(out_path)}.")
    print(f"\n  Wrote {out_path}  ({len(export):,} groups, {hr(total_reclaimable)} reclaimable)")


def _migrate_copy_onto_branch(loser_info: dict, keep_info: dict,
                              dry_run: bool) -> dict:
    """Migrate one cross-drive duplicate (`loser_info`) onto the keeper's branch,
    preserving every union path.

    For each path the loser holds on its own branch, recreate it at the SAME
    relative path on the keeper's branch as a hardlink to the keeper inode, then
    remove the loser's copy. Because qBittorrent/Plex/etc. see the mergerfs union
    (not the branches), the union path is unchanged — only the physical disk
    backing it changes — and the loser's redundant copy of the data is freed.

    Order is link-then-unlink so the path is served at all times. Never clobbers a
    different file already at the target. Requires both inodes to know their
    branch; returns {"ok","skipped","errors","freed","actions"}."""
    res = {"ok": 0, "skipped": 0, "errors": [], "freed": 0, "actions": []}
    kbranch = keep_info.get("branch")
    lbranch = loser_info.get("branch")
    ksrc = keep_info["paths"][0]
    if not kbranch or not lbranch:
        res["errors"].append("branch unknown for keeper or copy — cannot migrate "
                             "safely (need a mergerfs branch); left untouched")
        return res

    migrated_all = True
    for p in list(loser_info["paths"]):
        rel = os.path.relpath(p, lbranch)
        target = os.path.join(kbranch, rel)
        res["actions"].append(f"ln {target}  (→ keeper)  &&  rm {p}")
        if dry_run:
            res["ok"] += 1
            continue
        try:
            k_id = (os.lstat(ksrc).st_dev, os.lstat(ksrc).st_ino)
            if os.path.lexists(target):
                try:
                    t_id = (os.lstat(target).st_dev, os.lstat(target).st_ino)
                except OSError:
                    t_id = None
                if t_id == k_id:
                    # Already the keeper inode at this path → just drop the copy.
                    os.unlink(p)
                    if p in loser_info["paths"]:
                        loser_info["paths"].remove(p)
                    res["ok"] += 1
                    continue
                # Different file already there — do NOT clobber.
                res["errors"].append(f"{target}: a different file already exists "
                                     f"here — left {p} untouched")
                res["skipped"] += 1
                migrated_all = False
                continue
            # Create the parent dir on the keeper branch if needed, then link.
            os.makedirs(os.path.dirname(target), exist_ok=True)
            os.link(ksrc, target)
            if (os.lstat(target).st_dev, os.lstat(target).st_ino) != k_id:
                res["errors"].append(f"{target}: hardlink did not point at the "
                                     f"keeper inode — left {p} untouched")
                res["skipped"] += 1
                migrated_all = False
                continue
            os.unlink(p)                      # remove the redundant copy
            if p in loser_info["paths"]:
                loser_info["paths"].remove(p)
            if target not in keep_info["paths"]:
                keep_info["paths"].append(target)
            res["ok"] += 1
        except OSError as exc:
            res["errors"].append(f"{p} → {target}: {exc}")
            migrated_all = False
    if migrated_all and res["ok"]:
        res["freed"] = loser_info["size"]     # one physical copy reclaimed
    return res


def run_cross_drive_consolidate(dupes: list, qbt_files: dict, active_only: bool,
                                media_dirs: list, dry_run: bool = False):
    """Interactively consolidate cross-drive duplicates by MIGRATING the redundant
    copies onto the keeper's branch — recreating each at the same relative path as
    a hardlink to the keeper inode, then removing the source. On a mergerfs union
    this keeps every union path exactly where it was (qBittorrent/Plex see no
    change) while reclaiming the redundant physical copy. Always prompts per group
    (no --auto). Respects dry_run.

    A keeper is suggested that keeps the most-established copy: seeded first, then
    in a media dir, then the one with the most hardlinks. When branch info is
    missing (not a mergerfs scan) migration isn't possible, so those fall back to
    deleting the redundant copy (which does drop that union path)."""
    groups = _cross_drive_groups(dupes)
    groups = [d for d in groups
              if len([1 for _ino, info in d["copies"] if info["paths"]]) >= 2]
    if not groups:
        print(f"\n  No cross-drive duplicates to consolidate.\n")
        return

    mode_label = "DRY RUN" if dry_run else "LIVE"
    print(f"\n{'=' * W}")
    print(f"  CROSS-DRIVE CONSOLIDATION ({mode_label})")
    print(f"{'=' * W}")
    print(f"  For each group you pick the copy to KEEP. Every other copy is")
    print(f"  re-created as a hardlink to the kept inode at the SAME relative path")
    print(f"  on the kept copy's drive, then the original is removed. On mergerfs")
    print(f"  the union path is unchanged — only the disk backing it — and the")
    print(f"  redundant copy's space is reclaimed. (No hardlink is ever created")
    print(f"  across drives; that's impossible. Nothing is touched until you pick.)")
    if dry_run:
        print(f"  (dry-run mode — no files will be changed)")
    print()

    total_migrated = 0
    total_freed = 0
    total_skipped = 0
    total_errors = 0

    for idx, d in enumerate(groups, 1):
        copies = [(ino, info) for ino, info in d["copies"] if info["paths"]]
        # Suggested keeper: seeded > in-media > most hardlinks.
        def _score(item):
            _ino, info = item
            seeded = any(_qbt_lookup(p, qbt_files, active_only=active_only)
                         for p in info["paths"]) if qbt_files is not None else False
            in_media = any(_path_in_media_dirs(p, media_dirs) for p in info["paths"])
            return (1 if seeded else 0, 1 if in_media else 0,
                    info.get("nlink", len(info["paths"])), len(info["paths"]))
        suggested = max(range(len(copies)), key=lambda i: _score(copies[i]))

        print(f"  Group {idx}/{len(groups)}: {hr(d['size'])} — {len(copies)} copies "
              f"on {len({_drive_label(info) for _ino, info in copies})} drives "
              f"(reclaim {hr(d['size'] * (len(copies) - 1))})")
        for ci, (ino, info) in enumerate(copies):
            tag = _copy_status_tag(info, qbt_files, media_dirs, active_only)
            star = " ← suggested keep" if ci == suggested else ""
            nlink = info.get("nlink", len(info["paths"]))
            print(f"    [{ci + 1}] @ {_drive_label(info)}  ({tag}; {nlink} hardlink"
                  f"{'s' if nlink != 1 else ''}){star}")
            for p in info["paths"]:
                print(f"          {p}")

        try:
            ans = input(f"\n    Keep which copy? [1-{len(copies)}] "
                        f"(default {suggested + 1}) / [s]kip / [q]uit: ").strip().lower()
        except (EOFError, KeyboardInterrupt):
            print("\n  Aborted.")
            return
        if ans in ("q", "quit"):
            print(f"\n  Stopped. Migrated {total_migrated} copy(ies), freed {hr(total_freed)}.")
            return
        if ans in ("s", "skip"):
            print(f"    Skipped.\n")
            total_skipped += 1
            continue
        if ans == "":
            keep_idx = suggested
        else:
            try:
                keep_idx = int(ans) - 1
            except ValueError:
                print(f"    Unrecognised input — skipping this group.\n")
                total_skipped += 1
                continue
            if not (0 <= keep_idx < len(copies)):
                print(f"    Out of range — skipping this group.\n")
                total_skipped += 1
                continue

        keep_ino, keep_info = copies[keep_idx]
        print(f"    Keeping [{keep_idx + 1}] @ {_drive_label(keep_info)} "
              f"→ migrating the other copy(ies) onto that drive")
        for ci, (ino, info) in enumerate(copies):
            if ci == keep_idx:
                continue
            r = _migrate_copy_onto_branch(info, keep_info, dry_run)
            for a in r["actions"]:
                print(f"    {'Would: ' if dry_run else ''}{a}")
            if not dry_run:
                if r["ok"]:
                    print(f"    ✓ Migrated {r['ok']} path(s) from "
                          f"{_drive_label(info)} onto {_drive_label(keep_info)}")
                for e in r["errors"]:
                    print(f"    ⚠ {e}")
            total_migrated += r["ok"]
            total_freed += r["freed"]
            total_errors += len(r["errors"])
        print()

    print(f"{'─' * W}")
    print(f"  CROSS-DRIVE CONSOLIDATION SUMMARY ({mode_label})")
    print(f"{'─' * W}")
    action = "Would migrate" if dry_run else "Migrated"
    freed = "Would free" if dry_run else "Freed"
    print(f"  {action} : {total_migrated:,} copy path(s)")
    if total_skipped:
        print(f"  Skipped  : {total_skipped:,} group(s)")
    if total_errors:
        print(f"  Errors   : {total_errors:,}")
    print(f"  {freed}   : {hr(total_freed)}")
    print(f"{'=' * W}\n")


# ── JSON export (4 files) ────────────────────────────────────────────────────

def _build_inode_entry(ino: int, info: dict, qbt_files: dict,
                      stale_cutoff_ns: int = 0) -> dict:
    """Build one inode JSON entry with per-path torrent detail."""
    paths_detail = []
    for p in info["paths"]:
        pd = {"path": p}
        if qbt_files is not None:
            torrents = _qbt_lookup(p, qbt_files)
            # Enrich each association with an "active" flag
            enriched = []
            for t in (torrents or []):
                t_copy = dict(t)
                t_copy["active"] = t.get("torrent_state", "") in ACTIVE_TORRENT_STATES
                enriched.append(t_copy)
            pd["torrents"] = enriched
            pd["has_torrent"] = bool(enriched)
            pd["has_active_torrent"] = any(t["active"] for t in enriched)
        else:
            pd["torrents"] = None
            pd["has_torrent"] = None
            pd["has_active_torrent"] = None
        paths_detail.append(pd)

    mtime_s = info["mtime_ns"] / 1e9
    atime_s = info.get("atime_ns", info["mtime_ns"]) / 1e9
    last_access_ns = info.get("atime_ns", info["mtime_ns"])

    content_type = classify_media_type(info["paths"][0]) if info["paths"] else "other"

    entry = {
        "inode": ino,
        "size_bytes": info["size"],
        "size_human": hr(info["size"]),
        "content_type": content_type,
        # link_count = paths found under the scanned root.
        # fs_link_count = the inode's real st_nlink (all links on the device,
        # including any outside the scan). When fs_link_count == 1 the file has
        # no other hardlinks anywhere; this is what lets a non-seeded media-dir
        # file be classified "used" (see _classify_inode case 2).
        "link_count": len(info["paths"]),
        "fs_link_count": info.get("nlink", len(info["paths"])),
        # Which physical drive/branch this inode lives on (for the HTML report's
        # drive column + filter, and cross-drive views). Branch path on a union,
        # else "dev:<n>".
        "drive": _drive_label(info),
        "mtime": time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(mtime_s)),
        "atime": time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(atime_s)),
        "mtime_epoch": mtime_s,
        "atime_epoch": atime_s,
        "paths": paths_detail,
    }
    if stale_cutoff_ns > 0:
        entry["stale"] = last_access_ns < stale_cutoff_ns
    return entry


def _path_in_media_dirs(path: str, media_dirs: list) -> bool:
    """True if *path* resolves to a location inside ANY of *media_dirs* (or is
    one of them).

    *path* is resolved with realpath so symlinks are followed; each media dir is
    already realpath-normalised in parse_args(), so this compares real path to
    real path. Accepts a list so a mergerfs library that spans branches (a media
    path on each branch) can be covered when scanning a single branch.
    """
    if not media_dirs:
        return False
    rp = os.path.realpath(path)
    for md in media_dirs:
        if rp == md or rp.startswith(md + os.sep):
            return True
    return False


def _classify_inode(info: dict, qbt_files: dict, media_dirs: list = None,
                    active_only: bool = False,
                    keep_unseeded_media: bool = True) -> str:
    """
    Classify an inode based on torrent coverage of its paths.
    Returns: "used" | "unused" | "mixed" | "no_qbt"

    If *active_only* is True, only torrents in an active state (seeding,
    downloading, etc.) count — paused or errored torrents are ignored.

    Media-dir reclassification (only when *media_dir* is set). Two cases promote
    an inode to "used":

      1. Mixed inode (at least one torrent path + some non-torrent paths): if
         EVERY non-torrent path lives inside *media_dir*, the inode is "used".
         The torrent path seeds it and the media path serves it to Plex/Jellyfin,
         so the media-dir entries aren't orphans.

      2. Standalone media file (NO torrent on any path) whose only filesystem
         link is inside *media_dir*: i.e. info["nlink"] == 1 and every path is in
         *media_dir*. This is genuine user-owned content (a personal rip, a
         manually-added file, …) that simply isn't being seeded. It has no other
         hardlinks anywhere, so it isn't torrent leftovers — treat it as "used"
         so it isn't reported as unused or swept up by cross-seed/cleanup.
         Controlled by *keep_unseeded_media* (default True); pass False
         (CLI: --no-keep-unseeded-media) to leave these as "unused". Case 1 is
         NOT affected by this flag.

    A fully-unused inode with nlink > 1 (hardlinked somewhere else) is NOT
    promoted by case 2 — it still has "other hardlinks" and stays "unused".
    """
    if qbt_files is None:
        return "no_qbt"

    has_torrent = 0
    no_torrent_paths = []
    for p in info["paths"]:
        if _qbt_lookup(p, qbt_files, active_only=active_only):
            has_torrent += 1
        else:
            no_torrent_paths.append(p)

    if has_torrent > 0 and no_torrent_paths:
        # Mixed inode — case 1: reclassify to "used" if every non-torrent path
        # is inside a media dir.
        if media_dirs and all(_path_in_media_dirs(p, media_dirs)
                             for p in no_torrent_paths):
            return "used"
        return "mixed"
    elif has_torrent > 0:
        return "used"
    else:
        # Fully unused (no qualifying torrent on any path).
        # Case 2 (opt-out via keep_unseeded_media=False): a standalone file (no
        # other hardlinks: nlink == 1) living only inside a media dir is real
        # content, not torrent cruft → "used".
        nlink = info.get("nlink", len(info["paths"]))
        if (keep_unseeded_media and media_dirs and nlink == 1 and no_torrent_paths
                and all(_path_in_media_dirs(p, media_dirs)
                        for p in no_torrent_paths)):
            return "used"
        return "unused"


def _write_json_file(filepath: str, data: dict):
    """Write a JSON file with consistent formatting."""
    with open(filepath, "w") as f:
        json.dump(data, f, indent=2)


def write_reports(root: str, inodes: dict, dupes: list,
                  errors: list, qbt_files: dict, media_dirs: list = None,
                  active_only: bool = False, stale_days: int = 0,
                  keep_unseeded_media: bool = True, out_dir: str = None):
    """
    Write 4 JSON report files:
      - used_inodes.json     (all paths serve a torrent)
      - unused_inodes.json   (no paths serve a torrent)
      - mixed_inodes.json    (some paths have torrents, some don't)
      - duplicate_files.json (true duplicates across inodes)

    *root* is the scanned root recorded inside the files (the "root" field);
    *out_dir* is where the files are physically written (defaults to *root* for
    backward compatibility, but callers pass the script's own directory).

    When qBittorrent is not connected, all inodes go into used_inodes.json
    (since we can't classify), and the other two inode files are empty.
    """
    out_dir = out_dir or root
    all_sorted = sorted(inodes.items(), key=lambda x: x[1]["size"], reverse=True)
    stale_cutoff_ns = int((time.time() - stale_days * 86400) * 1e9) if stale_days > 0 else 0

    used_list = []
    unused_list = []
    mixed_list = []

    for _identity, info in all_sorted:
        entry = _build_inode_entry(info["ino"], info, qbt_files, stale_cutoff_ns)
        cat = _classify_inode(info, qbt_files, media_dirs, active_only,
                              keep_unseeded_media=keep_unseeded_media)
        if cat == "used":
            used_list.append(entry)
        elif cat == "unused":
            unused_list.append(entry)
        elif cat == "mixed":
            mixed_list.append(entry)
        else:
            # no qBittorrent — put everything in used (unclassified)
            used_list.append(entry)

    # Summary stats shared across files
    total_real = sum(i["size"] for i in inodes.values())
    total_apparent = sum(i["size"] * len(i["paths"]) for i in inodes.values())
    total_paths = sum(len(i["paths"]) for i in inodes.values())

    summary = {
        "root": root,
        "generated_at": time.strftime("%Y-%m-%d %H:%M:%S"),
        "qbittorrent_connected": qbt_files is not None,
        "total_unique_inodes": len(inodes),
        "total_paths": total_paths,
        "real_bytes": total_real,
        "real_human": hr(total_real),
        "apparent_bytes": total_apparent,
        "apparent_human": hr(total_apparent),
    }

    # ── 1. used_inodes.json ──────────────────────────────────────────────────
    used_path = os.path.join(out_dir, "used_inodes.json")
    used_size = sum(e["size_bytes"] for e in used_list)
    _write_json_file(used_path, {
        **summary,
        "description": "Inodes where ALL paths are associated with a torrent"
                       if qbt_files else "All inodes (qBittorrent not connected)",
        "count": len(used_list),
        "total_size_bytes": used_size,
        "total_size_human": hr(used_size),
        "inodes": used_list,
    })
    print(f"  Wrote {used_path}  ({len(used_list):,} inodes, {hr(used_size)})")

    # ── 2. unused_inodes.json ────────────────────────────────────────────────
    unused_path = os.path.join(out_dir, "unused_inodes.json")
    unused_size = sum(e["size_bytes"] for e in unused_list)
    _write_json_file(unused_path, {
        **summary,
        "description": "Inodes where NO paths are associated with a torrent",
        "count": len(unused_list),
        "total_size_bytes": unused_size,
        "total_size_human": hr(unused_size),
        "inodes": unused_list,
    })
    print(f"  Wrote {unused_path}  ({len(unused_list):,} inodes, {hr(unused_size)})")

    # ── 3. mixed_inodes.json ─────────────────────────────────────────────────
    mixed_path = os.path.join(out_dir, "mixed_inodes.json")
    mixed_size = sum(e["size_bytes"] for e in mixed_list)
    _write_json_file(mixed_path, {
        **summary,
        "description": "Inodes where SOME paths have torrents and some don't",
        "count": len(mixed_list),
        "total_size_bytes": mixed_size,
        "total_size_human": hr(mixed_size),
        "inodes": mixed_list,
    })
    print(f"  Wrote {mixed_path}  ({len(mixed_list):,} inodes, {hr(mixed_size)})")

    # ── 4. duplicate_files.json ──────────────────────────────────────────────
    dup_export = []
    for d in dupes:
        copies_export = []
        for ino, info in d["copies"]:
            if not info["paths"]:
                continue  # inode fully consolidated away
            copies_export.append(_build_inode_entry(ino, info, qbt_files, stale_cutoff_ns))
        dup_export.append({
            "size_bytes": d["size"],
            "size_human": hr(d["size"]),
            "wasted_bytes": d["wasted"],
            "wasted_human": hr(d["wasted"]),
            "cross_drive": d.get("cross_drive", False),
            "inodes": copies_export,
        })

    dup_path = os.path.join(out_dir, "duplicate_files.json")
    total_wasted = sum(d["wasted"] for d in dupes)
    _write_json_file(dup_path, {
        **summary,
        "description": "True duplicates: same content across different inodes (wasted space)",
        "duplicate_groups": len(dup_export),
        "total_wasted_bytes": total_wasted,
        "total_wasted_human": hr(total_wasted),
        "duplicates": dup_export,
    })
    print(f"  Wrote {dup_path}  ({len(dup_export):,} groups, {hr(total_wasted)} wasted)")


# ── HTML report ──────────────────────────────────────────────────────────────

def write_html_report(root: str, inodes: dict, dupes: list,
                      qbt_files: dict, media_dirs: list = None,
                      active_only: bool = False, stale_days: int = 0,
                      keep_unseeded_media: bool = True, out_dir: str = None):
    """Generate a self-contained HTML report with embedded JSON data.

    The report uses five separate ``<script type="application/json">`` tags
    (meta, used, unused, mixed, duplicates) consumed by a JS viewer app at
    load time.  This keeps the file fully self-contained while cleanly
    separating data from presentation.

    *root* is the scanned root shown in the report header/meta; *out_dir* is
    where ``diskreport.html`` is written (defaults to *root*; callers pass the
    script's own directory).
    """
    out_dir = out_dir or root

    stale_cutoff_ns = int((time.time() - stale_days * 86400) * 1e9) if stale_days > 0 else 0

    # Classify all inodes
    categories = {"used": [], "unused": [], "mixed": []}
    for _identity, info in sorted(inodes.items(), key=lambda x: x[1]["size"], reverse=True):
        if not info["paths"]:
            continue
        entry = _build_inode_entry(info["ino"], info, qbt_files, stale_cutoff_ns)
        cat = _classify_inode(info, qbt_files, media_dirs, active_only,
                              keep_unseeded_media=keep_unseeded_media)
        if cat in categories:
            categories[cat].append(entry)
        else:
            categories["used"].append(entry)

    # Media type stats
    type_stats = defaultdict(lambda: {"count": 0, "bytes": 0})
    for info in inodes.values():
        if not info["paths"]:
            continue
        mt = classify_media_type(info["paths"][0])
        type_stats[mt]["count"] += 1
        type_stats[mt]["bytes"] += info["size"]

    total_real = sum(i["size"] for i in inodes.values())
    total_paths = sum(len(i["paths"]) for i in inodes.values())

    # Build duplicate entries
    dup_entries = []
    for d in dupes:
        copies_list = []
        for ino, info in d["copies"]:
            if not info["paths"]:
                continue
            copies_list.append(_build_inode_entry(ino, info, qbt_files, stale_cutoff_ns))
        if not copies_list:
            continue
        dup_entries.append({
            "size_bytes": d["size"],
            "size_human": hr(d["size"]),
            "wasted_bytes": d["wasted"],
            "wasted_human": hr(d["wasted"]),
            "cross_drive": d.get("cross_drive", False),
            "copies": copies_list,
        })

    generated = time.strftime("%Y-%m-%d %H:%M:%S")

    # ── Build the five JSON blobs ──
    meta_json = json.dumps({
        "root": root,
        "generated": generated,
        "total_inodes": len(inodes),
        "total_paths": total_paths,
        "total_real_bytes": total_real,
        "total_real_human": hr(total_real),
        "qbt_connected": qbt_files is not None,
        "active_only": active_only,
        "stale_days": stale_days,
        "media_types": {mt: {"count": s["count"], "bytes": s["bytes"],
                             "human": hr(s["bytes"])}
                        for mt, s in sorted(type_stats.items(),
                                            key=lambda x: x[1]["bytes"], reverse=True)},
    }, default=str)

    def _safe_json(obj):
        # Escape the three characters that could let embedded data break out of
        # the <script> tag it's injected into (e.g. a path containing
        # "</script>"). These remain valid JSON \u escapes.
        return (json.dumps(obj, default=str)
                .replace("<", "\\u003c").replace(">", "\\u003e")
                .replace("&", "\\u0026"))

    meta_json = _safe_json(json.loads(meta_json))  # re-encode meta safely
    used_json = _safe_json(categories["used"])
    unused_json = _safe_json(categories["unused"])
    mixed_json = _safe_json(categories["mixed"])
    duplicates_json = _safe_json(dup_entries)

    html_content = _HTML_TEMPLATE
    html_content = html_content.replace("__DATA_META__", meta_json)
    html_content = html_content.replace("__DATA_USED__", used_json)
    html_content = html_content.replace("__DATA_UNUSED__", unused_json)
    html_content = html_content.replace("__DATA_MIXED__", mixed_json)
    html_content = html_content.replace("__DATA_DUPLICATES__", duplicates_json)

    html_path = os.path.join(out_dir, "diskreport.html")
    with open(html_path, "w", encoding="utf-8") as f:
        f.write(html_content)
    print(f"  Wrote {html_path}")


_HTML_TEMPLATE = r"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Disk Report</title>
<style>
:root {
  --bg: #0b0f14; --card: #161b22; --card-hover: #1e242d; --border: #30363d;
  --border-soft: #22282f;
  --text: #e6edf3; --dim: #8b949e; --accent: #58a6ff; --green: #3fb950;
  --red: #f85149; --orange: #d29922; --purple: #bc8cff; --cyan: #39d2c0;
  --accent-soft: rgba(88,166,255,0.14);
  --radius: 10px; --radius-sm: 6px;
  --shadow-sm: 0 1px 2px rgba(0,0,0,0.35);
  --shadow: 0 4px 16px rgba(0,0,0,0.38);
  --shadow-lg: 0 12px 34px rgba(0,0,0,0.5);
  --focus-ring: 0 0 0 3px rgba(88,166,255,0.28);
}
* { box-sizing: border-box; margin: 0; padding: 0; }
body {
  font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Helvetica, Arial, sans-serif;
  background:
    radial-gradient(900px 520px at 100% -10%, rgba(88,166,255,0.06), transparent 60%),
    radial-gradient(760px 440px at -5% 0%, rgba(188,140,255,0.05), transparent 55%),
    var(--bg);
  background-attachment: fixed;
  color: var(--text); line-height: 1.5; padding: 26px 22px 40px;
  max-width: 1680px; margin: 0 auto;
  -webkit-font-smoothing: antialiased; -moz-osx-font-smoothing: grayscale;
  text-rendering: optimizeLegibility;
}
h1 {
  font-size: 1.6em; font-weight: 700; letter-spacing: -0.02em; margin-bottom: 4px;
  display: flex; align-items: center; gap: 11px;
}
h1::before {
  content: ""; width: 6px; height: 1.05em; border-radius: 3px; flex: none;
  background: linear-gradient(180deg, var(--accent), var(--purple));
  box-shadow: 0 0 14px rgba(88,166,255,0.5);
}
.subtitle { color: var(--dim); margin-bottom: 16px; font-size: 0.9em; word-break: break-all; }
a { color: var(--accent); text-decoration: none; }
a:hover { text-decoration: underline; }

/* ── Global bar ── */
.globalbar {
  display: flex; flex-wrap: wrap; gap: 8px; align-items: center; margin-bottom: 14px;
}
.btn {
  padding: 6px 13px; background: var(--card); border: 1px solid var(--border);
  border-radius: var(--radius-sm); color: var(--text); cursor: pointer; font-family: inherit;
  font-size: 0.85em; transition: border-color 0.15s, background 0.15s, color 0.15s, transform 0.06s;
}
.btn:hover { border-color: var(--accent); background: var(--card-hover); }
.btn:active { transform: translateY(1px); }
.btn:focus-visible { outline: none; box-shadow: var(--focus-ring); }
.btn.small { padding: 2px 8px; font-size: 0.8em; }
.btn.danger:hover { border-color: var(--red); color: var(--red); background: rgba(248,81,73,0.08); }
.chip {
  font-size: 0.82em; color: var(--dim); padding: 4px 11px; border: 1px solid var(--border);
  border-radius: 20px; background: var(--card); box-shadow: var(--shadow-sm);
}
.chip b { color: var(--text); }
.chip .k { color: var(--green); }
.chip .d { color: var(--red); }
.chip .h { color: var(--dim); }
.toggle { display: flex; align-items: center; gap: 6px; font-size: 0.85em; color: var(--dim); cursor: pointer; user-select: none; }
.warn-banner {
  background: rgba(210,153,34,0.12); border: 1px solid var(--orange); color: var(--orange);
  border-radius: 6px; padding: 8px 12px; margin-bottom: 12px; font-size: 0.85em;
}

/* ── Pattern bulk bar ── */
.patternbar {
  display: flex; flex-wrap: wrap; gap: 8px; align-items: center; margin-bottom: 14px;
  padding: 10px 13px; background: var(--card); border: 1px solid var(--border);
  border-radius: var(--radius); box-shadow: var(--shadow-sm);
}
.patternbar .lbl { font-size: 0.82em; color: var(--dim); }
.patternbar input.pat {
  flex: 1; min-width: 200px; padding: 6px 10px; background: var(--bg); border: 1px solid var(--border);
  border-radius: 6px; color: var(--text); font-size: 0.85em; font-family: 'SF Mono', SFMono-Regular, Consolas, monospace;
}
.patternbar input.pat:focus { outline: none; border-color: var(--accent); box-shadow: var(--focus-ring); }
.patternbar .pat-hint { font-size: 0.8em; color: var(--dim); min-width: 90px; }
.patternbar .pat-hint b { color: var(--accent); }

/* ── Dropdown menu ── */
.menu-wrap { position: relative; display: inline-block; }
.menu {
  position: absolute; top: calc(100% + 4px); left: 0; z-index: 50; min-width: 240px;
  background: var(--card); border: 1px solid var(--border); border-radius: 8px;
  box-shadow: 0 8px 24px rgba(0,0,0,0.4); padding: 6px; display: none;
}
.menu.open { display: block; }
.menu button {
  display: block; width: 100%; text-align: left; padding: 7px 10px; background: none;
  border: none; color: var(--text); cursor: pointer; font-family: inherit; font-size: 0.85em;
  border-radius: 5px;
}
.menu button:hover { background: var(--card-hover); }
.menu .menu-sep { border-top: 1px solid var(--border); margin: 5px 0; }
.menu .menu-label { color: var(--dim); font-size: 0.72em; text-transform: uppercase; letter-spacing: 0.5px; padding: 4px 10px 2px; }

/* ── Stat Cards ── */
.stats { display: flex; flex-wrap: wrap; gap: 12px; margin-bottom: 18px; }
.stat-card {
  position: relative; overflow: hidden;
  background: linear-gradient(180deg, var(--card), rgba(22,27,34,0.6));
  border: 1px solid var(--border); border-radius: var(--radius);
  padding: 12px 16px; min-width: 130px; flex: 1; box-shadow: var(--shadow-sm);
  transition: transform 0.12s ease, border-color 0.15s, box-shadow 0.15s;
}
.stat-card::before {
  content: ""; position: absolute; left: 0; top: 0; bottom: 0; width: 3px;
  background: var(--border); transition: background 0.15s;
}
.stat-card:hover { transform: translateY(-2px); border-color: #3d444d; box-shadow: var(--shadow); }
.stat-card .label { color: var(--dim); font-size: 0.74em; text-transform: uppercase; letter-spacing: 0.6px; font-weight: 600; }
.stat-card .value { font-size: 1.42em; font-weight: 700; letter-spacing: -0.01em; margin-top: 1px; font-variant-numeric: tabular-nums; }
.stat-card .value.green { color: var(--green); }
.stat-card .value.red { color: var(--red); }
.stat-card .value.orange { color: var(--orange); }
.stat-card .value.purple { color: var(--purple); }
.stat-card:has(.value.green)::before { background: var(--green); }
.stat-card:has(.value.red)::before { background: var(--red); }
.stat-card:has(.value.orange)::before { background: var(--orange); }
.stat-card:has(.value.purple)::before { background: var(--purple); }

/* ── Media Breakdown Bar ── */
.media-bar-container { margin-bottom: 16px; }
.media-bar { display: flex; height: 28px; border-radius: var(--radius-sm); overflow: hidden; border: 1px solid var(--border); margin-bottom: 8px; box-shadow: var(--shadow-sm); }
.media-bar-seg {
  transition: opacity 0.2s; cursor: pointer; position: relative;
  display: flex; align-items: center; justify-content: center;
  font-size: 0.7em; font-weight: 600; color: #fff; text-shadow: 0 1px 2px rgba(0,0,0,0.5); min-width: 2px;
}
.media-bar-seg:hover { opacity: 0.8; }
.media-legend { display: flex; flex-wrap: wrap; gap: 6px 14px; font-size: 0.82em; }
.media-legend-item { display: flex; align-items: center; gap: 5px; cursor: pointer; }
.media-legend-item.dimmed { opacity: 0.35; }
.media-legend-dot { width: 10px; height: 10px; border-radius: 3px; }

/* ── Tabs ── */
.tabs { display: flex; gap: 2px; flex-wrap: wrap; border-bottom: 1px solid var(--border); margin-bottom: 2px; }
.tab {
  padding: 10px 18px; cursor: pointer; background: none; border: none; color: var(--dim);
  font-size: 0.95em; font-weight: 500; border-bottom: 2px solid transparent; margin-bottom: -1px;
  border-top-left-radius: var(--radius-sm); border-top-right-radius: var(--radius-sm);
  transition: color 0.15s, background 0.15s, border-color 0.15s; font-family: inherit;
}
.tab:hover { color: var(--text); background: rgba(255,255,255,0.03); }
.tab.active { color: var(--accent); border-bottom-color: var(--accent); background: linear-gradient(180deg, var(--accent-soft), transparent); font-weight: 600; }
.tab .badge { background: var(--border); color: var(--dim); border-radius: 20px; padding: 1px 8px; font-size: 0.8em; margin-left: 7px; font-variant-numeric: tabular-nums; }
.tab.active .badge { background: rgba(88,166,255,0.22); color: var(--accent); }

/* ── Panels ── */
.panel { display: none; }
.panel.active { display: block; }

/* ── Toolbar (search + filters) ── */
.toolbar { display: flex; flex-wrap: wrap; gap: 8px; align-items: center; padding: 12px 0 4px; }
.search-input {
  flex: 1; min-width: 200px; padding: 8px 12px; background: var(--card);
  border: 1px solid var(--border); border-radius: var(--radius-sm); color: var(--text);
  font-size: 0.88em; font-family: inherit; transition: border-color 0.15s, box-shadow 0.15s;
}
.search-input::placeholder { color: var(--dim); }
.search-input:focus { outline: none; border-color: var(--accent); box-shadow: var(--focus-ring); }
.filter-select {
  padding: 8px 10px; background: var(--card); border: 1px solid var(--border);
  border-radius: var(--radius-sm); color: var(--text); font-size: 0.85em; font-family: inherit; cursor: pointer;
  transition: border-color 0.15s, box-shadow 0.15s;
}
.filter-select:hover { border-color: #3d444d; }
.filter-select:focus { outline: none; border-color: var(--accent); box-shadow: var(--focus-ring); }
.size-filter { display: flex; align-items: center; gap: 4px; font-size: 0.85em; color: var(--dim); }
.size-filter input {
  width: 84px; padding: 8px 8px; background: var(--card); border: 1px solid var(--border);
  border-radius: var(--radius-sm); color: var(--text); font-size: 0.85em; font-family: inherit;
  transition: border-color 0.15s, box-shadow 0.15s;
}
.size-filter input:focus { outline: none; border-color: var(--accent); box-shadow: var(--focus-ring); }
.bulkbar { display: flex; flex-wrap: wrap; gap: 6px; align-items: center; padding: 2px 0 6px; }
.bulkbar .lbl { font-size: 0.8em; color: var(--dim); margin-right: 2px; }
.result-count { font-size: 0.82em; color: var(--dim); padding: 4px 0; }

/* ── Table ── */
table { width: 100%; border-collapse: collapse; font-size: 0.84em; }
th {
  text-align: left; padding: 9px 10px; border-bottom: 1px solid var(--border);
  color: var(--dim); cursor: pointer; user-select: none; white-space: nowrap;
  font-weight: 600; text-transform: uppercase; letter-spacing: 0.4px; font-size: 0.92em;
  position: sticky; top: 0; z-index: 2;
  background: #12161d; box-shadow: 0 1px 0 var(--border), 0 6px 12px -8px rgba(0,0,0,0.7);
}
th.nosort { cursor: default; }
th:hover:not(.nosort) { color: var(--text); }
th .arrow { font-size: 0.7em; margin-left: 3px; color: var(--accent); }
td { padding: 7px 10px; border-bottom: 1px solid var(--border-soft); vertical-align: top; }
tr:nth-child(even) { background: rgba(255,255,255,0.018); }
tr:hover { background: rgba(88,166,255,0.07); }
tr.stale-row { background: rgba(188,140,255,0.05); }
tr.row-keep { background: rgba(63,185,80,0.08); }
tr.row-keep td:first-child { box-shadow: inset 3px 0 0 var(--green); }
tr.row-del { background: rgba(248,81,73,0.08); }
tr.row-del td:first-child { box-shadow: inset 3px 0 0 var(--red); }
tr.row-hide { opacity: 0.45; }
tr.row-hide td:first-child { box-shadow: inset 3px 0 0 var(--dim); }
.size-cell { font-family: 'SF Mono', SFMono-Regular, Consolas, monospace; white-space: nowrap; text-align: right; }
.paths-cell { font-family: 'SF Mono', SFMono-Regular, Consolas, monospace; font-size: 0.9em; word-break: break-all; }
.path-line { margin: 2px 0; display: flex; flex-wrap: wrap; gap: 4px; align-items: baseline; }
.path-text { word-break: break-all; }
.copybtn {
  cursor: pointer; color: var(--dim); border: 1px solid var(--border); border-radius: 4px;
  padding: 0 5px; font-size: 0.8em; background: var(--card); flex: none;
  transition: color 0.12s, border-color 0.12s, background 0.12s;
}
.copybtn:hover { color: var(--accent); border-color: var(--accent); background: var(--accent-soft); }
.tag { font-size: 0.85em; padding: 0 4px; border-radius: 3px; white-space: nowrap; }
.tag-active { color: var(--green); }
.tag-paused { color: var(--orange); }
.tag-none   { color: var(--red); }
.tag-stale  { color: var(--purple); font-weight: 600; }
.drive-cell { color: var(--cyan); white-space: nowrap; font-size: 0.92em; }
.torrent-detail { font-size: 0.85em; color: var(--dim); overflow: hidden; text-overflow: ellipsis; max-width: 380px; white-space: nowrap; }
.torrent-detail:hover { white-space: normal; }

/* ── Mark buttons ── */
.marks { display: flex; gap: 3px; }
.mbtn {
  cursor: pointer; border: 1px solid var(--border); border-radius: 5px; background: var(--card);
  color: var(--dim); width: 23px; height: 23px; font-size: 0.85em; line-height: 1; padding: 0;
  display: flex; align-items: center; justify-content: center;
  transition: border-color 0.12s, color 0.12s, background 0.12s, transform 0.06s;
}
.mbtn:hover { border-color: var(--accent); color: var(--text); background: var(--card-hover); }
.mbtn:active { transform: scale(0.92); }
.mbtn.on-keep { background: rgba(63,185,80,0.2); border-color: var(--green); color: var(--green); }
.mbtn.on-del  { background: rgba(248,81,73,0.2); border-color: var(--red); color: var(--red); }
.mbtn.on-hide { background: rgba(139,148,158,0.2); border-color: var(--dim); color: var(--text); }

/* ── Type Badges ── */
.type-badge { display: inline-block; padding: 1px 8px; border-radius: 4px; font-size: 0.82em; font-weight: 500; }
.type-video    { background: rgba(88,166,255,0.15); color: var(--accent); }
.type-audio    { background: rgba(63,185,80,0.15); color: var(--green); }
.type-books    { background: rgba(188,140,255,0.15); color: var(--purple); }
.type-image    { background: rgba(210,153,34,0.15); color: var(--orange); }
.type-disc     { background: rgba(57,210,192,0.15); color: var(--cyan); }
.type-subtitle { background: rgba(139,148,158,0.15); color: var(--dim); }
.type-metadata { background: rgba(139,148,158,0.15); color: var(--dim); }
.type-nzbs     { background: rgba(139,148,158,0.15); color: var(--dim); }
.type-other    { background: rgba(139,148,158,0.1); color: var(--dim); }

/* ── Duplicates / cross-drive ── */
.dup-group { background: var(--card); border: 1px solid var(--border); border-radius: var(--radius); padding: 14px 16px; margin-bottom: 12px; box-shadow: var(--shadow-sm); transition: border-color 0.15s, box-shadow 0.15s; }
.dup-group:hover { border-color: #3d444d; box-shadow: var(--shadow); }
.dup-group.xd { border-color: rgba(188,140,255,0.5); }
.dup-group.xd:hover { border-color: rgba(188,140,255,0.75); }
.dup-header { font-weight: 600; margin-bottom: 8px; font-size: 0.95em; display: flex; flex-wrap: wrap; gap: 8px; align-items: center; }
.dup-copy { margin-left: 4px; margin-bottom: 8px; padding: 6px 8px; border-radius: 6px; border: 1px solid transparent; }
.dup-copy.c-keep { background: rgba(63,185,80,0.08); border-color: rgba(63,185,80,0.4); }
.dup-copy.c-del  { background: rgba(248,81,73,0.08); border-color: rgba(248,81,73,0.4); }
.dup-copy-head { font-weight: 500; margin-bottom: 3px; display: flex; flex-wrap: wrap; gap: 8px; align-items: center; }
.keep { color: var(--green); }
.dup  { color: var(--red); }
.badge-xd { background: #7c3aed; color: #fff; padding: 1px 7px; border-radius: 4px; font-size: 0.72em; }
.badge-suggest { background: rgba(63,185,80,0.2); color: var(--green); padding: 0 6px; border-radius: 4px; font-size: 0.72em; }

/* ── Misc ── */
.no-results { text-align: center; padding: 40px; color: var(--dim); font-size: 0.95em; }
.footer { text-align: center; color: var(--dim); font-size: 0.78em; margin-top: 36px; padding-top: 14px; border-top: 1px solid var(--border-soft); }
.pagination { display: flex; align-items: center; justify-content: center; gap: 8px; padding: 12px 0; font-size: 0.88em; }
.pagination button { padding: 5px 14px; background: var(--card); border: 1px solid var(--border); border-radius: 6px; color: var(--text); cursor: pointer; font-family: inherit; }
.pagination button:hover:not(:disabled) { border-color: var(--accent); }
.pagination button:disabled { opacity: 0.3; cursor: default; }
.pagination .page-info { color: var(--dim); }

/* ── Pager bar (top + bottom of tables) ── */
.pagbar { display: flex; flex-wrap: wrap; align-items: center; gap: 10px; padding: 8px 0; font-size: 0.84em; }
.pagbar.top { border-bottom: 1px solid var(--border); }
.pagbar.bottom { justify-content: center; }
.pagbar .rpp { color: var(--dim); }
.pagbar .rpp select { margin-left: 4px; }
.pagbar .range { color: var(--dim); }
.pagbar .nav { margin-left: auto; display: flex; align-items: center; gap: 6px; }
.pagbar.bottom .nav { margin-left: 0; }
.pgbtn { padding: 5px 12px; background: var(--card); border: 1px solid var(--border); border-radius: var(--radius-sm); color: var(--text); cursor: pointer; font-family: inherit; transition: border-color 0.12s, background 0.12s, transform 0.06s; }
.pgbtn:hover:not(:disabled) { border-color: var(--accent); background: var(--card-hover); }
.pgbtn:active:not(:disabled) { transform: translateY(1px); }
.pgbtn:disabled { opacity: 0.3; cursor: default; }
.page-info { color: var(--dim); white-space: nowrap; }
.page-jump { width: 46px; text-align: center; padding: 3px 4px; background: var(--bg); border: 1px solid var(--border); border-radius: 5px; color: var(--text); font-family: inherit; }
.page-jump:focus { outline: none; border-color: var(--accent); box-shadow: var(--focus-ring); }
.toast {
  position: fixed; bottom: 20px; left: 50%; transform: translateX(-50%);
  background: var(--card); border: 1px solid var(--accent); color: var(--text);
  padding: 10px 18px; border-radius: 8px; font-size: 0.88em; box-shadow: 0 6px 20px rgba(0,0,0,0.4);
  opacity: 0; transition: opacity 0.2s; pointer-events: none; z-index: 100;
}
.toast.show { opacity: 1; }
</style>
</head>
<body>

<h1>Disk Report</h1>
<div class="subtitle" id="subtitle"></div>
<div id="storage-warn"></div>

<div class="globalbar" id="globalbar"></div>
<div class="patternbar" id="patternbar"></div>
<div class="stats" id="stats"></div>
<div class="media-bar-container" id="media-bar-container"></div>
<div class="tabs" id="tabs-bar"></div>
<div id="panels"></div>
<div class="footer">Generated by disk.py &mdash; review state is saved in this browser (per report location).</div>
<div class="toast" id="toast"></div>

<!-- Data is embedded as JSON in script tags by the Python report writer. -->
<script id="data-meta" type="application/json">__DATA_META__</script>
<script id="data-used" type="application/json">__DATA_USED__</script>
<script id="data-unused" type="application/json">__DATA_UNUSED__</script>
<script id="data-mixed" type="application/json">__DATA_MIXED__</script>
<script id="data-duplicates" type="application/json">__DATA_DUPLICATES__</script>

<script>
"use strict";

// ── Load embedded data ──
const META = JSON.parse(document.getElementById('data-meta').textContent);
const DATASETS = {
  used:       JSON.parse(document.getElementById('data-used').textContent),
  unused:     JSON.parse(document.getElementById('data-unused').textContent),
  mixed:      JSON.parse(document.getElementById('data-mixed').textContent),
  duplicates: JSON.parse(document.getElementById('data-duplicates').textContent),
};
DATASETS.crossdrive = DATASETS.duplicates.filter(d => d.cross_drive);
const ALL_INODES = [...DATASETS.used, ...DATASETS.unused, ...DATASETS.mixed];

const MEDIA_COLORS = {
  video: '#58a6ff', audio: '#3fb950', books: '#bc8cff', image: '#d29922',
  disc: '#39d2c0', subtitle: '#8b949e', metadata: '#6e7681', nzbs: '#6e7681', other: '#484f58',
};
const PAGE_SIZE = 100;
const PAGE_SIZE_OPTIONS = [50, 100, 250, 500, 'all'];

// ── Helpers ──
function esc(s) {
  if (s === null || s === undefined) return '';
  return String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');
}
function formatBytes(b) {
  if (!b) return '0 B';
  const u = ['B','KB','MB','GB','TB','PB'];
  const i = Math.min(Math.floor(Math.log(b)/Math.log(1024)), u.length-1);
  return (b/Math.pow(1024,i)).toFixed(i?1:0) + ' ' + u[i];
}
function parseSize(s) {
  if (!s) return 0;
  s = String(s).trim().toUpperCase();
  const m = s.match(/^([\d.]+)\s*(B|KB|MB|GB|TB)?$/);
  if (!m) return parseFloat(s) || 0;
  const units = {'B':1,'KB':1024,'MB':1048576,'GB':1073741824,'TB':1099511627776};
  return parseFloat(m[1]) * (units[m[2]] || 1);
}
function driveShort(d) {
  if (!d) return '';
  const parts = String(d).split('/').filter(Boolean);
  return parts.length ? parts[parts.length-1] : d;
}
function baseName(p) { const s = String(p).split('/').filter(Boolean); return s.length ? s[s.length-1] : String(p); }
// Build a predicate from a query: /regex/flags, *glob?* (anchored), or plain
// substring (case-insensitive). Returns null for an empty query (match all).
function makeMatcher(query) {
  query = (query || '').trim();
  if (!query) return null;
  const rx = query.match(/^\/(.*)\/([a-z]*)$/);
  if (rx) {
    try { const re = new RegExp(rx[1], rx[2] || 'i'); return s => re.test(String(s)); } catch (e) {}
  }
  if (/[*?]/.test(query)) {
    let re = '';
    for (const ch of query) {
      if (ch === '*') re += '.*';
      else if (ch === '?') re += '.';
      else re += ch.replace(/[.+^${}()|[\]\\]/g, '\\$&');
    }
    const g = new RegExp('^' + re + '$', 'i');
    return s => g.test(String(s));
  }
  const q = query.toLowerCase();
  return s => String(s).toLowerCase().includes(q);
}
// Does an inode entry match, under 'path' or 'name' scope?
function entryMatches(entry, matcher, scope) {
  if (!matcher) return true;
  return entry.paths.some(p => matcher(scope === 'name' ? baseName(p.path) : p.path));
}
function download(filename, text, mime) {
  const blob = new Blob([text], {type: mime || 'text/plain'});
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url; a.download = filename;
  document.body.appendChild(a); a.click(); document.body.removeChild(a);
  setTimeout(() => URL.revokeObjectURL(url), 1000);
  toast('Downloaded ' + filename);
}
function copyText(text) {
  const done = () => toast('Copied to clipboard');
  if (navigator.clipboard && navigator.clipboard.writeText) {
    navigator.clipboard.writeText(text).then(done).catch(() => fallbackCopy(text));
  } else { fallbackCopy(text); }
}
function fallbackCopy(text) {
  try {
    const ta = document.createElement('textarea');
    ta.value = text; ta.style.position = 'fixed'; ta.style.opacity = '0';
    document.body.appendChild(ta); ta.select();
    document.execCommand('copy'); document.body.removeChild(ta);
    toast('Copied to clipboard');
  } catch (e) { window.prompt('Copy:', text); }
}
function shellQuote(p) { return "'" + String(p).replace(/'/g, "'\\''") + "'"; }
let _toastTimer = null;
function toast(msg) {
  const t = document.getElementById('toast');
  t.textContent = msg; t.classList.add('show');
  clearTimeout(_toastTimer);
  _toastTimer = setTimeout(() => t.classList.remove('show'), 1800);
}

// ── Persistent review state (keep / del / hide) ──
const NS = 'diskpy:' + (META.root || '');
const MARK_KEY = NS + ':marks';
const PREF_KEY = NS + ':prefs';
let STORAGE_OK = true;
try { localStorage.setItem(NS + ':t', '1'); localStorage.removeItem(NS + ':t'); }
catch (e) { STORAGE_OK = false; }

let marks = {};
let prefs = { showHidden: false, activeTab: 'used' };
if (STORAGE_OK) {
  try { marks = JSON.parse(localStorage.getItem(MARK_KEY)) || {}; } catch (e) { marks = {}; }
  try { Object.assign(prefs, JSON.parse(localStorage.getItem(PREF_KEY)) || {}); } catch (e) {}
}
function saveMarks() { if (STORAGE_OK) { try { localStorage.setItem(MARK_KEY, JSON.stringify(marks)); } catch (e) {} } }
function savePrefs() { if (STORAGE_OK) { try { localStorage.setItem(PREF_KEY, JSON.stringify(prefs)); } catch (e) {} } }
function keyOf(entry) { return entry.paths.map(p => p.path).slice().sort().join('\u0000'); }
function getMark(key) { return marks[key] || ''; }
function setMark(key, status) {
  if (!status || marks[key] === status) { delete marks[key]; }
  else { marks[key] = status; }
  saveMarks();
}
function markCounts() {
  const c = { keep: 0, del: 0, hide: 0 };
  ALL_INODES.forEach(e => { const m = getMark(keyOf(e)); if (c[m] != null) c[m]++; });
  return c;
}

// ── Subtitle + storage warning ──
document.getElementById('subtitle').textContent = META.root + ' — generated ' + META.generated;
if (!STORAGE_OK) {
  document.getElementById('storage-warn').innerHTML =
    '<div class="warn-banner">Your browser blocks local storage for file:// pages, so keep/delete/hide marks won’t persist across reloads (they still work this session). Exports work regardless.</div>';
}

// ═══════════════════════════════════════════════════════════════════
//  Global bar (export, show-hidden, reset) + stat cards
// ═══════════════════════════════════════════════════════════════════
function renderGlobalBar() {
  const c = markCounts();
  const bar = document.getElementById('globalbar');
  bar.innerHTML =
    '<div class="menu-wrap">' +
      '<button class="btn" id="export-btn">Export ▾</button>' +
      '<div class="menu" id="export-menu">' +
        '<div class="menu-label">Marked for deletion (' + c.del + ')</div>' +
        '<button data-exp="del-txt">Download delete list (.txt)</button>' +
        '<button data-exp="del-sh">Download delete script (.sh)</button>' +
        '<button data-exp="del-copy">Copy delete paths</button>' +
        '<div class="menu-sep"></div>' +
        '<div class="menu-label">Marked keep (' + c.keep + ')</div>' +
        '<button data-exp="keep-txt">Download keep list (.txt)</button>' +
        '<div class="menu-sep"></div>' +
        '<div class="menu-label">Current tab</div>' +
        '<button data-exp="view-csv">Export current view (.csv)</button>' +
        '<div class="menu-sep"></div>' +
        '<button data-exp="marks-json">Backup marks (.json)</button>' +
      '</div>' +
    '</div>' +
    '<label class="toggle"><input type="checkbox" id="show-hidden" ' + (prefs.showHidden ? 'checked' : '') + '> Show hidden</label>' +
    '<button class="btn danger small" id="reset-marks">Reset all marks</button>' +
    '<span class="chip">Reviewed <b>' + (c.keep + c.del + c.hide).toLocaleString() + '</b> / ' + ALL_INODES.length.toLocaleString() +
      ' &nbsp; <span class="k">✓ ' + c.keep + '</span> &nbsp; <span class="d">✗ ' + c.del + '</span> &nbsp; <span class="h">⊘ ' + c.hide + '</span></span>';

  document.getElementById('export-btn').onclick = (e) => {
    e.stopPropagation();
    document.getElementById('export-menu').classList.toggle('open');
  };
  document.querySelectorAll('#export-menu button').forEach(b => {
    b.onclick = () => { doExport(b.dataset.exp); document.getElementById('export-menu').classList.remove('open'); };
  });
  document.getElementById('show-hidden').onchange = (e) => {
    prefs.showHidden = e.target.checked; savePrefs(); refreshActive();
  };
  document.getElementById('reset-marks').onclick = () => {
    const c2 = markCounts();
    if (!(c2.keep + c2.del + c2.hide)) { toast('No marks to reset'); return; }
    if (confirm('Clear ALL keep/delete/hide marks for this report?')) {
      marks = {}; saveMarks(); renderGlobalBar(); renderStats(); refreshActive();
      toast('All marks cleared');
    }
  };
}

// ── Bulk-by-pattern bar (mark everything matching a name/path pattern) ──
// Built once so its input keeps focus. Applies across ALL inodes (every tab),
// with a live match count and a confirm, so "exclude everything matching *x*"
// is one action.
function renderPatternBar() {
  const bar = document.getElementById('patternbar');
  bar.innerHTML =
    '<span class="lbl">Bulk by pattern:</span>' +
    '<input type="text" class="pat" placeholder="e.g. *sample*  ·  *.nfo  ·  /S0[12]E/  (glob or /regex/)">' +
    '<select class="filter-select pat-scope"><option value="path">match: full path</option><option value="name">match: file name</option></select>' +
    '<span class="pat-hint"></span>' +
    '<button class="btn small" data-pat="keep">✓ Keep</button>' +
    '<button class="btn small" data-pat="del">✗ Delete</button>' +
    '<button class="btn small" data-pat="hide">⊘ Hide</button>' +
    '<button class="btn small" data-pat="clear">Clear</button>';
  const inp = bar.querySelector('.pat');
  const scopeSel = bar.querySelector('.pat-scope');
  const hint = bar.querySelector('.pat-hint');

  function matchList() {
    const m = makeMatcher(inp.value);
    if (!m) return null;                         // empty → no selection
    const scope = scopeSel.value;
    return ALL_INODES.filter(e => entryMatches(e, m, scope));
  }
  function updateHint() {
    const list = matchList();
    hint.innerHTML = list === null ? '' : '<b>' + list.length.toLocaleString() + '</b> match(es)';
  }
  inp.addEventListener('input', updateHint);
  scopeSel.addEventListener('change', updateHint);
  bar.querySelectorAll('[data-pat]').forEach(btn => {
    btn.addEventListener('click', () => {
      const list = matchList();
      if (list === null) return toast('Enter a pattern first');
      if (!list.length) return toast('No files match that pattern');
      const act = btn.dataset.pat;
      const verb = act === 'clear' ? 'clear marks on' : (act + ' — mark');
      if (!confirm(verb + ' ' + list.length + ' file(s) matching "' + inp.value.trim() + '"?')) return;
      list.forEach(e => { const k = keyOf(e); if (act === 'clear') delete marks[k]; else marks[k] = act; });
      saveMarks(); renderGlobalBar(); renderStats(); refreshActive();
      toast((act === 'clear' ? 'Cleared ' : 'Marked ') + list.length + (act === 'clear' ? '' : ' ' + act));
    });
  });
}
document.addEventListener('click', () => {
  const m = document.getElementById('export-menu');
  if (m) m.classList.remove('open');
});

function collectPaths(status) {
  const out = [];
  ALL_INODES.forEach(e => { if (getMark(keyOf(e)) === status) e.paths.forEach(p => out.push(p.path)); });
  return out;
}
function doExport(kind) {
  if (kind === 'del-txt') {
    const paths = collectPaths('del');
    if (!paths.length) return toast('Nothing marked for deletion');
    download('disk-delete-list.txt', paths.join('\n') + '\n');
  } else if (kind === 'del-copy') {
    const paths = collectPaths('del');
    if (!paths.length) return toast('Nothing marked for deletion');
    copyText(paths.join('\n'));
  } else if (kind === 'del-sh') {
    const paths = collectPaths('del');
    if (!paths.length) return toast('Nothing marked for deletion');
    let sh = '#!/usr/bin/env bash\n';
    sh += '# Deletion script generated by disk.py report on ' + new Date().toISOString() + '\n';
    sh += '# Report root: ' + META.root + '\n';
    sh += '# REVIEW BEFORE RUNNING. Uses rm -v; remove the echo to arm it.\n';
    sh += '# Each line removes one path (a hardlink); the file’s data is gone when\n';
    sh += '# its last link is removed.\n\nset -u\n\n';
    paths.forEach(p => { sh += 'echo rm -v -- ' + shellQuote(p) + '\n'; });
    download('disk-delete.sh', sh, 'text/x-shellscript');
  } else if (kind === 'keep-txt') {
    const paths = collectPaths('keep');
    if (!paths.length) return toast('Nothing marked keep');
    download('disk-keep-list.txt', paths.join('\n') + '\n');
  } else if (kind === 'marks-json') {
    download('disk-marks.json', JSON.stringify(marks, null, 0), 'application/json');
  } else if (kind === 'view-csv') {
    const ctrl = panelControllers[currentTab];
    if (ctrl && ctrl.exportCsv) ctrl.exportCsv();
    else toast('Nothing to export in this tab');
  }
}

function renderStats() {
  const totalWasted = DATASETS.duplicates.reduce((s,d) => s + d.wasted_bytes, 0);
  const xdReclaim = DATASETS.crossdrive.reduce((s,d) => s + d.wasted_bytes, 0);
  const unusedBytes = DATASETS.unused.reduce((s,e) => s + e.size_bytes, 0);
  const cards = [
    { label: 'Unique Inodes', value: META.total_inodes.toLocaleString() },
    { label: 'Real Disk Usage', value: META.total_real_human },
    { label: 'Used', value: DATASETS.used.length.toLocaleString(), cls: 'green' },
    { label: 'Unused', value: DATASETS.unused.length.toLocaleString() + ' · ' + formatBytes(unusedBytes), cls: DATASETS.unused.length ? 'orange' : '' },
    { label: 'Mixed', value: DATASETS.mixed.length.toLocaleString(), cls: DATASETS.mixed.length ? 'orange' : '' },
    { label: 'Dup Groups', value: DATASETS.duplicates.length.toLocaleString() + ' · ' + formatBytes(totalWasted), cls: totalWasted ? 'red' : '' },
  ];
  if (DATASETS.crossdrive.length) {
    cards.push({ label: 'Cross-Drive', value: DATASETS.crossdrive.length.toLocaleString() + ' · ' + formatBytes(xdReclaim), cls: 'purple' });
  }
  if (META.qbt_connected) cards.push({ label: 'Torrent Filter', value: META.active_only ? 'Active Only' : 'All' });
  if (META.stale_days > 0) {
    const staleCount = ALL_INODES.filter(e => e.stale).length;
    cards.push({ label: 'Stale (>' + META.stale_days + 'd)', value: staleCount.toLocaleString(), cls: staleCount ? 'purple' : '' });
  }
  document.getElementById('stats').innerHTML = cards.map(c =>
    '<div class="stat-card"><div class="label">' + c.label + '</div><div class="value ' + (c.cls||'') + '">' + c.value + '</div></div>'
  ).join('');
}

// ═══════════════════════════════════════════════════════════════════
//  Media type breakdown bar
// ═══════════════════════════════════════════════════════════════════
const mediaTypes = META.media_types || {};
const totalMediaBytes = Object.values(mediaTypes).reduce((s,v) => s + v.bytes, 0);
const activeMediaFilters = new Set();

function renderMediaBar() {
  const container = document.getElementById('media-bar-container');
  const entries = Object.entries(mediaTypes).sort((a,b) => b[1].bytes - a[1].bytes);
  if (!entries.length) { container.innerHTML = ''; return; }
  const allActive = activeMediaFilters.size === 0;
  let h = '<div class="media-bar">';
  entries.forEach(([mt, s]) => {
    const pct = totalMediaBytes ? (s.bytes / totalMediaBytes * 100) : 0;
    const dimmed = !allActive && !activeMediaFilters.has(mt);
    h += '<div class="media-bar-seg" style="width:' + Math.max(pct,0.3) + '%;background:' + (MEDIA_COLORS[mt]||'#484f58') + ';' + (dimmed?'opacity:0.2':'') + '"' +
         ' data-media="' + mt + '" title="' + mt + ': ' + s.human + ' (' + s.count + ' inodes, ' + pct.toFixed(1) + '%)">' + (pct > 5 ? mt : '') + '</div>';
  });
  h += '</div><div class="media-legend">';
  entries.forEach(([mt, s]) => {
    const dimmed = !allActive && !activeMediaFilters.has(mt);
    h += '<div class="media-legend-item ' + (dimmed?'dimmed':'') + '" data-media="' + mt + '">' +
         '<div class="media-legend-dot" style="background:' + (MEDIA_COLORS[mt]||'#484f58') + '"></div>' +
         '<span>' + mt + '</span> <span style="color:var(--dim)">' + s.human + ' (' + s.count + ')</span></div>';
  });
  h += '</div>';
  container.innerHTML = h;
  container.querySelectorAll('[data-media]').forEach(el => {
    el.onclick = () => toggleMediaFilter(el.dataset.media);
  });
}
function toggleMediaFilter(mt) {
  if (activeMediaFilters.has(mt)) activeMediaFilters.delete(mt); else activeMediaFilters.add(mt);
  if (activeMediaFilters.size === Object.keys(mediaTypes).length) activeMediaFilters.clear();
  renderMediaBar();
  refreshActive();
}

// ═══════════════════════════════════════════════════════════════════
//  Inode table panel (used / unused / mixed)
// ═══════════════════════════════════════════════════════════════════
function markButtons(status, extra) {
  extra = extra || '';
  return '<div class="marks">' +
    '<button class="mbtn ' + (status==='keep'?'on-keep':'') + '" data-act="mark" data-status="keep" ' + extra + ' title="Keep">✓</button>' +
    '<button class="mbtn ' + (status==='del'?'on-del':'') + '" data-act="mark" data-status="del" ' + extra + ' title="Mark for deletion">✗</button>' +
    '<button class="mbtn ' + (status==='hide'?'on-hide':'') + '" data-act="mark" data-status="hide" ' + extra + ' title="Hide from view">⊘</button>' +
    '</div>';
}
function pathsCellHtml(entry) {
  let h = '<td class="paths-cell">';
  entry.paths.forEach((p, pi) => {
    h += '<div class="path-line">';
    h += '<button class="copybtn" data-act="copy" data-p="' + pi + '" title="Copy path">copy</button> ';
    h += '<span class="path-text">' + esc(p.path) + '</span>';
    if (p.has_torrent === null) { /* no qbt */ }
    else if (p.has_active_torrent) {
      const names = (p.torrents||[]).filter(t => t.active).map(t => t.torrent_name);
      h += ' <span class="tag tag-active">[T]</span>';
      h += ' <span class="torrent-detail tag-active" title="' + esc(names.join(', ')) + '">' + esc(names[0]||'') + '</span>';
    } else if (p.has_torrent) {
      const names = (p.torrents||[]).map(t => t.torrent_name + ' (' + t.torrent_state + ')');
      h += ' <span class="tag tag-paused">[P]</span>';
      h += ' <span class="torrent-detail tag-paused" title="' + esc(names.join(', ')) + '">' + esc(names[0]||'') + '</span>';
    } else {
      h += ' <span class="tag tag-none">[no torrent]</span>';
    }
    h += '</div>';
  });
  return h + '</td>';
}

function createInodePanel(id, data) {
  const drives = [...new Set(data.map(e => e.drive).filter(Boolean))].sort();
  const types = [...new Set(data.map(e => e.content_type))].filter(Boolean).sort();
  const state = {
    data, filtered: data, pageItems: [],
    sortKey: 'size_bytes', sortDir: 'desc', page: 0, _viewPage: 0,
    pageSize: prefs.pageSize || PAGE_SIZE,
    search: '', typeFilter: '', driveFilter: '', minBytes: 0, maxBytes: Infinity,
    staleFilter: '', torrentFilter: '', statusFilter: '',
  };

  function applyFilters() {
    let f = state.data.slice();
    const sq = (state.search || '').trim();
    if (sq) {
      const matcher = makeMatcher(sq);
      const isPattern = /[*?]/.test(sq) || /^\/.*\/[a-z]*$/.test(sq);
      const ql = sq.toLowerCase();
      f = f.filter(e => {
        if (e.paths.some(p => matcher(p.path))) return true;
        if (isPattern) return false;   // glob/regex: match paths only
        return (e.content_type||'').includes(ql) || (e.drive||'').toLowerCase().includes(ql) ||
               e.size_human.toLowerCase().includes(ql) || String(e.inode).includes(ql);
      });
    }
    if (state.typeFilter) f = f.filter(e => e.content_type === state.typeFilter);
    if (state.driveFilter) f = f.filter(e => e.drive === state.driveFilter);
    if (activeMediaFilters.size > 0) f = f.filter(e => activeMediaFilters.has(e.content_type));
    if (state.minBytes > 0) f = f.filter(e => e.size_bytes >= state.minBytes);
    if (state.maxBytes < Infinity) f = f.filter(e => e.size_bytes <= state.maxBytes);
    if (state.staleFilter === 'stale') f = f.filter(e => e.stale);
    else if (state.staleFilter === 'fresh') f = f.filter(e => !e.stale);
    if (state.torrentFilter === 'active') f = f.filter(e => e.paths.some(p => p.has_active_torrent));
    else if (state.torrentFilter === 'paused') f = f.filter(e => e.paths.some(p => p.has_torrent && !p.has_active_torrent));
    else if (state.torrentFilter === 'none') f = f.filter(e => e.paths.every(p => p.has_torrent === false));
    // status / hidden
    f = f.filter(e => {
      const m = getMark(keyOf(e));
      if (state.statusFilter) return state.statusFilter === 'unreviewed' ? !m : m === state.statusFilter;
      if (m === 'hide' && !prefs.showHidden) return false;
      return true;
    });
    f.sort((a,b) => {
      let va = a[state.sortKey], vb = b[state.sortKey];
      if (state.sortKey === 'paths') { va = a.paths[0]?.path || ''; vb = b.paths[0]?.path || ''; }
      if (typeof va === 'number' && typeof vb === 'number') return state.sortDir === 'asc' ? va - vb : vb - va;
      va = String(va||''); vb = String(vb||'');
      return state.sortDir === 'asc' ? va.localeCompare(vb) : vb.localeCompare(va);
    });
    state.filtered = f;
  }

  // Build toolbar ONCE so typing in search never loses focus.
  const panel = document.getElementById('panel-' + id);
  panel.innerHTML =
    '<div class="toolbar">' +
      '<input type="text" class="search-input" placeholder="Search paths, type, drive, inode — or *glob* / /regex/…">' +
      '<select class="filter-select" data-f="type"><option value="">All types</option>' +
        types.map(t => '<option value="' + t + '">' + t + '</option>').join('') + '</select>' +
      (drives.length > 1 ? '<select class="filter-select" data-f="drive"><option value="">All drives</option>' +
        drives.map(d => '<option value="' + esc(d) + '">' + esc(driveShort(d)) + '</option>').join('') + '</select>' : '') +
      (META.stale_days > 0 ? '<select class="filter-select" data-f="stale"><option value="">All freshness</option><option value="stale">Stale only</option><option value="fresh">Fresh only</option></select>' : '') +
      (META.qbt_connected ? '<select class="filter-select" data-f="torrent"><option value="">All torrent states</option><option value="active">Has active torrent</option><option value="paused">Paused/inactive only</option><option value="none">No torrent</option></select>' : '') +
      '<select class="filter-select" data-f="status"><option value="">All review states</option><option value="unreviewed">Unreviewed</option><option value="keep">Keep</option><option value="del">For deletion</option><option value="hide">Hidden</option></select>' +
      '<div class="size-filter"><input type="text" data-f="min" placeholder="Min size"><span>–</span><input type="text" data-f="max" placeholder="Max size"></div>' +
      '<button class="btn small" data-clear="1" title="Reset search + all filters">Clear filters</button>' +
    '</div>' +
    '<div class="bulkbar"><span class="lbl">Bulk (filtered):</span>' +
      '<button class="btn small" data-bulk="keep">✓ Keep</button>' +
      '<button class="btn small" data-bulk="del">✗ Delete</button>' +
      '<button class="btn small" data-bulk="hide">⊘ Hide</button>' +
      '<button class="btn small" data-bulk="clear">Clear marks</button>' +
    '</div>' +
    '<div class="results"></div>';

  const searchEl = panel.querySelector('.search-input');
  const resultsEl = panel.querySelector('.results');
  const clearBtn = panel.querySelector('[data-clear]');

  // Filters/search/sort DON'T reset the page — the chosen page is kept (and shown
  // when still in range), so clearing a filter returns you to where you were.
  searchEl.addEventListener('input', () => { state.search = searchEl.value; renderResults(); });
  panel.querySelectorAll('.filter-select[data-f]').forEach(sel => {
    sel.addEventListener('change', () => {
      const f = sel.dataset.f;
      if (f === 'type') state.typeFilter = sel.value;
      else if (f === 'drive') state.driveFilter = sel.value;
      else if (f === 'stale') state.staleFilter = sel.value;
      else if (f === 'torrent') state.torrentFilter = sel.value;
      else if (f === 'status') state.statusFilter = sel.value;
      renderResults();
    });
  });
  panel.querySelectorAll('.size-filter input').forEach(inp => {
    inp.addEventListener('change', () => {
      if (inp.dataset.f === 'min') state.minBytes = parseSize(inp.value);
      else state.maxBytes = inp.value ? parseSize(inp.value) : Infinity;
      renderResults();
    });
  });
  clearBtn.addEventListener('click', () => {
    state.search = ''; state.typeFilter = ''; state.driveFilter = '';
    state.staleFilter = ''; state.torrentFilter = ''; state.statusFilter = '';
    state.minBytes = 0; state.maxBytes = Infinity;
    searchEl.value = '';
    panel.querySelectorAll('.filter-select[data-f]').forEach(s => s.value = '');
    panel.querySelectorAll('.size-filter input').forEach(i => i.value = '');
    if (activeMediaFilters.size) { activeMediaFilters.clear(); renderMediaBar(); }
    renderResults();
    toast('Filters cleared');
  });
  panel.querySelectorAll('[data-bulk]').forEach(btn => {
    btn.addEventListener('click', () => {
      applyFilters();
      const keys = state.filtered.map(keyOf);
      const act = btn.dataset.bulk;
      if (!keys.length) return toast('No rows in current filter');
      if (keys.length > 200 && !confirm(act + ' ' + keys.length + ' items?')) return;
      keys.forEach(k => { if (act === 'clear') delete marks[k]; else marks[k] = act; });
      saveMarks(); renderGlobalBar(); renderStats(); renderResults();
      toast((act === 'clear' ? 'Cleared ' : 'Marked ') + keys.length + (act === 'clear' ? '' : ' ' + act));
    });
  });

  // Row-level actions via delegation (indices into pageItems).
  resultsEl.addEventListener('click', (ev) => {
    const el = ev.target.closest('[data-act]');
    if (!el) return;
    const act = el.dataset.act;
    if (act === 'sort') { onSort(el.dataset.key); return; }
    if (act === 'page') { goPage(parseInt(el.dataset.page, 10)); return; }
    const tr = el.closest('[data-i]');
    if (!tr) return;
    const entry = state.pageItems[parseInt(tr.dataset.i, 10)];
    if (!entry) return;
    if (act === 'mark') {
      setMark(keyOf(entry), el.dataset.status);
      renderGlobalBar(); renderStats(); renderResults();
    } else if (act === 'copy') {
      const p = entry.paths[parseInt(el.dataset.p, 10)];
      if (p) copyText(p.path);
    }
  });

  // Rows-per-page select and page-jump input (change events).
  resultsEl.addEventListener('change', (ev) => {
    const el = ev.target.closest('[data-act]');
    if (!el) return;
    if (el.dataset.act === 'pagesize') {
      setPageSize(el.value === 'all' ? 'all' : parseInt(el.value, 10));
    } else if (el.dataset.act === 'pagejump') {
      const n = parseInt(el.value, 10);
      if (!isNaN(n)) goPage(n - 1); else renderResults();
    }
  });

  // Arrow keys page through the active table (when not typing in a field).
  document.addEventListener('keydown', (ev) => {
    if (currentTab !== id) return;
    const t = ev.target;
    if (t && /^(INPUT|SELECT|TEXTAREA)$/.test(t.tagName)) return;
    if (ev.key === 'ArrowRight') { goPage(state._viewPage + 1); ev.preventDefault(); }
    else if (ev.key === 'ArrowLeft') { goPage(state._viewPage - 1); ev.preventDefault(); }
  });

  function onSort(key) {
    if (state.sortKey === key) state.sortDir = state.sortDir === 'asc' ? 'desc' : 'asc';
    else { state.sortKey = key; state.sortDir = key === 'paths' ? 'asc' : 'desc'; }
    renderResults();
  }
  function _effSize() {
    return state.pageSize === 'all' ? Math.max(state.filtered.length, 1) : state.pageSize;
  }
  function goPage(p) {
    const maxP = Math.max(0, Math.ceil(state.filtered.length / _effSize()) - 1);
    state.page = Math.max(0, Math.min(p, maxP));
    renderResults();
  }
  function setPageSize(v) {
    const firstIdx = state._viewPage * _effSize();   // keep the first visible row visible
    state.pageSize = v; prefs.pageSize = v; savePrefs();
    const newSize = v === 'all' ? Math.max(state.filtered.length, 1) : v;
    state.page = Math.floor(firstIdx / newSize);
    renderResults();
  }
  function pagerHtml(viewPage, totalPages, top) {
    const f = state.filtered;
    const size = _effSize();
    const start = f.length ? viewPage * size + 1 : 0;
    const end = Math.min((viewPage + 1) * size, f.length);
    const totalSize = f.reduce((s, e) => s + e.size_bytes, 0);
    let h = '<div class="pagbar ' + (top ? 'top' : 'bottom') + '">';
    if (top) {
      h += '<span class="rpp">Rows: <select class="filter-select" data-act="pagesize">' +
        PAGE_SIZE_OPTIONS.map(o => '<option value="' + o + '"' +
          (String(o) === String(state.pageSize) ? ' selected' : '') + '>' +
          (o === 'all' ? 'All' : o) + '</option>').join('') + '</select></span>';
      h += '<span class="range">' + (f.length
            ? 'Showing ' + start.toLocaleString() + '–' + end.toLocaleString() +
              ' of ' + f.length.toLocaleString() + ' — ' + formatBytes(totalSize)
            : '0 of 0') + '</span>';
    }
    h += '<span class="nav">';
    if (totalPages > 1) {
      h += '<button class="pgbtn" data-act="page" data-page="0" ' + (viewPage === 0 ? 'disabled' : '') + ' title="First page">«</button>' +
           '<button class="pgbtn" data-act="page" data-page="' + (viewPage - 1) + '" ' + (viewPage === 0 ? 'disabled' : '') + ' title="Previous">‹</button>' +
           '<span class="page-info">Page <input class="page-jump" data-act="pagejump" value="' + (viewPage + 1) + '"> of ' + totalPages.toLocaleString() + '</span>' +
           '<button class="pgbtn" data-act="page" data-page="' + (viewPage + 1) + '" ' + (viewPage >= totalPages - 1 ? 'disabled' : '') + ' title="Next">›</button>' +
           '<button class="pgbtn" data-act="page" data-page="' + (totalPages - 1) + '" ' + (viewPage >= totalPages - 1 ? 'disabled' : '') + ' title="Last page">»</button>';
    } else {
      h += '<span class="page-info">Page 1 of 1</span>';
    }
    return h + '</span></div>';
  }

  const cols = [
    {key: 'mark', label: '', nosort: true},
    {key: 'size_bytes', label: 'Size', cls: 'size-cell'},
    {key: 'content_type', label: 'Type'},
  ];
  if (drives.length > 1) cols.push({key: 'drive', label: 'Drive'});
  cols.push({key: 'link_count', label: 'Links', cls: 'size-cell'});
  cols.push({key: 'atime_epoch', label: 'Last Access'});
  cols.push({key: 'mtime_epoch', label: 'Modified'});
  if (META.stale_days > 0) cols.push({key: 'stale', label: 'Stale'});
  cols.push({key: 'paths', label: 'Paths', nosort: true});

  function renderResults() {
    applyFilters();
    const f = state.filtered;
    const size = _effSize();
    const totalPages = Math.max(1, Math.ceil(f.length / size));
    // Keep the chosen page when still in range; otherwise show the first page —
    // but do NOT overwrite state.page, so clearing a filter restores your spot.
    const viewPage = (state.page >= 0 && state.page <= totalPages - 1) ? state.page : 0;
    state._viewPage = viewPage;
    state.pageItems = f.slice(viewPage * size, (viewPage + 1) * size);

    if (!f.length) {
      resultsEl.innerHTML = pagerHtml(0, 1, true) +
        '<div class="no-results">No matching entries</div>';
      return;
    }

    let h = pagerHtml(viewPage, totalPages, true);
    h += '<table><thead><tr>';
    cols.forEach(c => {
      const arrow = state.sortKey === c.key ? (state.sortDir === 'asc' ? ' ▲' : ' ▼') : '';
      h += '<th class="' + (c.cls||'') + (c.nosort?' nosort':'') + '"' +
           (c.nosort ? '' : ' data-act="sort" data-key="' + c.key + '"') + '>' + c.label + '<span class="arrow">' + arrow + '</span></th>';
    });
    h += '</tr></thead><tbody>';
    state.pageItems.forEach((e, i) => {
      const mk = getMark(keyOf(e));
      const cls = [e.stale ? 'stale-row' : '', mk ? 'row-' + mk : ''].filter(Boolean).join(' ');
      h += '<tr class="' + cls + '" data-i="' + i + '">';
      cols.forEach(c => {
        if (c.key === 'mark') h += '<td>' + markButtons(mk) + '</td>';
        else if (c.key === 'size_bytes') h += '<td class="size-cell">' + e.size_human + '</td>';
        else if (c.key === 'content_type') h += '<td><span class="type-badge type-' + (e.content_type||'other') + '">' + (e.content_type||'other') + '</span></td>';
        else if (c.key === 'drive') h += '<td class="drive-cell" title="' + esc(e.drive) + '">' + esc(driveShort(e.drive)) + '</td>';
        else if (c.key === 'link_count') h += '<td class="size-cell">' + e.link_count + '</td>';
        else if (c.key === 'atime_epoch') h += '<td>' + (e.atime||'') + '</td>';
        else if (c.key === 'mtime_epoch') h += '<td>' + (e.mtime||'') + '</td>';
        else if (c.key === 'stale') h += '<td>' + (e.stale ? '<span class="tag-stale">STALE</span>' : '') + '</td>';
        else if (c.key === 'paths') h += pathsCellHtml(e);
      });
      h += '</tr>';
    });
    h += '</tbody></table>';
    h += pagerHtml(viewPage, totalPages, false);
    resultsEl.innerHTML = h;
  }

  function exportCsv() {
    applyFilters();
    const rows = [['size_bytes','size_human','type','drive','links','fs_links','last_access','modified','review','path']];
    state.filtered.forEach(e => {
      const mk = getMark(keyOf(e)) || '';
      e.paths.forEach(p => {
        rows.push([e.size_bytes, e.size_human, e.content_type||'', e.drive||'', e.link_count, e.fs_link_count,
                   e.atime||'', e.mtime||'', mk, p.path]);
      });
    });
    const csv = rows.map(r => r.map(v => {
      v = String(v); return /[",\n]/.test(v) ? '"' + v.replace(/"/g,'""') + '"' : v;
    }).join(',')).join('\n');
    download('disk-' + id + '-view.csv', csv + '\n', 'text/csv');
  }

  if (!data.length) { resultsEl.innerHTML = '<div class="no-results">No entries in this category</div>'; }

  // state/goPage/setPageSize are exposed for testing; the UI drives them via events.
  return { render: renderResults, refresh: renderResults, exportCsv, state, goPage, setPageSize };
}

// ═══════════════════════════════════════════════════════════════════
//  Duplicates / cross-drive group panels
// ═══════════════════════════════════════════════════════════════════
function suggestKeeperIndex(copies) {
  // Prefer a seeded copy, then the one with the most hardlinks (the established
  // one), then most links found in-scan. Matches the CLI's keeper heuristic.
  function score(c) {
    const seeded = c.paths.some(p => p.has_active_torrent) ? 2 : (c.paths.some(p => p.has_torrent) ? 1 : 0);
    return [seeded, c.fs_link_count || 0, c.link_count || 0];
  }
  let best = 0, bs = score(copies[0]);
  for (let i = 1; i < copies.length; i++) {
    const s = score(copies[i]);
    if (s[0] > bs[0] || (s[0]===bs[0] && (s[1] > bs[1] || (s[1]===bs[1] && s[2] > bs[2])))) { best = i; bs = s; }
  }
  return best;
}
// ── Cross-drive migration-script generation (relink onto keeper branch) ──
function relTo(p, branch) {
  p = String(p); branch = String(branch || '').replace(/\/+$/, '');
  if (branch && p === branch) return '';
  if (branch && p.startsWith(branch + '/')) return p.slice(branch.length + 1);
  return baseName(p);
}
function joinPath(branch, rel) { return String(branch).replace(/\/+$/, '') + '/' + rel; }
function dirName(p) { const i = String(p).lastIndexOf('/'); return i > 0 ? p.slice(0, i) : '/'; }
function migrationScript(groups, keeperOf) {
  let sh = '#!/usr/bin/env bash\n';
  sh += '# Cross-drive consolidation generated by disk.py report on ' + new Date().toISOString() + '\n';
  sh += '# Report root: ' + META.root + '\n';
  sh += '# For each group: recreate the redundant copies as hardlinks to the kept\n';
  sh += '# inode at the SAME relative path on the kept copy\'s drive, then remove\n';
  sh += '# the source. On a mergerfs union the union path is unchanged and the\n';
  sh += '# redundant copy is freed. "ln && rm" means the source is only removed if\n';
  sh += '# the new hardlink was created (so an existing target is never clobbered).\n';
  sh += '# REVIEW before running.  (The interactive `--consolidate-cross-drive`\n';
  sh += '# does the same with extra verification.)\n\nset -u\n\n';
  let n = 0, skipped = 0;
  groups.forEach(g => {
    const ki = keeperOf(g);
    const keep = g.copies[ki], kbranch = keep.drive, ksrc = keep.paths[0].path;
    g.copies.forEach((c, i) => {
      if (i === ki) return;
      if (!kbranch || !c.drive) { sh += '# SKIP (unknown branch): ' + c.paths[0].path + '\n'; skipped++; return; }
      c.paths.forEach(p => {
        const target = joinPath(kbranch, relTo(p.path, c.drive));
        sh += 'mkdir -p ' + shellQuote(dirName(target)) + '\n';
        sh += 'ln -- ' + shellQuote(ksrc) + ' ' + shellQuote(target) + ' && rm -v -- ' + shellQuote(p.path) + '\n';
        n++;
      });
    });
  });
  return { sh, n, skipped };
}
function createGroupPanel(id, data, opts) {
  opts = opts || {};
  const state = { data, filtered: data, groupItems: [], search: '' };
  const panel = document.getElementById('panel-' + id);
  panel.innerHTML =
    '<div class="toolbar"><input type="text" class="search-input" placeholder="Search duplicate paths — or *glob* / /regex/…">' +
      (opts.crossOnly ? '<button class="btn small" id="xd-migrate-all">Migration script (all, keep suggested)</button>' : '') +
    '</div>' +
    (opts.crossOnly ? '<div class="result-count" style="color:var(--dim)">Reclaim these by relinking the redundant copy onto the kept copy\'s drive at the same path (union path unchanged). Use the buttons below, or run <code>--consolidate-cross-drive</code>.</div>' : '') +
    '<div class="result-count"></div><div class="results"></div>';
  const searchEl = panel.querySelector('.search-input');
  const resultsEl = panel.querySelector('.results');
  const countEl = panel.querySelectorAll('.result-count')[opts.crossOnly ? 1 : 0];
  if (opts.crossOnly) {
    panel.querySelector('#xd-migrate-all').addEventListener('click', () => {
      const gs = state.filtered && state.filtered.length ? state.filtered : data;
      const { sh, n } = migrationScript(gs, g => suggestKeeperIndex(g.copies));
      if (!n) return toast('Nothing to migrate');
      download('disk-crossdrive-migrate.sh', sh, 'text/x-shellscript');
    });
  }

  searchEl.addEventListener('input', () => { state.search = searchEl.value; renderResults(); });

  resultsEl.addEventListener('click', (ev) => {
    const el = ev.target.closest('[data-act]');
    if (!el) return;
    const g = parseInt(el.closest('[data-g]')?.dataset.g, 10);
    const group = state.groupItems[g];
    if (!group) return;
    if (el.dataset.act === 'copy') {
      const c = group.copies[parseInt(el.dataset.c,10)];
      const p = c && c.paths[parseInt(el.dataset.p,10)];
      if (p) copyText(p.path);
    } else if (el.dataset.act === 'mark') {
      const entry = group.copies[parseInt(el.dataset.c,10)];
      setMark(keyOf(entry), el.dataset.status);
      renderGlobalBar(); renderStats(); renderResults();
    } else if (el.dataset.act === 'migrate') {
      // Build a migration script that keeps THIS copy and relinks the others
      // onto its drive at the same relative path (then removes the sources).
      const ki = parseInt(el.dataset.c,10);
      const { sh, n } = migrationScript([group], () => ki);
      if (!n) return toast('Nothing to migrate in this group');
      download('disk-crossdrive-migrate.sh', sh, 'text/x-shellscript');
    }
  });

  function renderResults() {
    if (!data.length) { resultsEl.innerHTML = '<div class="no-results">' + (opts.emptyMsg || 'No duplicates found') + '</div>'; countEl.textContent = ''; return; }
    const matcher = makeMatcher(state.search);
    state.filtered = matcher ? data.filter(d => d.copies.some(c => c.paths.some(p => matcher(p.path)))) : data;
    state.groupItems = state.filtered;
    const totalWasted = state.filtered.reduce((s,d) => s + d.wasted_bytes, 0);
    countEl.textContent = state.filtered.length.toLocaleString() + ' group(s) — ' +
      formatBytes(totalWasted) + (opts.crossOnly ? ' reclaimable' : ' wasted');

    let h = '';
    state.filtered.forEach((d, gi) => {
      const suggest = opts.crossOnly ? suggestKeeperIndex(d.copies) : -1;
      h += '<div class="dup-group' + (d.cross_drive ? ' xd' : '') + '" data-g="' + gi + '">';
      h += '<div class="dup-header">' + d.size_human + ' × ' + d.copies.length + ' copies — ' +
           (opts.crossOnly ? 'reclaim ' : 'wasted ') + '<span class="dup">' + d.wasted_human + '</span>' +
           (d.cross_drive ? ' <span class="badge-xd">⇄ CROSS-DRIVE</span>' : '') + '</div>';
      d.copies.forEach((c, ci) => {
        const mk = getMark(keyOf(c));
        const ccls = mk === 'keep' ? ' c-keep' : (mk === 'del' ? ' c-del' : '');
        h += '<div class="dup-copy' + ccls + '">';
        h += '<div class="dup-copy-head">' + markButtons(mk, 'data-c="' + ci + '"');
        h += ' <span class="' + (ci===0 && !opts.crossOnly ? 'keep' : 'dup') + '">' + (opts.crossOnly ? 'COPY' : (ci===0?'KEEP':'DUP')) + '</span>' +
             ' <span class="drive-cell" title="' + esc(c.drive) + '">' + esc(driveShort(c.drive)) + '</span>' +
             ' <span style="color:var(--dim)">inode ' + c.inode + ' · ' + c.link_count + ' path' + (c.link_count!==1?'s':'') + '</span>' +
             (ci === suggest ? ' <span class="badge-suggest">suggested keep</span>' : '') +
             (opts.crossOnly ? ' <button class="btn small" data-act="migrate" data-c="' + ci + '">keep this → migration script</button>' : '') +
             '</div>';
        h += '<div class="paths-cell">';
        c.paths.forEach((p, pi) => {
          h += '<div class="path-line"><button class="copybtn" data-act="copy" data-c="' + ci + '" data-p="' + pi + '" title="Copy path">copy</button> ';
          h += '<span class="path-text">' + esc(p.path) + '</span>';
          if (p.has_active_torrent) h += ' <span class="tag tag-active">[T]</span>';
          else if (p.has_torrent) h += ' <span class="tag tag-paused">[P]</span>';
          else if (p.has_torrent === false) h += ' <span class="tag tag-none">[no torrent]</span>';
          h += '</div>';
        });
        h += '</div></div>';
      });
      h += '</div>';
    });
    resultsEl.innerHTML = h;
  }
  if (!data.length) renderResults();
  return { render: renderResults, refresh: renderResults };
}

// ═══════════════════════════════════════════════════════════════════
//  Tabs
// ═══════════════════════════════════════════════════════════════════
var panelControllers = {};
var currentTab = 'used';

const tabDefs = [
  { id: 'used', label: 'Used', count: DATASETS.used.length },
  { id: 'unused', label: 'Unused', count: DATASETS.unused.length },
  { id: 'mixed', label: 'Mixed', count: DATASETS.mixed.length },
  { id: 'duplicates', label: 'Duplicates', count: DATASETS.duplicates.length },
];
if (DATASETS.crossdrive.length) tabDefs.push({ id: 'crossdrive', label: 'Cross-Drive', count: DATASETS.crossdrive.length });

const tabsBar = document.getElementById('tabs-bar');
const panelsEl = document.getElementById('panels');

function selectTab(tabId) {
  currentTab = tabId;
  prefs.activeTab = tabId; savePrefs();
  document.querySelectorAll('.tab').forEach(b => b.classList.toggle('active', b.dataset.tabId === tabId));
  document.querySelectorAll('.panel').forEach(p => p.classList.toggle('active', p.id === 'panel-' + tabId));
  panelControllers[tabId].refresh();
}
function refreshActive() {
  if (currentTab !== 'duplicates' && currentTab !== 'crossdrive') panelControllers[currentTab]?.refresh();
  else panelControllers[currentTab]?.refresh();
}

tabDefs.forEach((t) => {
  const btn = document.createElement('button');
  btn.className = 'tab';
  btn.dataset.tabId = t.id;
  btn.innerHTML = t.label + '<span class="badge">' + t.count.toLocaleString() + '</span>';
  btn.onclick = () => selectTab(t.id);
  tabsBar.appendChild(btn);
  const panel = document.createElement('div');
  panel.id = 'panel-' + t.id;
  panel.className = 'panel';
  panelsEl.appendChild(panel);
});

// Build controllers (also builds each panel's toolbar DOM)
panelControllers.used = createInodePanel('used', DATASETS.used);
panelControllers.unused = createInodePanel('unused', DATASETS.unused);
panelControllers.mixed = createInodePanel('mixed', DATASETS.mixed);
panelControllers.duplicates = createGroupPanel('duplicates', DATASETS.duplicates, {});
if (DATASETS.crossdrive.length) {
  panelControllers.crossdrive = createGroupPanel('crossdrive', DATASETS.crossdrive,
    { crossOnly: true, emptyMsg: 'No cross-drive duplicates' });
}

renderGlobalBar();
renderPatternBar();
renderStats();
renderMediaBar();

// Restore last tab if still valid
let startTab = tabDefs.some(t => t.id === prefs.activeTab) ? prefs.activeTab : 'used';
selectTab(startTab);
</script>
</body>
</html>
"""


# ── Main ─────────────────────────────────────────────────────────────────────

def main():
    args = parse_args()
    orig_roots = []
    for r in args.roots:
        ar = os.path.abspath(r)
        if not os.path.isdir(ar):
            print(f"Error: {ar} is not a directory.", file=sys.stderr)
            sys.exit(1)
        if ar not in orig_roots:
            orig_roots.append(ar)

    # *report_root* is only a LABEL — the first path the user gave — used in the
    # report header/meta and terminal output, even when it's a mergerfs union we
    # scan branch-by-branch underneath. All generated files (log, cache, JSON,
    # HTML) are written to *output_dir* = the script's own directory instead, so
    # the scanned tree is never littered and read-only/union mounts still work.
    report_root = orig_roots[0]
    output_dir = _SCRIPT_DIR

    # mergerfs-aware: if a root is a union, scan the real branches instead and
    # auto-derive path mappings + media-dir expansions (see _expand_mergerfs_roots).
    scan_roots, args._mergerfs_info = _expand_mergerfs_roots(orig_roots, args)

    # ── Register Ctrl+C handler for graceful interruption ─────────────────
    _run_state["root"] = report_root
    _run_state["out_dir"] = output_dir
    _run_state["args"] = args
    signal.signal(signal.SIGINT, _sigint_handler)

    # ── Set up tee logging (stdout + stderr → terminal + log file) ────────
    log_file = None
    original_stdout = sys.stdout
    original_stderr = sys.stderr
    if not args.no_log:
        log_path = os.path.join(output_dir, "diskreport.log")
        log_file = open(log_path, "w", encoding="utf-8")
        sys.stdout = TeeWriter(original_stdout, log_file)
        sys.stderr = TeeWriter(original_stderr, log_file)

    try:
        return _run(args, scan_roots, report_root, output_dir)
    finally:
        # Restore streams and close log
        sys.stdout = original_stdout
        sys.stderr = original_stderr
        if log_file:
            log_file.close()
            print(f"  Log saved to: {log_path}")


def _run(args, roots, report_root=None, output_dir=None):
    """Main logic, separated so the tee logger wraps everything.

    *roots* is the list of resolved scan roots (already mergerfs-expanded to
    branches where applicable). *report_root* is the LABEL for what was scanned
    (the original path the user gave; defaults to roots[0]) and is recorded
    inside the reports. *output_dir* is where the report/JSON files are actually
    written — the script's own directory (defaults to _SCRIPT_DIR)."""
    if report_root is None:
        report_root = roots[0]
    if output_dir is None:
        output_dir = _SCRIPT_DIR
    _run_state["out_dir"] = output_dir
    min_dup_bytes = args.min_dup_mb * 1024 * 1024
    progress = ProgressPrinter(quiet=args.quiet)

    # ── Announce any mergerfs union expansion ────────────────────────────────
    for union, mp, branches, added in getattr(args, "_mergerfs_info", []) or []:
        print(f"\n  mergerfs union detected: {union}")
        print(f"    branches: {', '.join(branches)}")
        if added:
            print(f"    → scanning the real disks: {', '.join(added)}")
        else:
            print(f"    → (no matching sub-path on any branch; scanning as given)")

    # Publish path mappings so the torrent-lookup helpers can translate on-disk
    # paths to the paths qBittorrent reports (Docker/mergerfs setups).
    global _PATH_MAPPINGS
    _PATH_MAPPINGS = args.path_mappings

    # ── qBittorrent (optional; one or more instances, all merged) ────────────
    qbt_files = None
    if args.qbt_instances:
        n = len(args.qbt_instances)
        label = "instance" if n == 1 else "instances"
        print(f"\n  Connecting to {n} qBittorrent {label} …")
        per_instance_maps = []
        succeeded = 0
        failed = []
        for inst in args.qbt_instances:
            sec = "  (insecure: SSL verification off)" if inst["insecure"] else ""
            print(f"    • {_sanitize_url(inst['url'])}{sec}")
            try:
                client = QBittorrentClient(inst["url"], inst["user"], inst["pass"],
                                           insecure=inst["insecure"])
                client.login()
                fmap = client.get_all_torrent_files(progress)
                per_instance_maps.append(fmap)
                succeeded += 1
                print(f"      ✓ authenticated — {len(fmap):,} paths")
            except Exception as exc:
                failed.append((inst["url"], exc))
                print(f"      ⚠ failed: {exc}", file=sys.stderr)

        if failed:
            # Some/all instances unreachable. Treating a seeded file as unused is
            # dangerous (cleanup / cross-seed could act on it), so proceed only on
            # an explicit yes in a TTY; otherwise abort.
            print(f"  ⚠ {len(failed)} of {n} qBittorrent {label} could not be "
                  f"reached.", file=sys.stderr)
            if sys.stdin.isatty():
                if succeeded:
                    prompt = (f"     Continue with torrent data from the "
                              f"{succeeded} instance(s) that connected? [y/N] ")
                else:
                    prompt = "     Continue WITHOUT any torrent data? [y/N] "
                try:
                    ans = input(prompt).strip().lower()
                except (EOFError, KeyboardInterrupt):
                    ans = ""
                if ans not in ("y", "yes"):
                    print("  Aborted.", file=sys.stderr)
                    sys.exit(1)
            else:
                # Non-interactive: abort — a configured instance being unreachable
                # means the evaluation would be incomplete (and unsafe to act on).
                print("     Non-interactive mode — aborting (a configured "
                      "qBittorrent instance was unreachable).", file=sys.stderr)
                sys.exit(1)

        if per_instance_maps:
            qbt_files = _merge_qbt_file_maps(per_instance_maps)
            if succeeded > 1:
                print(f"  qBittorrent: merged {len(qbt_files):,} unique paths "
                      f"from {succeeded} instances (source not differentiated)")
            else:
                print(f"  qBittorrent: {len(qbt_files):,} unique paths across all torrents")
            if args.all_torrents:
                print(f"  Torrent filter: ALL torrents count as active (--all-torrents)")
            else:
                print(f"  Torrent filter: active only (seeding/downloading/checking); "
                      f"paused/errored ignored. Use --all-torrents to include all.")
        else:
            # All instances failed but the user chose to continue in a TTY.
            print(f"  Continuing without torrent data.\n", file=sys.stderr)

        if _PATH_MAPPINGS:
            print(f"  Path mappings (on-disk → qBittorrent):")
            for local, qbt in _PATH_MAPPINGS:
                print(f"    {local} → {qbt}")

    if args.media_dirs:
        if len(args.media_dirs) == 1:
            print(f"  Media dir: {args.media_dirs[0]}")
        else:
            print(f"  Media dirs ({len(args.media_dirs)}):")
            for md in args.media_dirs:
                print(f"    • {md}")
        print(f"    (mixed inodes with orphans only inside a media dir → 'used')")
        if args.keep_unseeded_media:
            print(f"    (non-seeded files with no other hardlinks here → 'used'; "
                  f"--no-keep-unseeded-media to treat them as unused)")
        else:
            print(f"    (--no-keep-unseeded-media set: non-seeded single-link files "
                  f"here → 'unused')")

    # ── Hash cache ────────────────────────────────────────────────────────────
    if args.hash_db:
        cache = HashCache(args.hash_db, force_rehash=args.rehash)
        mode = "rehash" if args.rehash else "enabled"
        print(f"  Hash cache: {args.hash_db} ({mode})")
    else:
        cache = NoCache()
        print(f"  Hash cache: disabled (use --hash-db FILE to enable)")

    # ── Scan ─────────────────────────────────────────────────────────────────
    if len(roots) == 1:
        print(f"\n  Scanning {report_root} …")
    else:
        print(f"\n  Scanning {len(roots)} roots (cross-drive comparison):")
        for r in roots:
            print(f"    • {r}")
    t0 = time.monotonic()

    if args.ignore_ext_set:
        print(f"  Ignoring extensions: {', '.join(sorted(args.ignore_ext_set))}")
    inodes, dir_sizes, errors = scan_roots(
        roots, args.one_filesystem, progress, args.ignore_ext_set,
        root_branches=getattr(args, "_mergerfs_root_branches", None))
    t_scan = time.monotonic() - t0
    print(f"  Scan complete: {len(inodes):,} unique inodes in {t_scan:.1f}s")

    # Update run state for graceful interruption
    _run_state["inodes"] = inodes
    _run_state["errors"] = errors
    _run_state["qbt_files"] = qbt_files

    # Prune stale cache entries
    if isinstance(cache, HashCache):
        all_paths = set()
        for info in inodes.values():
            all_paths.update(info["paths"])
        pruned = cache.prune_missing(all_paths)
        if pruned:
            print(f"  Hash cache: pruned {pruned:,} stale entries")

    print(f"  Detecting duplicates (hash: {HASH_NAME}, max {args.workers} reader(s) "
          f"per SSD; 1 per spinning disk) …")
    t1 = time.monotonic()
    dupes = find_duplicates(inodes, min_dup_bytes, args.workers, progress, cache)
    t_dup = time.monotonic() - t1
    print(f"  Duplicate scan complete in {t_dup:.1f}s")
    _run_state["dupes"] = dupes

    # Cache stats
    if cache.total_lookups > 0:
        hit_pct = (cache.hits / cache.total_lookups) * 100
        print(f"  Hash cache: {cache.hits:,} hits, {cache.misses:,} misses "
              f"({hit_pct:.0f}% hit rate)")

    # ── Terminal report ───────────────────────────────────────────────────────
    print_report(report_root, inodes, dir_sizes, dupes, errors, args.top, qbt_files,
                 stale_days=args.stale_days)

    active_only = not args.all_torrents

    # ── Deduplication ─────────────────────────────────────────────────────────
    if args.fix or args.auto_fix:
        if not dupes:
            print(f"\n  No duplicates found — nothing to fix.\n")
        else:
            run_dedup(
                dupes,
                interactive=(args.fix and not args.auto_fix),
                dry_run=args.dry_run,
                qbt_files=qbt_files,
                inodes=inodes,
            )
    elif dupes and not args.quiet:
        print(f"  Dedup skipped (--no-fix). Re-run without --no-fix to fix duplicates.\n")

    # ── Cross-drive duplicates (same content on different drives) ────────────
    # These can't be hardlink-consolidated (EXDEV). Always REPORT them; only act
    # on them (delete a redundant copy) with the explicit --consolidate-cross-drive
    # flag, and never without a prompt.
    write_cross_drive_report(report_root, dupes, qbt_files, out_dir=output_dir)
    if args.consolidate_cross_drive:
        run_cross_drive_consolidate(
            dupes, qbt_files, active_only=active_only,
            media_dirs=args.media_dirs, dry_run=args.dry_run,
        )

    # ── Orphan path cleanup (on by default) ─────────────────────────────────
    if (args.cleanup_orphans or args.auto_cleanup) and qbt_files is not None:
        if not args.media_dirs:
            print(f"  ⚠ Orphan cleanup requires --media-dir to distinguish "
                  f"media paths from true orphans.  Skipping.\n", file=sys.stderr)
        else:
            run_orphan_cleanup(
                inodes, qbt_files, args.media_dirs,
                active_only=active_only,
                interactive=(args.cleanup_orphans and not args.auto_cleanup),
                dry_run=args.dry_run,
            )
    elif (args.cleanup_orphans or args.auto_cleanup) and qbt_files is None:
        if not args.quiet:
            print(f"  Orphan cleanup skipped (no qBittorrent connection).\n")

    # ── Empty folder cleanup (on by default) ──────────────────────────────
    # A mergerfs union mirrors its directory skeleton across branches, so the
    # per-branch scan roots that came from expanding one union are a single
    # "mirror group": a folder is only empty if empty on ALL of them, and must be
    # removed from all of them together. Non-expanded roots are independent.
    if args.cleanup_empty or args.auto_cleanup_empty:
        empty_interactive = args.cleanup_empty and not args.auto_cleanup_empty
        groups = []
        grouped = set()
        for _union, _mp, _branches, added in getattr(args, "_mergerfs_info", []) or []:
            if added:
                groups.append(added)
                grouped.update(added)
        for r in roots:
            if r not in grouped:
                groups.append([r])
        for group in groups:
            run_empty_dir_cleanup(
                group,
                interactive=empty_interactive,
                dry_run=args.dry_run,
            )

    # ── mergerfs skeleton repair (after empty-dir cleanup) ─────────────────
    # Ensure every directory exists on every branch of each expanded union, so
    # any func.mkdir=epall gap is fixed and file placement stays correct.
    if getattr(args, "repair_skeleton", True):
        for _union, _mp, branches, _added in getattr(args, "_mergerfs_info", []) or []:
            sub = os.path.relpath(_union, _mp)
            subroots = [b if sub == "." else os.path.normpath(os.path.join(b, sub))
                        for b in branches]
            run_mergerfs_skeleton_repair(subroots, dry_run=args.dry_run)

    # ── Cross-seed hardlinks (opt-in) ──────────────────────────────────────
    if args.cross_seed:
        if qbt_files is None:
            print(f"  ⚠ --cross-seed requires a qBittorrent connection to classify "
                  f"files as unused.  Skipping.\n", file=sys.stderr)
        else:
            run_cross_seed_links(
                report_root, inodes, qbt_files,
                media_dirs=args.media_dirs,
                active_only=active_only,
                dry_run=args.dry_run,
                keep_unseeded_media=args.keep_unseeded_media,
            )

    # ── Write JSON + HTML reports (after all cleanups for accurate data) ──
    print(f"{'─' * W}")
    print(f"  WRITING REPORTS → {output_dir}")
    print(f"{'─' * W}")
    write_reports(report_root, inodes, dupes, errors, qbt_files, args.media_dirs,
                  active_only, stale_days=args.stale_days,
                  keep_unseeded_media=args.keep_unseeded_media, out_dir=output_dir)
    write_html_report(report_root, inodes, dupes, qbt_files, args.media_dirs,
                      active_only, stale_days=args.stale_days,
                      keep_unseeded_media=args.keep_unseeded_media, out_dir=output_dir)
    print()

    return 0


if __name__ == "__main__":
    sys.exit(main())
