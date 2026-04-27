#!/usr/bin/env python3
"""
LFS/BLFS version checker  (v3.0)

Compares tarballs in a local source directory against the versions listed in
the BLFS HTML book and reports packages that have a newer upstream version.

Improvements over v2:
  • Structural parse of the BLFS book (reads <h1 class="sect1"> headers and
    package download <div>s instead of scraping every <a href>).
  • Name-alias map handles BLFS/tarball naming mismatches (ICU ↔ icu4c,
    LMDB ↔ lmdb, mit-krb5 ↔ krb5, etc.).
  • HTTP caching: --online fetches at most once per 24h into ~/.cache/.
  • --package NAME to query a single package.
  • Proper aligned output table with header row.
  • Exit code 1 when updates are available (useful for cron / prompt / CI).

Usage:
  LFS_version_check.py [options]

Options:
  --online          Force fetch from live URL (honours 24h cache)
  --offline         Force read local HTML file
  --refresh         Bypass cache and re-download even if cached copy is fresh
  --src-dir DIR     Source directory to scan           (default: /sources/blfs)
  --html-file FILE  Local BLFS HTML file               (default: auto)
  --package NAME    Check only this package
  --up-to-date      Also list packages that are current
  --no-color        Disable ANSI colour output
  -h, --help        Show this help
"""

from __future__ import annotations

import argparse
import os
import re
import sys
import time
import urllib.request
from pathlib import Path

from bs4 import BeautifulSoup
from packaging import version as pkg_version

# ── CONFIG ────────────────────────────────────────────────────────────────────

BLFS_VERSION = "13.0-systemd"
DEFAULT_SRC  = "/sources/blfs"
DEFAULT_HTML = f"/sources/blfs/BLFS-BOOK-{BLFS_VERSION}-nochunks.html"
BLFS_URL     = (
    f"https://www.linuxfromscratch.org/blfs/downloads/stable-systemd/"
    f"BLFS-BOOK-{BLFS_VERSION}-nochunks.html"
)

CACHE_DIR    = Path.home() / ".cache" / "blfs-version-check"
CACHE_FILE   = CACHE_DIR / f"BLFS-BOOK-{BLFS_VERSION}-nochunks.html"
CACHE_TTL    = 24 * 3600   # 24 hours

# Map tarball-basename → BLFS package key.
# Extend this when a legitimate package pair fails to match.
NAME_ALIASES: dict[str, str] = {
    "icu4c":               "icu",
    "mit-krb5":            "krb5",
    "mitkrb":              "krb5",
    "linux-pam":           "linux-pam",
    "lsb-tools":           "lsb-tools",
    "openjdk":             "openjdk",
    "jdk":                 "openjdk",
    "lmdb":                "lmdb",
    "lvm2":                "lvm2",
    "node":                "nodejs",
    "tk8.6":               "tk",
    "sqlite-autoconf":     "sqlite",
    "qt-everywhere-src":   "qt",
    "alsa-lib":            "alsa-lib",
    "boost":               "boost",
    "libreoffice":         "libreoffice",
    "postgresql":          "postgresql",
    "rustc":               "rust",
    "cmake":               "cmake",
    "wayland":             "wayland",
    "pulseaudio":          "pulseaudio",
    "webkitgtk":           "webkitgtk",
    "fontconfig":          "fontconfig",
    "libjpeg-turbo":       "libjpeg-turbo",
    "harfbuzz":            "harfbuzz",
    "gnutls":              "gnutls",
    "openssh":             "openssh",
    "openvpn":             "openvpn",
    "openldap":            "openldap",
}

# Reject (name, version) matches when the version matches a known-bogus
# pattern. Use this for upstream entries the BLFS book refers to but that
# are NOT the real upstream of this package (e.g. python-libxslt bindings
# are versioned as 2.0xxxxx — six-digit padded — and get misattributed to
# libxslt itself). Patterns are matched against the parsed version string.
#
# A regex pattern is preferred over hardcoding exact versions so that future
# bogus releases following the same scheme (e.g. 2.003001) are also ignored
# without script changes — while LEGITIMATE libxslt versions like 1.1.45 or
# 1.1.46 continue to be accepted.
UPSTREAM_VERSION_IGNORE: dict[str, list[re.Pattern[str]]] = {
    # python-libxslt uses zero-padded six-digit minor (2.003000, 2.003001…)
    "libxslt": [re.compile(r"^2\.\d{6}$")],
}

# ── ANSI COLOURS ──────────────────────────────────────────────────────────────

class C:
    RESET  = "\033[0m"
    BOLD   = "\033[1m"
    DIM    = "\033[2m"
    RED    = "\033[31m"
    YELLOW = "\033[33m"
    GREEN  = "\033[32m"
    CYAN   = "\033[36m"
    WHITE  = "\033[97m"
    MAGENTA= "\033[35m"

    @classmethod
    def disable(cls) -> None:
        for attr in ("RESET","BOLD","DIM","RED","YELLOW","GREEN","CYAN","WHITE","MAGENTA"):
            setattr(cls, attr, "")


def _sep(char: str = "─", width: int = 72) -> str:
    return C.DIM + char * width + C.RESET


def _info(tag: str, msg: str) -> None:
    print(f"{C.DIM}[{tag}]{C.RESET}  {msg}")


def _warn(msg: str) -> None:
    print(f"{C.RED}[warn]{C.RESET}  {msg}", file=sys.stderr)


# ── TARBALL REGEX ─────────────────────────────────────────────────────────────

_EXT = r"\.(?:tar\.(?:gz|bz2|xz|lz|lzma|zst)|tgz)"

_TRAILING = (
    r"(?:[-_.](?:"
    r"src|source[s]?|bin|release|stable|docs?|nodocs|b2|nochunks|htmldocs|manpages|"
    r"chromium[_-]method[-\d]*|upstream[_-]fix[-\d]*|security[_-]fix(?:es)?[-\d]*|"
    r"consolidated[-\d]*|i18n[-\d]*|ipv6[_\w]*|cmake\d*[_-]fixes[-\d]*|"
    r"contribs[_\w]*|linux[-\w]*|x86_64[-\w]*|[a-z]{2}(?:_[A-Z]{2})?"
    r")[-\w]*)?"
)

TARBALL_RE = re.compile(
    r"^(?P<name>[A-Za-z0-9][A-Za-z0-9._+-]*?)"
    r"[-_.]"
    r"[vV]?(?P<ver>\d[0-9A-Za-z.+~]*?)"
    + _TRAILING + _EXT + r"$",
    re.IGNORECASE,
)

# ── HELPERS ───────────────────────────────────────────────────────────────────

def _normalise(name: str) -> str:
    """Lowercase + resolve alias."""
    key = name.lower()
    return NAME_ALIASES.get(key, key)


def _strip_suffix(ver: str) -> str:
    return re.sub(
        r"[-_.](?:src|source[s]?|bin|release|stable|docs?|nochunks|htmldocs|"
        r"manpages|chromium|upstream|security|consolidated|i18n).*$",
        "", ver, flags=re.IGNORECASE,
    )


def _best(existing: str | None, candidate: str) -> str:
    if existing is None:
        return candidate
    try:
        if pkg_version.parse(candidate) > pkg_version.parse(existing):
            return candidate
    except pkg_version.InvalidVersion:
        pass
    return existing


# ── HTML LOADING (with cache) ─────────────────────────────────────────────────

def _cache_is_fresh() -> bool:
    if not CACHE_FILE.is_file():
        return False
    age = time.time() - CACHE_FILE.stat().st_mtime
    return age < CACHE_TTL


def load_html(html_file: str, force_online: bool, refresh: bool) -> str:
    # Offline path: local book file takes priority unless --online
    if not force_online and Path(html_file).is_file():
        _info("html ", f"local file: {C.CYAN}{html_file}{C.RESET}")
        with open(html_file, encoding="utf-8") as fh:
            return fh.read()

    # Online path: check cache first
    CACHE_DIR.mkdir(parents=True, exist_ok=True)
    if not refresh and _cache_is_fresh():
        age = int((time.time() - CACHE_FILE.stat().st_mtime) / 60)
        _info("html ", f"cached ({age}m old): {C.CYAN}{CACHE_FILE}{C.RESET}")
        return CACHE_FILE.read_text(encoding="utf-8")

    _info("html ", f"fetching: {C.CYAN}{BLFS_URL}{C.RESET}")
    req = urllib.request.Request(
        BLFS_URL,
        headers={"User-Agent": "LFS-version-checker/3.0 (python urllib)"},
    )
    with urllib.request.urlopen(req, timeout=60) as resp:
        data = resp.read().decode("utf-8", errors="replace")

    try:
        CACHE_FILE.write_text(data, encoding="utf-8")
        _info("html ", f"cached to: {C.CYAN}{CACHE_FILE}{C.RESET}")
    except OSError as e:
        _warn(f"could not write cache: {e}")

    return data


# ── STRUCTURAL BLFS PARSER ────────────────────────────────────────────────────

# Section header like:   "Introduction to curl-8.12.0"
#                        "curl-8.12.0"
#                        "Building OpenSSH-9.9p2"
_SECT_TITLE_RE = re.compile(
    r"\b(?:Introduction to |Building )?"
    r"(?P<name>[A-Za-z][A-Za-z0-9._+-]*?)"
    r"-[vV]?(?P<ver>\d[0-9A-Za-z.+~]*)"
)


def _is_ignored_upstream(name: str, ver: str) -> bool:
    """True if (name, ver) matches a UPSTREAM_VERSION_IGNORE pattern."""
    patterns = UPSTREAM_VERSION_IGNORE.get(name)
    if not patterns:
        return False
    return any(p.match(ver) for p in patterns)


def parse_blfs_versions(html: str) -> dict[str, str]:
    """
    Structural parse of the BLFS book.

    Strategy:
      1. Walk every <div class="sect1"> (each package section).
      2. Extract name+version from its <h1>/<h2> title text.
      3. Fall back to the first download <a> whose href basename is a tarball
         when the title doesn't contain a version (e.g. some meta-sections).
    """
    try:
        soup = BeautifulSoup(html, "lxml")
    except Exception:
        soup = BeautifulSoup(html, "html.parser")

    packages: dict[str, str] = {}

    # Primary: structural sections
    for sect in soup.select("div.sect1, div.sect2"):
        header = sect.find(["h1", "h2", "h3"])
        if not header:
            continue
        title = header.get_text(" ", strip=True)

        m = _SECT_TITLE_RE.search(title)
        if m:
            name = _normalise(m.group("name"))
            ver  = _strip_suffix(m.group("ver"))
            if re.search(r"[A-Za-z]", name) and not _is_ignored_upstream(name, ver):
                packages[name] = _best(packages.get(name), ver)
            continue

        # Fallback: scan the section's download links
        for a in sect.select("a[href]"):
            basename = a["href"].rstrip("/").split("/")[-1]
            mm = TARBALL_RE.match(basename)
            if mm:
                name = _normalise(mm.group("name"))
                ver  = _strip_suffix(mm.group("ver"))
                if re.search(r"[A-Za-z]", name) and not _is_ignored_upstream(name, ver):
                    packages[name] = _best(packages.get(name), ver)
                    break

    # Secondary sweep: generic anchors, for items missed by sectioning
    # (BLFS sometimes lists supporting packages only in body text)
    for a in soup.find_all("a", href=True):
        basename = a["href"].rstrip("/").split("/")[-1]
        mm = TARBALL_RE.match(basename)
        if mm:
            name = _normalise(mm.group("name"))
            ver  = _strip_suffix(mm.group("ver"))
            if (re.search(r"[A-Za-z]", name)
                    and name not in packages
                    and not _is_ignored_upstream(name, ver)):
                packages[name] = ver

    return packages


# InfoZip's tarballs use a smushed `zip<digits>` / `unzip<digits>` form
# (e.g. zip30.tar.gz = zip 3.0, unzip60.tar.gz = unzip 6.0).  Each digit
# in the run is one component of the version: 30 → 3.0, 614 → 6.1.4.
_INFOZIP_RE = re.compile(
    r"^(?P<name>(?:un)?zip)(?P<digits>\d+)\.(?:tar\.\w+|tgz)$",
    re.IGNORECASE,
)


def _infozip_version(digits: str) -> str:
    """30 → '3.0', 614 → '6.1.4', 6 → '6'."""
    return ".".join(digits) if len(digits) > 1 else digits


# ── LOCAL DIR PARSER ──────────────────────────────────────────────────────────

def parse_local_versions(src_dir: str) -> tuple[dict[str, str], list[str]]:
    """Return ({name: highest_version}, skipped_filenames)."""
    local: dict[str, str] = {}
    skipped: list[str] = []

    try:
        entries = os.listdir(src_dir)
    except FileNotFoundError:
        _warn(f"source directory not found: {src_dir}")
        return local, skipped

    for fname in entries:
        # Special case: InfoZip's name+version smushed format
        iz = _INFOZIP_RE.match(fname)
        if iz:
            name = _normalise(iz.group("name"))
            ver  = _infozip_version(iz.group("digits"))
            local[name] = _best(local.get(name), ver)
            continue

        m = TARBALL_RE.match(fname)
        if not m:
            if re.search(r"\.(tar\.|tgz)", fname, re.IGNORECASE):
                skipped.append(fname)
            continue

        name = _normalise(m.group("name"))
        ver  = _strip_suffix(m.group("ver"))

        if not re.search(r"[A-Za-z]", name):
            skipped.append(fname)
            continue

        local[name] = _best(local.get(name), ver)

    return local, skipped


# ── VERSION COMPARISON ────────────────────────────────────────────────────────

def _implausible_jump(lver: str, rver: str) -> bool:
    """
    Detect bogus upstream matches caused by parser collisions between a
    package and its language bindings / unrelated tarballs.

    Rule: if the integer major component jumps by more than 5, or the total
    digit count of the version changes by more than 3, treat the upstream
    version as suspect. Example catches:
      libxslt 1.1.45 → 2.003000   (major +1, digits 5→7, jump=2)
        ^ this is actually caught by digit count 6→7 being within 3, but
          the numeric value 1.1.45 vs 2.003000 = 2003000 is > 1000x larger.
    """
    def _digits(v: str) -> int:
        return sum(c.isdigit() for c in v)

    def _first_num(v: str) -> int:
        m = re.match(r"(\d+)", v)
        return int(m.group(1)) if m else 0

    if abs(_first_num(rver) - _first_num(lver)) > 5:
        return True
    if abs(_digits(rver) - _digits(lver)) > 3:
        return True
    # Ratio check: upstream shouldn't be orders of magnitude "bigger" when
    # interpreted as a flat integer (catches 2.003000 vs 1.1.45).
    try:
        li = int(re.sub(r"\D", "", lver) or "0")
        ri = int(re.sub(r"\D", "", rver) or "0")
        if li and ri / li > 100:
            return True
    except (ValueError, ZeroDivisionError):
        pass
    return False


def compare_versions(
    local: dict[str, str],
    upstream: dict[str, str],
) -> tuple[dict[str, tuple[str, str]], dict[str, str], list[tuple[str, str, str]]]:
    """
    Returns:
      updates   — {name: (local_ver, upstream_ver)}  newer upstream
      uptodate  — {name: ver}                         local is current
      suspects  — [(name, lver, rver), …]             implausible jumps skipped
    """
    updates:  dict[str, tuple[str, str]]     = {}
    uptodate: dict[str, str]                 = {}
    suspects: list[tuple[str, str, str]]     = []

    for name, lver in local.items():
        rver = upstream.get(name)
        if rver is None:
            continue
        try:
            if pkg_version.parse(rver) > pkg_version.parse(lver):
                if _implausible_jump(lver, rver):
                    suspects.append((name, lver, rver))
                else:
                    updates[name] = (lver, rver)
            else:
                uptodate[name] = lver
        except pkg_version.InvalidVersion:
            pass

    return updates, uptodate, suspects


# ── OUTPUT FORMATTING ─────────────────────────────────────────────────────────

def print_table(
    title: str,
    rows: list[tuple[str, str, str]],    # (name, col2, col3)
    *, col_headers: tuple[str, str, str],
    col_colors:   tuple[str, str, str]   = ("", "", ""),
    arrow: str = "→",
) -> None:
    if not rows:
        return

    # Clean colour bytes out for width calculation
    def w(s: str) -> int:
        return len(re.sub(r"\033\[[0-9;]*m", "", s))

    nw = max(max(w(r[0]) for r in rows), w(col_headers[0]))
    lw = max(max(w(r[1]) for r in rows), w(col_headers[1]))
    rw = max(max(w(r[2]) for r in rows), w(col_headers[2]))

    # Header
    print(f"  {C.BOLD}{col_headers[0]:<{nw}}  "
          f"{col_headers[1]:<{lw}}  {' ':^{len(arrow)}}  "
          f"{col_headers[2]:<{rw}}{C.RESET}")
    print(f"  {C.DIM}{'─'*nw}  {'─'*lw}  {'─'*len(arrow)}  {'─'*rw}{C.RESET}")

    # Rows
    c1, c2, c3 = col_colors
    for name, a, b in rows:
        print(
            f"  {c1}{name:<{nw}}{C.RESET}  "
            f"{c2}{a:<{lw}}{C.RESET}  {arrow}  "
            f"{c3}{b:<{rw}}{C.RESET}"
        )


# ── CLI ───────────────────────────────────────────────────────────────────────

def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="LFS_version_check.py",
        description="Compare local BLFS source tarballs against the upstream BLFS book.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    mode = p.add_mutually_exclusive_group()
    mode.add_argument("--online",  action="store_true",
                      help="force fetch from live URL (honours 24h cache)")
    mode.add_argument("--offline", action="store_true",
                      help="force read local HTML file")

    p.add_argument("--refresh",   action="store_true",
                   help="bypass cache and re-download even if fresh")
    p.add_argument("--src-dir",   default=DEFAULT_SRC,  metavar="DIR",
                   help=f"source directory to scan (default: {DEFAULT_SRC})")
    p.add_argument("--html-file", default=DEFAULT_HTML, metavar="FILE",
                   help=f"local BLFS HTML file (default: {DEFAULT_HTML})")
    p.add_argument("--package",   metavar="NAME",
                   help="check only this single package")
    p.add_argument("--up-to-date", action="store_true",
                   help="also list packages that are current")
    p.add_argument("--no-color",  action="store_true",
                   help="disable ANSI colour output")
    return p


# ── MAIN ──────────────────────────────────────────────────────────────────────

def main() -> int:
    args = build_parser().parse_args()

    if args.no_color or not sys.stdout.isatty():
        C.disable()

    if args.offline and not Path(args.html_file).is_file():
        _warn(f"--offline set but file not found: {args.html_file}")
        return 2

    print(_sep())

    # 1. Load BLFS book
    try:
        html = load_html(
            args.html_file,
            force_online=args.online,
            refresh=args.refresh,
        )
    except Exception as exc:
        _warn(f"could not load BLFS HTML: {exc}")
        return 2

    upstream = parse_blfs_versions(html)
    _info("blfs ", f"{C.BOLD}{len(upstream)}{C.RESET} packages found in book")

    # 2. Parse local dir
    local, skipped = parse_local_versions(args.src_dir)
    _info("local", f"{C.BOLD}{len(local)}{C.RESET} packages found in {args.src_dir}")

    # 3. Single-package query mode
    if args.package:
        key = _normalise(args.package)
        print(_sep())
        lv = local.get(key)
        rv = upstream.get(key)
        print(f"{C.BOLD}Package:{C.RESET}  {C.WHITE}{key}{C.RESET}")
        print(f"  local:     {C.YELLOW}{lv or '(not installed)'}{C.RESET}")
        print(f"  upstream:  {C.GREEN}{rv or '(not in BLFS)'}{C.RESET}")
        if lv and rv:
            try:
                if pkg_version.parse(rv) > pkg_version.parse(lv):
                    print(f"  status:    {C.YELLOW}update available{C.RESET}")
                    print(_sep())
                    return 1
                else:
                    print(f"  status:    {C.GREEN}up to date{C.RESET}")
            except pkg_version.InvalidVersion:
                print(f"  status:    {C.RED}version parse error{C.RESET}")
        print(_sep())
        return 0

    # 4. Full compare
    updates, uptodate, suspects = compare_versions(local, upstream)

    # 5. Skipped files (before tables so they don't get buried)
    if skipped:
        _warn(f"{len(skipped)} file(s) skipped (unparseable names):")
        for s in sorted(skipped):
            print(f"  {C.DIM}• {s}{C.RESET}", file=sys.stderr)

    if suspects:
        _warn(f"{len(suspects)} suspicious upstream match(es) hidden "
              f"(likely BLFS parser collision):")
        for n, lv, rv in sorted(suspects):
            print(f"  {C.DIM}• {n}:  local {lv}  vs  upstream {rv}{C.RESET}",
                  file=sys.stderr)

    # 6. Updates table
    print(_sep())
    print(f"{C.BOLD}Packages with newer BLFS versions: "
          f"{C.YELLOW}{len(updates)}{C.RESET}")
    print()
    if updates:
        rows = [(n, lv, rv) for n, (lv, rv) in sorted(updates.items())]
        print_table(
            "Updates",
            rows,
            col_headers=("Package", "Local", "Upstream"),
            col_colors=(C.WHITE, C.YELLOW, C.GREEN),
        )
    else:
        print(f"  {C.GREEN}✔  all matched packages are up to date{C.RESET}")

    # 7. Up-to-date table (opt-in)
    if args.up_to_date and uptodate:
        print()
        print(_sep())
        print(f"{C.BOLD}Packages already up to date: "
              f"{C.GREEN}{len(uptodate)}{C.RESET}")
        print()
        rows = [(n, v, "✔") for n, v in sorted(uptodate.items())]
        print_table(
            "Current",
            rows,
            col_headers=("Package", "Version", "Status"),
            col_colors=(C.DIM, C.DIM, C.GREEN),
            arrow=" ",
        )

    # 8. Footer
    total = len(updates) + len(uptodate)
    unmatched = len(local) - total
    print()
    print(_sep())
    print(
        f"{C.BOLD}Summary:{C.RESET}  "
        f"{C.YELLOW}{len(updates)} update(s){C.RESET}  •  "
        f"{C.GREEN}{len(uptodate)} current{C.RESET}  •  "
        f"{C.DIM}{unmatched} unmatched  "
        f"(of {len(local)} local){C.RESET}"
    )
    print(_sep())

    # Exit 1 if updates are available — useful for cron / shell prompts / CI
    return 1 if updates else 0


if __name__ == "__main__":
    sys.exit(main())
