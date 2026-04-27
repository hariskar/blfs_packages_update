#!/usr/bin/env python3
"""
Diagnostic for the OpenSSH version mismatch between the Python and C BLFS
version checkers.

Reports every place 'openssh' appears in the book that the Python parser
COULD see (section titles + <a href> anchors), so we can identify why
v3.1's _best() upgrade isn't catching 10.2p1.
"""
import re
import sys
from pathlib import Path
from bs4 import BeautifulSoup

BOOK = sys.argv[1] if len(sys.argv) > 1 \
       else "/sources/blfs/BLFS-BOOK-13.0-systemd-nochunks.html"

# Same regexes as v3.1
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
    r"[-_.][vV]?(?P<ver>\d[0-9A-Za-z.+~]*?)"
    + _TRAILING + _EXT + r"$",
    re.IGNORECASE,
)
SECT_RE = re.compile(
    r"\b(?:Introduction to |Building )?"
    r"(?P<name>[A-Za-z][A-Za-z0-9._+-]*?)"
    r"-[vV]?(?P<ver>\d[0-9A-Za-z.+~]*)"
)

html = Path(BOOK).read_text(encoding="utf-8")
print(f"Loaded {len(html):,} bytes from {BOOK}")
print()

# Quick text grep first
hits = [(i+1, line) for i, line in enumerate(html.splitlines())
        if "openssh" in line.lower() and re.search(r"\d+\.\d+p\d", line)]
print(f"=== Lines mentioning openssh + p-versioned tag ({len(hits)} total) ===")
for lineno, line in hits[:30]:
    print(f"  {lineno}: {line.strip()[:200]}")
print()

soup = BeautifulSoup(html, "lxml")

# Section-title pass
print("=== Section-title pass: every sect1/sect2 whose title contains 'ssh' ===")
for sect in soup.select("div.sect1, div.sect2"):
    h = sect.find(["h1", "h2", "h3"])
    if not h:
        continue
    title = h.get_text(" ", strip=True)
    if "ssh" not in title.lower():
        continue
    m = SECT_RE.search(title)
    parsed = f"name={m.group('name')!r} ver={m.group('ver')!r}" if m else "(no regex match)"
    print(f"  title: {title!r}")
    print(f"    -> {parsed}")
print()

# Anchor pass
print("=== Anchor pass: every <a href> whose basename mentions ssh ===")
seen = {}
for a in soup.find_all("a", href=True):
    bn = a["href"].rstrip("/").split("/")[-1]
    if "ssh" not in bn.lower():
        continue
    mm = TARBALL_RE.match(bn)
    parsed = f"name={mm.group('name')!r} ver={mm.group('ver')!r}" if mm else "(NO match)"
    print(f"  href basename: {bn!r}")
    print(f"    -> {parsed}")
    if mm:
        seen.setdefault(mm.group('name').lower(), []).append(mm.group('ver'))

print()
print("=== What the parser would store for 'openssh' ===")
for name, vers in seen.items():
    print(f"  {name}: versions seen = {vers}")
