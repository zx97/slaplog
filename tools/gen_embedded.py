#!/usr/bin/env python3
"""Splice LICENSE and doc/slaplog.md into embedded.hpp.

`embedded.hpp` carries two raw string literals that back `slaplog -l` and
`slaplog -D`.  Keeping those two copies in step with their sources by hand is
exactly what let them drift apart (131 differing lines at v3.8.0, each side
holding changes the other lacked), so they are no longer maintained by hand:

    doc/slaplog.md   is the source of the documentation (a real Markdown file:
                     preview, tables, GitHub rendering)
    LICENSE          is the source of the licence text
    tools/embedded.hpp.in   owns the C++ skeleton
    embedded.hpp     is GENERATED here

Usage:
    tools/gen_embedded.py            rewrite embedded.hpp
    tools/gen_embedded.py --check    exit 1 if embedded.hpp is stale

The template and the sources are plain UTF-8; a source containing the
raw-string terminator would break the C++ literal, so that is refused.
"""

import pathlib
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent
TEMPLATE = ROOT / "tools" / "embedded.hpp.in"
OUTPUT = ROOT / "embedded.hpp"
TERMINATOR = ')EMBED"'

# Placeholder -> file whose contents replace it.
SOURCES = {
    "@LICENSE@": ROOT / "LICENSE",
    "@DOC@": ROOT / "doc" / "slaplog.md",
}


def render() -> str:
    """The embedded.hpp that the current sources should produce."""
    text = TEMPLATE.read_text(encoding="utf-8")
    for token, path in SOURCES.items():
        if token not in text:
            sys.exit(f"gen_embedded: {TEMPLATE.name} has no {token} placeholder")
        body = path.read_text(encoding="utf-8")
        if not body.endswith("\n"):
            body += "\n"                      # a literal must not end mid-line
        if TERMINATOR in body:
            sys.exit(f"gen_embedded: {path} contains {TERMINATOR}; it cannot be "
                     f"embedded in a raw string literal")
        text = text.replace(token, body)
    return text


def main() -> int:
    check = "--check" in sys.argv[1:]
    wanted = render()
    current = OUTPUT.read_text(encoding="utf-8") if OUTPUT.exists() else None

    if check:
        if current == wanted:
            print(f"check-doc: {OUTPUT.name} matches LICENSE and doc/slaplog.md")
            return 0
        print(f"check-doc: {OUTPUT.name} is STALE — run `make embedded`",
              file=sys.stderr)
        return 1

    if current == wanted:
        print(f"embedded: {OUTPUT.name} already up to date")
        return 0
    OUTPUT.write_text(wanted, encoding="utf-8")
    print(f"embedded: {OUTPUT.name} regenerated from "
          + " + ".join(str(p.relative_to(ROOT)) for p in SOURCES.values()))
    return 0


if __name__ == "__main__":
    sys.exit(main())
