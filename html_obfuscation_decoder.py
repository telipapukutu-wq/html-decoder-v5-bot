#!/usr/bin/env python3
"""
HTML Obfuscation Decoder (safe, non-executing)

Supports:
- HTML entities (&lt;div&gt; -> <div>)
- URL percent-encoding (%3Cdiv%3E -> <div>)
- Base64 text/payloads when the whole input is Base64
- JavaScript string escapes (\x3C, \u003C)
- Hex-encoded byte text when the whole input looks like hex
- Repeated decoding passes for layered encodings

IMPORTANT:
This tool does NOT run JavaScript, evaluate code, or execute downloaded HTML.
It cannot decode every custom/encrypted obfuscator. Review output before opening it.
"""

import argparse
import base64
import binascii
import html
import re
import sys
from pathlib import Path
from urllib.parse import unquote


def decode_js_escapes(text: str) -> str:
    # Decode common JS string escapes without evaluating JavaScript.
    text = re.sub(r"\\x([0-9a-fA-F]{2})",
                  lambda m: chr(int(m.group(1), 16)), text)
    text = re.sub(r"\\u([0-9a-fA-F]{4})",
                  lambda m: chr(int(m.group(1), 16)), text)
    text = re.sub(r"\\u\{([0-9a-fA-F]{1,6})\}",
                  lambda m: chr(int(m.group(1), 16))
                  if int(m.group(1), 16) <= 0x10FFFF else m.group(0), text)
    return text


def decode_whole_base64(text: str) -> str | None:
    compact = re.sub(r"\s+", "", text)
    if len(compact) < 8 or not re.fullmatch(r"[A-Za-z0-9+/]*={0,2}", compact):
        return None
    if len(compact) % 4 == 1:
        return None
    padded = compact + "=" * ((4 - len(compact) % 4) % 4)
    try:
        raw = base64.b64decode(padded, validate=True)
        decoded = raw.decode("utf-8")
    except (binascii.Error, UnicodeDecodeError, ValueError):
        return None
    # Avoid replacing readable input with arbitrary binary-like text.
    if not decoded or sum(ch.isprintable() or ch in "\r\n\t" for ch in decoded) / len(decoded) < 0.85:
        return None
    return decoded


def decode_whole_hex(text: str) -> str | None:
    compact = re.sub(r"\s+", "", text)
    if len(compact) < 8 or len(compact) % 2 or not re.fullmatch(r"[0-9a-fA-F]+", compact):
        return None
    try:
        decoded = bytes.fromhex(compact).decode("utf-8")
    except (ValueError, UnicodeDecodeError):
        return None
    if not decoded or sum(ch.isprintable() or ch in "\r\n\t" for ch in decoded) / len(decoded) < 0.85:
        return None
    return decoded


def decode_embedded_base64(text: str) -> str:
    # Replace likely Base64 strings inside quotes only when decoded text looks like HTML/JS/text.
    pattern = re.compile(r"""(['"])([A-Za-z0-9+/]{24,}={0,2})\1""")

    def replace(match):
        decoded = decode_whole_base64(match.group(2))
        if decoded is None:
            return match.group(0)
        if any(token in decoded.lower() for token in ("<html", "<!doctype", "<script", "<div", "function", "document.")):
            return match.group(1) + decoded.replace("\\", "\\\\").replace(match.group(1), "\\" + match.group(1)) + match.group(1)
        return match.group(0)

    return pattern.sub(replace, text)


def one_pass(text: str) -> tuple[str, list[str]]:
    changes = []

    new = html.unescape(text)
    if new != text:
        text = new
        changes.append("HTML entities")

    new = unquote(text)
    if new != text:
        text = new
        changes.append("URL percent-encoding")

    new = decode_js_escapes(text)
    if new != text:
        text = new
        changes.append("JavaScript hex/Unicode escapes")

    whole_b64 = decode_whole_base64(text.strip())
    if whole_b64 is not None:
        text = whole_b64
        changes.append("whole-file Base64")

    whole_hex = decode_whole_hex(text.strip())
    if whole_hex is not None:
        text = whole_hex
        changes.append("whole-file hex")

    new = decode_embedded_base64(text)
    if new != text:
        text = new
        changes.append("embedded Base64 strings")

    return text, changes


def decode_layers(text: str, max_passes: int = 8) -> tuple[str, list[str]]:
    all_changes = []
    for pass_no in range(1, max_passes + 1):
        updated, changes = one_pass(text)
        if not changes or updated == text:
            break
        all_changes.extend(f"Pass {pass_no}: {item}" for item in changes)
        text = updated
    return text, all_changes


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Safely decode common HTML/text obfuscation layers (does not execute code)."
    )
    parser.add_argument("input", help="Input .html, .htm, .txt, or other text file")
    parser.add_argument("-o", "--output", help="Output file (default: <input>_decoded.html)")
    parser.add_argument("--passes", type=int, default=8, help="Maximum decoding passes (default: 8)")
    args = parser.parse_args()

    if not 1 <= args.passes <= 30:
        parser.error("--passes must be between 1 and 30")

    source = Path(args.input)
    if not source.is_file():
        print(f"Error: input file not found: {source}", file=sys.stderr)
        return 2

    try:
        raw = source.read_text(encoding="utf-8-sig")
    except UnicodeDecodeError:
        print("Error: file is not valid UTF-8 text. Convert it to UTF-8 first.", file=sys.stderr)
        return 2
    except OSError as exc:
        print(f"Error reading input: {exc}", file=sys.stderr)
        return 2

    decoded, changes = decode_layers(raw, args.passes)
    output = Path(args.output) if args.output else source.with_name(source.stem + "_decoded.html")

    try:
        output.write_text(decoded, encoding="utf-8")
    except OSError as exc:
        print(f"Error writing output: {exc}", file=sys.stderr)
        return 2

    print(f"Done. Output saved to: {output}")
    if changes:
        print("Decoding steps:")
        for change in changes:
            print(f"  - {change}")
    else:
        print("No supported encoding layers were detected.")
    print("Safety note: decoded output is not guaranteed safe. Do not open untrusted HTML directly in your main browser.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
