"""Text extraction for one untrusted attachment, run in a separate child process.

Usage: python -I extractor.py {pdf|docx|xlsx} < file_bytes > text

The server starts this with an empty environment (no credentials), a
timeout, and, where the OS supports it, limits on memory, CPU time and file
writes. A malicious file that crashes or hangs the parser only kills this
child, never the server. Office files are read with plain text matching:
no XML parser and no macro execution.
"""

from __future__ import annotations

import html
import io
import re
import sys
import zipfile

MAX_PAGES = 50
MAX_SHEETS = 10
MAX_ROWS_PER_SHEET = 2000
MAX_ZIP_MEMBER_BYTES = 20 * 1024 * 1024  # uncompressed; blocks zip bombs
MAX_ZIP_TOTAL_BYTES = 60 * 1024 * 1024


def _apply_limits() -> None:
    try:
        import resource
    except ImportError:  # Windows: rely on the parent's timeout
        return
    for name, value in (("RLIMIT_AS", 1024 * 1024 * 1024), ("RLIMIT_CPU", 25), ("RLIMIT_FSIZE", 0)):
        try:
            limit = getattr(resource, name)
            resource.setrlimit(limit, (value, value))
        except (AttributeError, ValueError, OSError):
            pass  # not supported on this OS (e.g. RLIMIT_AS on macOS)


def _pdf(data: bytes) -> str:
    from pypdf import PdfReader

    reader = PdfReader(io.BytesIO(data))
    if reader.is_encrypted:
        try:
            if not reader.decrypt(""):
                return "[PDF is password-protected]"
        except Exception:
            return "[PDF is password-protected]"
    pages = reader.pages
    out = []
    for i, page in enumerate(pages):
        if i >= MAX_PAGES:
            out.append(f"[...stopped after {MAX_PAGES} of {len(pages)} pages]")
            break
        out.append(f"--- page {i + 1} ---\n{(page.extract_text() or '').strip()}")
    text = "\n".join(out)
    if not re.search(r"\w", re.sub(r"--- page \d+ ---", "", text)):
        text += "\n[No text layer: this PDF is probably a scan.]"
    return text


def _open_zip(data: bytes) -> zipfile.ZipFile:
    zf = zipfile.ZipFile(io.BytesIO(data))
    infos = zf.infolist()
    if sum(i.file_size for i in infos) > MAX_ZIP_TOTAL_BYTES or any(
        i.file_size > MAX_ZIP_MEMBER_BYTES for i in infos
    ):
        raise ValueError("archive expands too much")
    return zf


def _read(zf: zipfile.ZipFile, name: str) -> str:
    try:
        raw = zf.read(name)
    except KeyError:
        return ""
    if len(raw) > MAX_ZIP_MEMBER_BYTES:  # declared size can lie
        raise ValueError("archive expands too much")
    return raw.decode("utf-8", "replace")


def _xml_text(fragment: str) -> str:
    return html.unescape("".join(re.findall(r"<(?:\w+:)?t(?:\s[^>]*)?>([^<]*)</(?:\w+:)?t>", fragment)))


def _docx(data: bytes) -> str:
    xml = _read(_open_zip(data), "word/document.xml")
    if not xml:
        raise ValueError("not a Word document")
    xml = re.sub(r"<w:tab\s*/>", "<w:t>\t</w:t>", xml)
    xml = re.sub(r"<w:(?:br|cr)\b[^>]*/>", "<w:t>\n</w:t>", xml)
    paragraphs = [_xml_text(p) for p in re.split(r"</w:p>", xml)]
    return "\n".join(p for p in paragraphs if p.strip())


def _xlsx(data: bytes) -> str:
    zf = _open_zip(data)
    shared = [_xml_text(si) for si in re.findall(r"<si>(.*?)</si>", _read(zf, "xl/sharedStrings.xml"), re.S)]
    names = [html.unescape(n) for n in re.findall(r'<sheet\b[^>]*\bname="([^"]*)"', _read(zf, "xl/workbook.xml"))]
    sheet_files = sorted(
        (n for n in zf.namelist() if re.fullmatch(r"xl/worksheets/sheet\d+\.xml", n)),
        key=lambda n: int(re.search(r"(\d+)\.xml$", n).group(1)),
    )
    if not sheet_files:
        raise ValueError("not an Excel workbook")
    out = []
    for i, path in enumerate(sheet_files):
        if i >= MAX_SHEETS:
            out.append(f"[...stopped after {MAX_SHEETS} sheets]")
            break
        out.append(f"--- sheet: {names[i] if i < len(names) else i + 1} ---")
        rows = re.findall(r"<row\b[^>]*>(.*?)</row>", _read(zf, path), re.S)
        for r, row in enumerate(rows):
            if r >= MAX_ROWS_PER_SHEET:
                out.append(f"[...stopped after {MAX_ROWS_PER_SHEET} rows]")
                break
            cells = []
            for attrs, body in re.findall(r"<c\b([^>]*?)(?:/>|>(.*?)</c>)", row, re.S):
                kind = re.search(r'\bt="(\w+)"', attrs)
                kind = kind.group(1) if kind else "n"
                value = re.search(r"<v>([^<]*)</v>", body or "")
                if kind == "s" and value and value.group(1).isdigit() and int(value.group(1)) < len(shared):
                    cells.append(shared[int(value.group(1))])
                elif kind == "inlineStr":
                    cells.append(_xml_text(body or ""))
                else:
                    cells.append(html.unescape(value.group(1)) if value else "")
            out.append("\t".join(cells))
    return "\n".join(out)


def main() -> None:
    _apply_limits()
    kind = sys.argv[1]
    data = sys.stdin.buffer.read()
    text = {"pdf": _pdf, "docx": _docx, "xlsx": _xlsx}[kind](data)
    sys.stdout.buffer.write(text.encode("utf-8", "replace"))


if __name__ == "__main__":
    try:
        main()
    except Exception as e:  # report the kind of failure only, never file content
        sys.stderr.write(type(e).__name__)
        sys.exit(2)
