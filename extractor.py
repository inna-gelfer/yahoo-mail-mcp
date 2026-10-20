"""Text extraction for one untrusted attachment, run in a separate child process.

Usage:
  python -I extractor.py {pdf|docx|xlsx} < file_bytes > text
  python -I extractor.py pdfpages FIRST MAX < file_bytes > JSON with page images

The server starts this with an empty environment (no credentials) and a
timeout. Before reading any input, the child limits itself:
  * Linux/macOS: memory, CPU time, and no file writes (setrlimit).
  * Windows: a Job Object with a memory cap, CPU time cap, no child
    processes, and kill-on-close. If the job cannot be applied, the child
    refuses to run (fail closed).
A malicious file that crashes or hangs the parser only kills this child,
never the server. Office files are read with plain text matching: no XML
parser and no macro execution. Nothing is written to disk.
"""

from __future__ import annotations

import base64
import html
import io
import json
import re
import sys
import zipfile

MAX_PAGES = 50
MAX_SHEETS = 10
MAX_ROWS_PER_SHEET = 2000
MAX_ZIP_MEMBER_BYTES = 20 * 1024 * 1024  # uncompressed; blocks zip bombs
MAX_ZIP_TOTAL_BYTES = 60 * 1024 * 1024
MEMORY_LIMIT_BYTES = 1024 * 1024 * 1024
CPU_LIMIT_S = 25

# Page rendering (scanned PDFs)
RENDER_DPI = 150
MAX_RENDER_PAGES = 5
MAX_PAGE_PIXELS_LONG_SIDE = 2000      # caps bitmap memory for oversized pages
MAX_PAGE_IMAGE_BYTES = 3_500_000      # stays under the 5 MB image limit after base64
MAX_TOTAL_IMAGE_BYTES = 12_000_000    # all pages in one response
NO_TEXT_LAYER = "[No text layer: this PDF is probably a scan.]"

_job_handle = None  # keeps the Windows job alive for this process's lifetime


def _job_limit_struct():
    """JOBOBJECT_EXTENDED_LIMIT_INFORMATION with fixed-size fields (144 bytes on 64-bit Windows)."""
    import ctypes

    DWORD = ctypes.c_uint32

    class BASIC(ctypes.Structure):
        _fields_ = [
            ("PerProcessUserTimeLimit", ctypes.c_int64),
            ("PerJobUserTimeLimit", ctypes.c_int64),
            ("LimitFlags", DWORD),
            ("MinimumWorkingSetSize", ctypes.c_size_t),
            ("MaximumWorkingSetSize", ctypes.c_size_t),
            ("ActiveProcessLimit", DWORD),
            ("Affinity", ctypes.c_size_t),
            ("PriorityClass", DWORD),
            ("SchedulingClass", DWORD),
        ]

    class IO_COUNTERS(ctypes.Structure):
        _fields_ = [(n, ctypes.c_uint64) for n in (
            "ReadOperationCount", "WriteOperationCount", "OtherOperationCount",
            "ReadTransferCount", "WriteTransferCount", "OtherTransferCount")]

    class EXTENDED(ctypes.Structure):
        _fields_ = [
            ("BasicLimitInformation", BASIC),
            ("IoInfo", IO_COUNTERS),
            ("ProcessMemoryLimit", ctypes.c_size_t),
            ("JobMemoryLimit", ctypes.c_size_t),
            ("PeakProcessMemoryUsed", ctypes.c_size_t),
            ("PeakJobMemoryUsed", ctypes.c_size_t),
        ]

    return EXTENDED


JOB_OBJECT_LIMIT_PROCESS_TIME = 0x00000002
JOB_OBJECT_LIMIT_ACTIVE_PROCESS = 0x00000008
JOB_OBJECT_LIMIT_PROCESS_MEMORY = 0x00000100
JOB_OBJECT_LIMIT_JOB_MEMORY = 0x00000200
JOB_OBJECT_LIMIT_DIE_ON_UNHANDLED_EXCEPTION = 0x00000400
JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE = 0x00002000
JOB_OBJECT_EXTENDED_LIMIT_INFORMATION = 9  # JOBOBJECTINFOCLASS value


def _apply_windows_job() -> None:
    """Put this process into a Job Object with memory/CPU/process limits."""
    global _job_handle
    import ctypes

    HANDLE = ctypes.c_void_p
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel32.CreateJobObjectW.restype = HANDLE
    kernel32.CreateJobObjectW.argtypes = [ctypes.c_void_p, ctypes.c_wchar_p]
    kernel32.SetInformationJobObject.restype = ctypes.c_int
    kernel32.SetInformationJobObject.argtypes = [HANDLE, ctypes.c_int, ctypes.c_void_p, ctypes.c_uint32]
    kernel32.AssignProcessToJobObject.restype = ctypes.c_int
    kernel32.AssignProcessToJobObject.argtypes = [HANDLE, HANDLE]
    kernel32.GetCurrentProcess.restype = HANDLE
    kernel32.GetCurrentProcess.argtypes = []

    job = kernel32.CreateJobObjectW(None, None)
    if not job:
        raise OSError(ctypes.get_last_error(), "CreateJobObjectW failed")
    info = _job_limit_struct()()
    info.BasicLimitInformation.LimitFlags = (
        JOB_OBJECT_LIMIT_PROCESS_TIME | JOB_OBJECT_LIMIT_ACTIVE_PROCESS | JOB_OBJECT_LIMIT_PROCESS_MEMORY
        | JOB_OBJECT_LIMIT_JOB_MEMORY | JOB_OBJECT_LIMIT_DIE_ON_UNHANDLED_EXCEPTION
        | JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
    )
    info.BasicLimitInformation.PerProcessUserTimeLimit = CPU_LIMIT_S * 10_000_000  # 100 ns units
    info.BasicLimitInformation.ActiveProcessLimit = 1  # this process only: no child processes
    info.ProcessMemoryLimit = MEMORY_LIMIT_BYTES
    info.JobMemoryLimit = MEMORY_LIMIT_BYTES
    if not kernel32.SetInformationJobObject(
        job, JOB_OBJECT_EXTENDED_LIMIT_INFORMATION, ctypes.byref(info), ctypes.sizeof(info)
    ):
        raise OSError(ctypes.get_last_error(), "SetInformationJobObject failed")
    # A process may assign itself. Doing it here, in the real interpreter, also
    # covers the Windows venv launcher, which starts python.exe as a second process.
    if not kernel32.AssignProcessToJobObject(job, kernel32.GetCurrentProcess()):
        raise OSError(ctypes.get_last_error(), "AssignProcessToJobObject failed")
    _job_handle = job


def _apply_limits() -> None:
    if sys.platform == "win32":
        _apply_windows_job()  # raises: the child refuses to parse without limits
        return
    try:
        import resource
    except ImportError:
        return
    for name, value in (("RLIMIT_AS", MEMORY_LIMIT_BYTES), ("RLIMIT_CPU", CPU_LIMIT_S), ("RLIMIT_FSIZE", 0)):
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
        text += "\n" + NO_TEXT_LAYER
    return text


def _encode_page(img) -> tuple[str, bytes]:
    """JPEG-encode a rendered page, lowering quality and then size to fit the image limit."""
    if img.mode not in ("RGB", "L"):
        img = img.convert("RGB")
    for _ in range(6):
        for quality in (85, 70, 55):
            buf = io.BytesIO()
            img.save(buf, format="JPEG", quality=quality, optimize=True)
            if buf.tell() <= MAX_PAGE_IMAGE_BYTES:
                return "jpeg", buf.getvalue()
        img = img.resize((max(1, img.width * 3 // 4), max(1, img.height * 3 // 4)))
    raise ValueError("page image too large")


def _pdf_pages(data: bytes, first: int, count: int) -> str:
    import pypdfium2 as pdfium

    pdf = pdfium.PdfDocument(data)  # in memory; no file is written
    try:
        total = len(pdf)
        first = max(1, first)
        count = max(1, min(count, MAX_RENDER_PAGES))
        pages, used, note = [], 0, ""
        for n in range(first, min(total, first + count - 1) + 1):
            page = pdf[n - 1]
            try:
                width, height = page.get_size()  # points (1/72 inch)
                scale = min(RENDER_DPI / 72, MAX_PAGE_PIXELS_LONG_SIDE / max(width, height, 1))
                img = page.render(scale=scale).to_pil()
            finally:
                page.close()
            fmt, blob = _encode_page(img)
            if used + len(blob) > MAX_TOTAL_IMAGE_BYTES:
                note = f"Stopped before page {n}: response size limit reached."
                break
            used += len(blob)
            pages.append({"page": n, "format": fmt, "data": base64.b64encode(blob).decode("ascii")})
    finally:
        pdf.close()
    return json.dumps({"total_pages": total, "pages": pages, "note": note})


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
    data = sys.stdin.buffer.read()  # only after the limits are in place
    if kind == "pdfpages":
        text = _pdf_pages(data, int(sys.argv[2]), int(sys.argv[3]))
    else:
        text = {"pdf": _pdf, "docx": _docx, "xlsx": _xlsx}[kind](data)
    sys.stdout.buffer.write(text.encode("utf-8", "replace"))


if __name__ == "__main__":
    try:
        main()
    except Exception as e:  # report the kind of failure only, never file content
        sys.stderr.write(type(e).__name__)
        sys.exit(2)
