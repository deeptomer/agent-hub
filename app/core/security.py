"""Untrusted-input handling: safe zip extraction, GitHub fetch, prompt-injection scan, SQL output guard."""
from __future__ import annotations

import io
import re
import urllib.request
import zipfile
from dataclasses import asdict, dataclass
from pathlib import Path

ALLOWED_EXT = {".java", ".xml", ".sql", ".properties", ".yml", ".yaml", ".gradle", ".kt", ".txt", ".md", ".pks", ".pkb",
                ".prc", ".fnc", ".trg", ".ddl"}


@dataclass
class Finding:
    severity: str  # high | medium | low | info
    category: str
    file: str
    line: int
    detail: str

    def to_dict(self) -> dict:
        return asdict(self)


class UnsafeInput(Exception):
    pass


def safe_extract_zip(data: bytes, dest: Path, *, max_files: int, max_total_bytes: int = 30 * 1024 * 1024) -> int:
    """Extract only allow-listed text files; reject zip-slip, huge or bomb-like archives."""
    dest.mkdir(parents=True, exist_ok=True)
    try:
        zf = zipfile.ZipFile(io.BytesIO(data))
    except zipfile.BadZipFile as exc:
        raise UnsafeInput("not a valid zip file") from exc
    infos = [i for i in zf.infolist() if not i.is_dir()]
    if len(infos) > max_files * 5:
        raise UnsafeInput(f"archive has too many entries ({len(infos)})")
    total = 0
    written = 0
    root = dest.resolve()
    for info in infos:
        name = info.filename.replace("\\", "/")
        if name.startswith("/") or ".." in Path(name).parts:
            raise UnsafeInput(f"unsafe path in archive: {name}")
        if Path(name).suffix.lower() not in ALLOWED_EXT:
            continue
        if any(part in (".git", "node_modules", "target", "build") for part in Path(name).parts):
            continue
        if info.file_size > 2 * 1024 * 1024:
            continue
        total += info.file_size
        if total > max_total_bytes:
            raise UnsafeInput("archive expands to too much data")
        target = (dest / name).resolve()
        if root not in target.parents:
            raise UnsafeInput(f"unsafe path in archive: {name}")
        target.parent.mkdir(parents=True, exist_ok=True)
        with zf.open(info) as src:
            target.write_bytes(src.read(info.file_size + 1)[: info.file_size])
        written += 1
        if written >= max_files:
            break
    return written


_GH = re.compile(r"^https://github\.com/([A-Za-z0-9_.-]+)/([A-Za-z0-9_.-]+?)(?:\.git)?(?:/tree/([\w./-]+))?/?$")


def fetch_github_zip(url: str, max_bytes: int) -> bytes:
    """Public GitHub repositories only. The host is fixed so user input cannot steer the request elsewhere (SSRF)."""
    m = _GH.match(url.strip())
    if not m:
        raise UnsafeInput("only public https://github.com/<owner>/<repo> URLs are supported")
    owner, repo, branch = m.group(1), m.group(2), m.group(3) or "HEAD"
    api = f"https://codeload.github.com/{owner}/{repo}/zip/{branch}"
    req = urllib.request.Request(api, headers={"User-Agent": "oracle2pg-agent-hub"})
    with urllib.request.urlopen(req, timeout=30) as resp:  # noqa: S310 - fixed https host
        data = resp.read(max_bytes + 1)
    if len(data) > max_bytes:
        raise UnsafeInput("repository archive is larger than the upload limit")
    return data


_INJECTION = [
    (r"ignore\s+(all\s+|any\s+|the\s+)?(previous|prior|above|earlier)\s+(instructions|prompts?|rules)", "instruction override"),
    (r"disregard\s+(the\s+)?(system|previous|above)", "instruction override"),
    (r"you\s+are\s+now\s+(a|an|the)\b", "role hijack"),
    (r"(reveal|print|show|leak)\s+(your|the)\s+(system\s+prompt|instructions|api\s*key|secrets?)", "prompt/secret exfiltration"),
    (r"</?\s*(system|assistant|untrusted_source|instructions)\s*>", "fake prompt delimiter"),
    (r"(send|post|upload|exfiltrate)\s+.{0,40}\s+(to|via)\s+https?://", "data exfiltration"),
    (r"\bas\s+an\s+ai\s+(language\s+)?model\b.{0,60}\b(must|should)\b", "directive aimed at an AI"),
]
_INJECTION_RE = [(re.compile(p, re.I), label) for p, label in _INJECTION]


def scan_injection(text: str, file: str) -> list[Finding]:
    out: list[Finding] = []
    for i, line in enumerate(text.splitlines(), start=1):
        for rx, label in _INJECTION_RE:
            if rx.search(line):
                out.append(Finding("high", "Possible prompt injection in source", file, i,
                                   f"{label}: \"{line.strip()[:140]}\" (treated as data, never as an instruction)"))
                break
    return out


_DENY = re.compile(
    r"\b(pg_read_file|pg_read_binary_file|pg_ls_dir|pg_stat_file|lo_import|lo_export|dblink|pg_sleep|"
    r"copy\s+\S+\s+(from|to)|create\s+extension|create\s+role|alter\s+role|set\s+role|set\s+session|"
    r"drop\s+(database|schema\s+public|role)|grant\s|revoke\s|pg_terminate_backend|pg_cancel_backend|"
    r"pg_reload_conf|pg_catalog\.set_config|current_setting\s*\(\s*'(?:app|password))", re.I)


def output_guard(sql: str) -> str | None:
    """Return a reason string if model-produced SQL must not reach the database sandbox."""
    if _DENY.search(sql):
        return "blocked: statement uses a capability that is not allowed in the sandbox"
    if len(sql) > 60_000:
        return "blocked: statement is unreasonably large"
    return None
