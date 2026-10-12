"""Pinned, offline adapters for public vulnerability snapshots.

``load_sources(manifest_path)`` returns ``(records, provenance)``. Records use
numeric CWE strings (not ``CWE-`` prefixes); text is deliberately not sanitized.
Only explicit review evidence sets ``reviewed``: GitHub's reviewed flag, or a
completed expert adjudication. KEV is metadata, never a source of gold labels.
CVE vendors come from CNA affected products, never from the reporting provider.

``snapshot_sha256(path)`` computes the pin for a local snapshot. A file's pin is
the SHA-256 of its bytes. For a directory, sort JSON files by their POSIX relative
paths and hash, for each file, its UTF-8 path length as an unsigned eight-byte
big-endian integer, the path bytes, its content length in the same format, and
its content bytes. Hidden files/directories, node_modules and __pycache__ are
excluded. Only .json files are included; symlinks are not permitted. This framing
avoids collisions between different path/content boundaries. Both hashing and
loading use exactly the same directory selection.

Provenance contains ``manifest_sha256``, ``sources`` and aggregate ``counts`` /
``exclusions``. Each source retains kind, resolved absolute path, sha256 and
revision, plus counts (seen, accepted, excluded, metadata) and exclusion reasons.
KEV entries count as metadata, not accepted benchmark records.
"""

import hashlib
import json
import re
from collections import Counter
from datetime import date, datetime
from pathlib import Path


_KINDS = {"nvd", "cve", "ghsa", "vendor", "adjudicated", "kev"}
_IGNORED_DIRS = {"node_modules", "__pycache__"}
_CWE = re.compile(r"(?i)\bCWE-(\d+)\b")
_LABEL = re.compile(r"(?i)(?:CWE-)?(\d+)")
_SHA256 = re.compile(r"[0-9a-fA-F]{64}")


def _snapshot(path):
    path = Path(path)
    if path.is_symlink():
        raise ValueError(f"Snapshot symlinks are not supported: {path}")
    if path.is_file():
        content = path.read_bytes()
        return hashlib.sha256(content).hexdigest(), [(path, content)]
    if not path.is_dir():
        raise ValueError(f"Snapshot does not exist: {path}")
    files = []

    def walk(directory):
        for child in sorted(directory.iterdir(), key=lambda entry: entry.name):
            if child.name.startswith(".") or child.name in _IGNORED_DIRS:
                continue
            if child.is_symlink():
                raise ValueError(f"Snapshot symlinks are not supported: {child}")
            if child.is_dir():
                walk(child)
            elif child.is_file() and child.suffix.lower() == ".json":
                files.append(child)

    walk(path)
    digest = hashlib.sha256()
    contents = []
    for file in sorted(files, key=lambda file: file.relative_to(path).as_posix()):
        relative = file.relative_to(path).as_posix().encode("utf-8")
        content = file.read_bytes()
        digest.update(len(relative).to_bytes(8, "big"))
        digest.update(relative)
        digest.update(len(content).to_bytes(8, "big"))
        digest.update(content)
        contents.append((file, content))
    return digest.hexdigest(), contents


def snapshot_sha256(path):
    """Return the deterministic SHA-256 pin for a file or JSON directory.

    See the module docstring for the exact directory framing and exclusions.
    No network access, archive extraction or writes are performed.
    """
    return _snapshot(path)[0]


def _object(value, field):
    if not isinstance(value, dict):
        raise ValueError(f"{field} must be an object")
    return value


def _string(value, field, nonempty=False):
    if not isinstance(value, str) or (nonempty and not value.strip()):
        raise ValueError(f"{field} must be {'a nonempty' if nonempty else 'a'} string")
    return value.strip()


def _list(value, field):
    if not isinstance(value, list):
        raise ValueError(f"{field} must be a list")
    return value


def _strings(value, field):
    return list(dict.fromkeys(
        _string(item, field, nonempty=True) for item in _list(value, field)))


def _bool(value, field):
    if not isinstance(value, bool):
        raise ValueError(f"{field} must be a boolean")
    return value


def _published(value):
    value = _string(value, "published")
    if not value:
        return ""
    if not re.fullmatch(r"\d{4}-\d{2}-\d{2}(?:[Tt ].+)?", value):
        raise ValueError(f"Invalid ISO published date: {value}")
    try:
        result = date.fromisoformat(value[:10])
        if len(value) > 10:
            datetime.fromisoformat(value)
    except ValueError as exc:
        raise ValueError(f"Invalid ISO published date: {value}") from exc
    return result.isoformat()


def _labels(value):
    labels = []
    for item in _list(value, "labels"):
        item = _string(item, "label", nonempty=True)
        match = _LABEL.fullmatch(item)
        if not match or int(match[1]) == 0:
            raise ValueError(f"Invalid CWE label: {item}")
        label = str(int(match[1]))
        if label not in labels:
            labels.append(label)
    return labels


def _cwes(text):
    return [str(int(match)) for match in _CWE.findall(text) if int(match)]


def _english(descriptions):
    parts = []
    for description in _list(descriptions, "descriptions"):
        description = _object(description, "description")
        language = _string(description.get("lang", ""), "description.lang")
        value = _string(description.get("value", ""), "description.value")
        if language.lower().split("-")[0] == "en" and value:
            parts.append(value)
    return "\n\n".join(parts)


def _record(kind, identifier, text, labels, published="", aliases=None,
            ecosystems=None, vendors=None, reviewed=False, ambiguous=False,
            insufficient_information=False, expert_reviewed=False):
    identifier = _string(identifier, "id", nonempty=True)
    return {
        "id": identifier,
        "aliases": list(dict.fromkeys([identifier] + (aliases or []))),
        "text": _string(text, "text"),
        "labels": list(dict.fromkeys(labels)),
        "published": _published(published),
        "ecosystems": ecosystems or [],
        "vendors": vendors or [],
        "source": kind,
        "reviewed": reviewed,
        "ambiguous": ambiguous,
        "insufficient_information": insufficient_information,
        "expert_reviewed": expert_reviewed,
    }


def _nvd(entry):
    cve = _object(entry.get("cve", entry), "cve")
    status = _string(cve.get("vulnStatus", ""), "vulnStatus")
    if status.lower() in {"rejected", "reject"}:
        return None, "rejected"
    text = _english(cve.get("descriptions", []))
    if not text:
        return None, "missing_description"
    labels = []
    for weakness in _list(cve.get("weaknesses", []), "weaknesses"):
        weakness = _object(weakness, "weakness")
        for description in _list(weakness.get("description", []), "weakness.description"):
            description = _object(description, "weakness.description")
            labels.extend(_cwes(_string(description.get("value", ""), "weakness.value")))
    return _record("nvd", cve.get("id"), text, labels, cve.get("published", "")), None


def _cve(entry):
    metadata = _object(entry.get("cveMetadata", {}), "cveMetadata")
    state = _string(metadata.get("state", ""), "cveMetadata.state")
    if state != "PUBLISHED":
        return None, "rejected" if state == "REJECTED" else "not_published"
    containers = _object(entry.get("containers", {}), "containers")
    cna = _object(containers.get("cna", {}), "containers.cna")
    text = _english(cna.get("descriptions", []))
    if not text:
        return None, "missing_description"
    labels = []
    for problem in _list(cna.get("problemTypes", []), "problemTypes"):
        problem = _object(problem, "problemType")
        for description in _list(problem.get("descriptions", []), "problemType.descriptions"):
            description = _object(description, "problemType.description")
            for field in ("cweId", "description"):
                labels.extend(_cwes(_string(description.get(field, ""), field)))
    vendors = []
    for affected in _list(cna.get("affected", []), "containers.cna.affected"):
        affected = _object(affected, "affected")
        vendor = _string(affected.get("vendor", ""), "affected.vendor")
        if vendor and vendor.casefold() not in {"n/a", "na", "unknown", "not applicable", "none"}:
            if vendor not in vendors:
                vendors.append(vendor)
    published = metadata.get("datePublished") or cna.get("datePublished", "")
    return _record("cve", metadata.get("cveId"), text, labels, published,
                   vendors=vendors), None


def _ghsa(entry):
    if entry.get("withdrawn") is not None:
        _string(entry["withdrawn"], "withdrawn")
        if entry["withdrawn"]:
            return None, "withdrawn"
    specific = _object(entry.get("database_specific", {}), "database_specific")
    reviewed = _bool(specific.get("github_reviewed", False), "github_reviewed")
    if not reviewed:
        return None, "unreviewed"
    text = "\n\n".join(part for part in (
        _string(entry.get("summary", ""), "summary"),
        _string(entry.get("details", ""), "details")) if part)
    if not text:
        return None, "missing_description"
    ecosystems = []
    for affected in _list(entry.get("affected", []), "affected"):
        affected = _object(affected, "affected")
        package = _object(affected.get("package", {}), "affected.package")
        ecosystem = _string(package.get("ecosystem", ""), "package.ecosystem")
        if ecosystem and ecosystem not in ecosystems:
            ecosystems.append(ecosystem)
    return _record(
        "ghsa", entry.get("id"), text, _labels(specific.get("cwe_ids", [])),
        entry.get("published", ""), _strings(entry.get("aliases", []), "aliases"),
        ecosystems, reviewed=True), None


def _normalized(entry, kind):
    text = _string(entry.get("text", ""), "text")
    if not text:
        return None, "missing_description"
    insufficient = _bool(entry.get("insufficient_information", False),
                         "insufficient_information")
    if "labels" not in entry:
        raise ValueError(f"{kind} record requires labels (use [] for unlabeled records)")
    expert = _bool(entry.get("expert_reviewed", False), "expert_reviewed")
    status = entry.get("adjudication_status", "pending")
    if kind == "adjudicated":
        if status not in ("pending", "complete"):
            raise ValueError("adjudication_status must be pending or complete")
    record = _record(
        kind, entry.get("id"), text, _labels(entry["labels"]),
        entry.get("published", ""), _strings(entry.get("aliases", []), "aliases"),
        _strings(entry.get("ecosystems", []), "ecosystems"),
        _strings(entry.get("vendors", []), "vendors"),
        reviewed=kind == "adjudicated" and expert and status == "complete",
        ambiguous=_bool(entry.get("ambiguous", False), "ambiguous"),
        insufficient_information=insufficient, expert_reviewed=expert)
    if kind == "adjudicated":
        record["adjudication_status"] = status
    return record, None


def _documents(file, content):
    try:
        if file.suffix.lower() == ".jsonl":
            return [json.loads(line) for line in content.decode("utf-8-sig").splitlines()
                    if line.strip()]
        return [json.loads(content.decode("utf-8-sig"))]
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError(f"Invalid JSON snapshot: {file}") from exc


def _entries(document, kind):
    if isinstance(document, list):
        return document
    document = _object(document, "snapshot")
    if kind in {"nvd", "kev"} and "vulnerabilities" in document:
        return _list(document["vulnerabilities"], "vulnerabilities")
    return [document]


def load_sources(manifest_path):
    """Load a SHA-256-pinned manifest without fetching or modifying anything.

    Malformed types, dates, manifests and pins raise ValueError. Ineligible
    public records and records without descriptions are excluded with counters.
    KEV annotations are joined by aliases after all sources have been loaded;
    they do not alter primary text or labels. Pending adjudications remain
    unreviewed, with only their explicitly supplied labels.
    Directory snapshot bytes are retained until parsed, ensuring the loaded
    bytes match the pin; memory use includes the current snapshot and records.
    """
    manifest_path = Path(manifest_path)
    manifest_bytes = manifest_path.read_bytes()
    try:
        manifest = _object(json.loads(manifest_bytes), "manifest")
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError("Invalid JSON manifest") from exc
    sources = _list(manifest.get("sources"), "manifest.sources")
    records, audits, kev_ids = [], [], set()
    totals, exclusions = Counter(), Counter()
    for source in sources:
        source = _object(source, "source")
        kind = _string(source.get("kind"), "source.kind")
        if kind not in _KINDS:
            raise ValueError(f"Unsupported source kind: {kind}")
        raw_path = _string(source.get("path"), "source.path", nonempty=True)
        path = Path(raw_path)
        if not path.is_absolute():
            path = manifest_path.parent / path
        # Do not resolve before hashing: resolving would hide a root symlink.
        pin = _string(source.get("sha256"), "source.sha256")
        if not _SHA256.fullmatch(pin):
            raise ValueError("source.sha256 must be 64 hexadecimal characters")
        revision = _string(source.get("revision"), "source.revision", nonempty=True)
        actual, contents = _snapshot(path)
        if actual != pin.lower():
            raise ValueError(f"SHA-256 mismatch for {path}: expected {pin}, got {actual}")
        counts = Counter(seen=0, accepted=0, excluded=0, metadata=0)
        reasons = Counter()
        for file, content in contents:
            if file.suffix.lower() not in {".json", ".jsonl"}:
                raise ValueError(f"Snapshot must be JSON or JSONL: {file}")
            for document in _documents(file, content):
                for entry in _entries(document, kind):
                    entry = _object(entry, f"{kind} record")
                    counts["seen"] += 1
                    if kind == "kev":
                        kev_ids.add(_string(entry.get("cveID"), "cveID", nonempty=True))
                        counts["metadata"] += 1
                        continue
                    if kind == "nvd":
                        record, reason = _nvd(entry)
                    elif kind == "cve":
                        record, reason = _cve(entry)
                    elif kind == "ghsa":
                        record, reason = _ghsa(entry)
                    else:
                        record, reason = _normalized(entry, kind)
                    if record is None:
                        counts["excluded"] += 1
                        reasons[reason] += 1
                    else:
                        counts["accepted"] += 1
                        records.append(record)
        totals.update(counts)
        exclusions.update(reasons)
        audits.append(dict(kind=kind, path=str(path.resolve()), sha256=actual,
                           revision=revision, counts=dict(counts), exclusions=dict(reasons)))
    for record in records:
        record["kev"] = any(alias in kev_ids for alias in record["aliases"])
    return records, {
        "manifest_sha256": hashlib.sha256(manifest_bytes).hexdigest(),
        "sources": audits,
        "counts": dict(totals),
        "exclusions": dict(exclusions),
    }
