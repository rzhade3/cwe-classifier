"""Content-addressed checkpoints and atomic publication for one local writer."""

import json
import os
import platform
import subprocess
from contextlib import contextmanager
from importlib.metadata import distributions
from pathlib import Path

from . import fingerprint

ROOT = Path(__file__).resolve().parent.parent


def provenance():
    paths = sorted(
        [
            *ROOT.glob("*.py"),
            *ROOT.glob("experiment/*.py"),
            ROOT / "uv.lock",
            ROOT / "pyproject.toml",
        ]
    )
    sources = {str(p.relative_to(ROOT)): fingerprint(p.read_text()) for p in paths}
    revision = (
        subprocess.run(
            ["git", "-C", str(ROOT), "rev-parse", "HEAD"],
            capture_output=True,
            text=True,
        ).stdout.strip()
        or None
    )
    return {
        "revision": revision,
        "source_sha256": fingerprint(sources),
        "sources": sources,
        "python": platform.python_version(),
        "packages": dict(
            sorted(
                (d.metadata["Name"], d.version)
                for d in distributions()
                if d.metadata["Name"]
            )
        ),
    }


def atomic_json(path, value):
    path = Path(path)
    temporary = path.with_name(path.name + ".tmp")
    with temporary.open("w", encoding="utf-8") as stream:
        stream.write(json.dumps(value, indent=2, sort_keys=True) + "\n")
        stream.flush()
        os.fsync(stream.fileno())
    os.replace(temporary, path)


@contextmanager
def output_lock(output):
    output.mkdir(parents=True, exist_ok=True)
    lock = output / ".run.lock"
    try:
        descriptor = os.open(lock, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    except FileExistsError as error:
        raise RuntimeError(
            f"Another run owns {lock}; after a crash, verify the writer is gone before removing it"
        ) from error
    try:
        os.write(descriptor, str(os.getpid()).encode())
        os.close(descriptor)
        yield
    finally:
        lock.unlink()


def load_checkpoint(path):
    """Recover a torn final append; reject corruption in completed records."""
    if not path.exists():
        return {}
    saved = {}
    with path.open("rb+") as stream:
        while line := stream.readline():
            end = stream.tell()
            if not line.endswith(b"\n"):
                stream.truncate(end - len(line))
                break
            value = json.loads(line)
            payload = {key: value[key] for key in ("record", "metadata")}
            if value.get("sha256") != fingerprint(payload):
                raise ValueError("Checkpoint record checksum mismatch")
            identifier = value["record"]["id"]
            if identifier in saved:
                raise ValueError(f"Duplicate checkpoint ID: {identifier}")
            saved[identifier] = value
    return saved


def append_checkpoint(path, record, metadata):
    payload = {"record": record, "metadata": metadata}
    payload["sha256"] = fingerprint(payload)
    with path.open("a", encoding="utf-8") as stream:
        stream.write(json.dumps(payload, sort_keys=True) + "\n")
        stream.flush()
        os.fsync(stream.fileno())
