"""Sandboxing: an isolated scratch directory, and a locked-down subprocess runner.

Nothing in this tool executes code from the analysed package. External decompilers
(apktool, jadx, otool) *are* executed, but they are trusted binaries from PATH that
we hand untrusted *data* to — so they get a timeout, a private working directory, a
scrubbed environment, resource limits and process-group kill on expiry.
"""

from __future__ import annotations

import os
import resource
import shutil
import signal
import subprocess
import sys
import tempfile
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Sequence

from masa.config import Limits, DEFAULT_LIMITS

_OUTPUT_CAP = 4 * 1024 * 1024  # bytes of stdout/stderr we keep from a tool


@dataclass
class ToolResult:
    """Outcome of one external tool invocation."""

    tool: str
    returncode: int
    stdout: str
    stderr: str
    duration: float
    timed_out: bool = False
    not_found: bool = False

    @property
    def ok(self) -> bool:
        return self.returncode == 0 and not self.timed_out and not self.not_found


class Sandbox:
    """A private, mode-0700 scratch directory that wipes itself on exit."""

    def __init__(
        self,
        limits: Limits = DEFAULT_LIMITS,
        parent: Path | None = None,
        keep: bool = False,
        prefix: str = "masa-",
    ) -> None:
        self.limits = limits
        self.keep = keep
        self._parent = Path(parent) if parent else None
        self._prefix = prefix
        self.root: Path | None = None

    def __enter__(self) -> "Sandbox":
        if self._parent is not None:
            self._parent.mkdir(parents=True, exist_ok=True)
        raw = tempfile.mkdtemp(prefix=self._prefix, dir=self._parent)
        # mkdtemp already creates 0700, but be explicit: this directory holds
        # decompiled contents of someone's app and possibly their secrets.
        os.chmod(raw, 0o700)
        self.root = Path(raw).resolve()
        return self

    def __exit__(self, *exc_info: object) -> None:
        self.cleanup()

    def subdir(self, name: str) -> Path:
        """A named directory inside the sandbox. Name is not attacker-controlled."""
        if self.root is None:
            raise RuntimeError("sandbox is not active")
        safe = "".join(ch for ch in name if ch.isalnum() or ch in "-_")
        if not safe:
            raise ValueError(f"unusable subdirectory name: {name!r}")
        path = self.root / safe
        path.mkdir(parents=True, exist_ok=True)
        os.chmod(path, 0o700)
        return path

    def cleanup(self) -> None:
        """Wipe the sandbox unless the user asked to keep artifacts."""
        if self.root is None:
            return
        if self.keep:
            return
        # rmtree uses lstat internally, so a symlink inside the tree is unlinked
        # rather than followed. onexc keeps a stubborn file from masking errors.
        shutil.rmtree(self.root, ignore_errors=True)
        self.root = None


def _apply_child_limits(memory_bytes: int, cpu_seconds: int, file_bytes: int):
    """Build a preexec hook that caps what a decompiler subprocess can consume."""

    def _preexec() -> None:  # pragma: no cover - runs in the forked child
        os.setsid()
        for what, limit in (
            (resource.RLIMIT_CPU, cpu_seconds),
            (resource.RLIMIT_FSIZE, file_bytes),
            (resource.RLIMIT_NOFILE, 4096),
        ):
            try:
                soft, hard = resource.getrlimit(what)
                new_soft = limit if hard == resource.RLIM_INFINITY else min(limit, hard)
                resource.setrlimit(what, (new_soft, hard))
            except (ValueError, OSError):
                pass
        # An address-space cap breaks the JVM (it reserves huge virtual regions),
        # so it is deliberately not applied here; wall-clock and CPU caps plus
        # process-group kill are what actually bound a runaway decompiler.

    return _preexec


def _scrubbed_env() -> dict[str, str]:
    """Minimal environment: no inherited secrets, no proxy redirection."""
    keep = ("PATH", "HOME", "LANG", "LC_ALL", "TMPDIR", "JAVA_HOME")
    env = {k: os.environ[k] for k in keep if k in os.environ}
    env.setdefault("PATH", "/usr/local/bin:/usr/bin:/bin")
    # Decompilers have no business reaching the network; unset any proxy config
    # that would let them, and stop the JVM from phoning home.
    env["NO_PROXY"] = "*"
    env["_JAVA_OPTIONS"] = "-Djava.awt.headless=true"
    return env


def tool_available(name: str) -> bool:
    return shutil.which(name) is not None


def run_tool(
    argv: Sequence[str],
    cwd: Path,
    limits: Limits = DEFAULT_LIMITS,
    timeout: int | None = None,
) -> ToolResult:
    """Run an external decompiler. Never uses a shell; always bounded.

    `argv` is a list, so nothing in a filename can be interpreted as a shell
    metacharacter or as an extra argument.
    """
    if not argv:
        raise ValueError("empty command")
    tool = argv[0]
    budget = timeout if timeout is not None else limits.subprocess_timeout_seconds

    if shutil.which(tool) is None:
        return ToolResult(tool, -1, "", f"{tool} not found on PATH", 0.0, not_found=True)

    started = time.monotonic()
    preexec = _apply_child_limits(
        memory_bytes=0,
        cpu_seconds=budget,
        file_bytes=limits.max_extract_bytes,
    )
    try:
        proc = subprocess.Popen(
            list(argv),
            cwd=str(cwd),
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=_scrubbed_env(),
            preexec_fn=preexec if sys.platform != "win32" else None,
            close_fds=True,
        )
    except (OSError, ValueError) as exc:
        return ToolResult(tool, -1, "", f"could not start {tool}: {exc}", 0.0)

    timed_out = False
    try:
        out, err = proc.communicate(timeout=budget)
    except subprocess.TimeoutExpired:
        timed_out = True
        _kill_process_group(proc)
        try:
            out, err = proc.communicate(timeout=10)
        except subprocess.TimeoutExpired:  # pragma: no cover - defensive
            out, err = b"", b""
    duration = time.monotonic() - started

    return ToolResult(
        tool=tool,
        returncode=proc.returncode if proc.returncode is not None else -1,
        stdout=out[:_OUTPUT_CAP].decode("utf-8", "replace"),
        stderr=err[:_OUTPUT_CAP].decode("utf-8", "replace"),
        duration=duration,
        timed_out=timed_out,
    )


def _kill_process_group(proc: subprocess.Popen) -> None:
    """SIGKILL the child's whole process group so grandchildren die too."""
    try:
        os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
    except (ProcessLookupError, PermissionError, OSError):
        try:
            proc.kill()
        except OSError:
            pass
