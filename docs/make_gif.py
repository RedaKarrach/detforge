"""Render docs/assets/demo.gif for DetForge: a passing run, a rule someone "simplified"
failing, and the fix.

    pip install pillow
    python docs/make_gif.py

Runs the real `detforge test` in this repository (FORCE_COLOR keeps the colours),
temporarily loosens the PowerShell rule for the failing scene, and restores it.
"""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "docs"))
from termgif import Scene, build

RULE = ROOT / "rules" / "windows" / "execution" / "powershell_encoded_command.yml"
ENV = {
    **os.environ,
    "COLUMNS": "86",
    "FORCE_COLOR": "1",
    "TERM": "xterm-256color",
    "PYTHONIOENCODING": "utf-8",
}


def run(*args: str) -> str:
    exe = shutil.which("detforge") or str(ROOT / ".venv" / "Scripts" / "detforge.exe")
    p = subprocess.run(
        [exe, *args],
        cwd=ROOT,
        env=ENV,
        capture_output=True,
        text=True,
        encoding="utf-8",
        check=False,
    )
    return (p.stdout + p.stderr).rstrip()


def main() -> None:
    original = RULE.read_text(encoding="utf-8")
    try:
        passing = run("test")
        RULE.write_text(
            original.replace("    condition: all of selection_*", "    condition: selection_img"),
            encoding="utf-8",
        )
        failing = run("test")
    finally:
        RULE.write_text(original, encoding="utf-8")
    fixed = run("test")
    build(
        [
            Scene("detforge — unit tests for detection rules", "detforge test", passing, hold=14),
            Scene(
                'detforge — six months later, someone "simplifies" the rule',
                "detforge test",
                failing,
                intro='# someone "simplified" the rule:  condition: all of selection_*  ->  selection_img',
                hold=24,
            ),
            Scene(
                "detforge — the build gate did its job",
                "git checkout -- rules/ && detforge test",
                fixed,
                hold=16,
            ),
        ],
        ROOT / "docs" / "assets" / "demo.gif",
    )


if __name__ == "__main__":
    main()
