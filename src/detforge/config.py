"""Project settings: defaults, overridden by [tool.detforge] in pyproject.toml, then by CLI options."""

import tomllib
from dataclasses import dataclass, replace
from pathlib import Path


@dataclass(frozen=True)
class Settings:
    rules: Path = Path("rules")
    fixtures: Path = Path("tests/fixtures")
    out: Path = Path("dist")
    author: str | None = None  # when set, lint requires every rule to carry this author

    @classmethod
    def load(cls, project_dir: Path | None = None) -> "Settings":
        pyproject = (project_dir or Path.cwd()) / "pyproject.toml"
        if not pyproject.is_file():
            return cls()
        with pyproject.open("rb") as fh:
            section = tomllib.load(fh).get("tool", {}).get("detforge", {})
        unknown = set(section) - {"rules", "fixtures", "out", "author"}
        if unknown:
            raise ValueError(f"unknown [tool.detforge] keys in pyproject.toml: {sorted(unknown)}")
        return cls(
            rules=Path(section.get("rules", cls.rules)),
            fixtures=Path(section.get("fixtures", cls.fixtures)),
            out=Path(section.get("out", cls.out)),
            author=section.get("author"),
        )

    def override(
        self, rules: Path | None = None, fixtures: Path | None = None, out: Path | None = None
    ) -> "Settings":
        changes = {k: v for k, v in {"rules": rules, "fixtures": fixtures, "out": out}.items() if v}
        return replace(self, **changes)
