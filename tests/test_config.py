from pathlib import Path

import pytest

from detforge.config import Settings


def test_defaults_without_pyproject(tmp_path: Path) -> None:
    cfg = Settings.load(tmp_path)
    assert cfg == Settings()
    assert cfg.author is None


def test_pyproject_section_overrides_defaults(tmp_path: Path) -> None:
    (tmp_path / "pyproject.toml").write_text(
        '[tool.detforge]\nrules = "sigma"\nfixtures = "events"\nauthor = "Reda"\n'
    )
    cfg = Settings.load(tmp_path)
    assert (cfg.rules, cfg.fixtures, cfg.out, cfg.author) == (
        Path("sigma"),
        Path("events"),
        Path("dist"),
        "Reda",
    )


def test_cli_values_override_pyproject(tmp_path: Path) -> None:
    (tmp_path / "pyproject.toml").write_text('[tool.detforge]\nrules = "sigma"\n')
    cfg = Settings.load(tmp_path).override(rules=Path("other"), out=Path("build"))
    assert (cfg.rules, cfg.out) == (Path("other"), Path("build"))


def test_unknown_key_is_rejected(tmp_path: Path) -> None:
    (tmp_path / "pyproject.toml").write_text('[tool.detforge]\nrulez = "sigma"\n')
    with pytest.raises(ValueError, match="rulez"):
        Settings.load(tmp_path)
