import tomllib
from pathlib import Path

from netkatana.types import Severity

with open(Path(__file__).parent.parent.parent.parent / "checks.toml", "rb") as f:
    _config = tomllib.load(f)


def get_severity(code: str) -> Severity:
    return Severity(_config[code]["severity"])


def get_detail(code: str) -> str:
    return _config[code]["detail"]
