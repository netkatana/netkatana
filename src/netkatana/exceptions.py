from collections.abc import Iterable


class ValidationError(Exception):
    def __init__(self, message: str, metadata: dict[str, str] | None = None) -> None:
        self.message: str = message
        self.metadata: dict[str, str] = metadata or {}


class ValidationErrors(Exception):
    def __init__(self, errors: Iterable[ValidationError]) -> None:
        self.errors: list[ValidationError] = list(errors)
