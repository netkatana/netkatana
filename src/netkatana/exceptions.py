from typing import Self


class ValidationError(Exception):
    def __init__(self, message: str | list[Self], metadata: dict[str, str] | None = None) -> None:
        if isinstance(message, list):
            self.errors = message
            self.message = None
            self.metadata = {}
        else:
            self.errors = [self]
            self.message = message
            self.metadata = metadata or {}
