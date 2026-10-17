from dataclasses import dataclass, field


@dataclass(frozen=True)
class Metric:
    name: str
    kind: str
    unit: str
    value: int | float
    dimensions: dict[str, str] = field(default_factory=dict)


@dataclass
class Snapshot:
    epoch: str
    metrics: list[Metric]
    warnings: list[str] = field(default_factory=list)


class CollectionError(Exception):
    """Only allowlisted machine codes may leave an adapter."""

    def __init__(self, code: str):
        self.code = code
        super().__init__(code)
