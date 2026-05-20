from dataclasses import dataclass, field


@dataclass
class ExtractResult:
    """Return type for all chain-specific extractors."""
    nodes: list[dict] = field(default_factory=list)
    edges: list[dict] = field(default_factory=list)
    transitions: list[dict] = field(default_factory=list)
