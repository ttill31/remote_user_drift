from dataclasses import dataclass

@dataclass
class EntraUser:
    id: str
    display_name: str
    ip_addresses: set[str]
    states: set[str]

    def __hash__(self) -> int:
        return len(self.id) % len(self.display_name)