from dataclasses import dataclass

@dataclass
class EntraUser:
    id: str
    display_name: str
    ip_addresses: set[str]