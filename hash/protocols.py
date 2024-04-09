from abc import ABC, abstractmethod


class ProtocolConfig(ABC):
    """Base class for protocol config"""

    @classmethod
    @abstractmethod
    def hash_fields(cls) -> list[str]:
        """List of fields that will be transformed to first level hash"""
        ...

    @classmethod
    @abstractmethod
    def name(cls) -> str:
        """Protocol name"""
        ...


class TCPConfig(ProtocolConfig):
    name: str = "TCP"
    hash_fields: list[str] = ["seq", "ack", "dataofs", "reserved", "flags", "urgptr"]


class UDPConfig(ProtocolConfig):
    name: str = "UDP"
    hash_fields: list[str] = ["len", "chksum"]


class ICMPConfig(ProtocolConfig):
    name: str = "ICMP"
    hash_fields: list[str] = ["type", "id", "seq"]

config_dict: dict[str, type[ProtocolConfig]] = {config.name: config for config in ProtocolConfig.__subclasses__()}
