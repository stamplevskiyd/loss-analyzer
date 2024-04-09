from scapy.layers.inet import TCP, UDP, ICMP
from scapy.packet import Packet

from custom_exceptions import NoTransportLayerException


class ProtocolHashBase:
    """Base class for protocol config"""

    hash_fields: list[str] = []

    @classmethod
    def create_hash(cls, packet: Packet) -> int:
        fields_combined: list[str] = [
            str(packet.fields[field]) for field in cls.hash_fields
        ]
        return hash("".join(fields_combined))


class TCPHash(ProtocolHashBase):
    hash_fields: list[str] = ["seq", "ack", "dataofs", "reserved", "flags", "urgptr"]

    @classmethod
    def create_hash(cls, packet: Packet) -> int:
        fields_combined: list[str] = [
            str(packet.fields[field]) for field in cls.hash_fields if field != "flags"
        ]
        fields_combined.append(str(packet.fields["flags"].value))
        return hash("".join(fields_combined))


class UDPHash(ProtocolHashBase):
    hash_fields: list[str] = ["len", "chksum"]


class ICMPHash(ProtocolHashBase):
    hash_fields: list[str] = ["type", "id", "seq"]


def transport_hash(packet: Packet) -> int:
    """Create first-level hash from transport level of packet"""
    transport_level: Packet
    transport_level_type: str

    if packet.haslayer(TCP):
        return TCPHash.create_hash(packet[TCP])
    elif packet.haslayer(UDP):
        return UDPHash.create_hash(packet[UDP])
    elif packet.haslayer(ICMP):
        return ICMPHash.create_hash(packet[ICMP])
    else:
        raise NoTransportLayerException()
