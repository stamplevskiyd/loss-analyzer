"""
This package is responsible for creating first-level hash from transport level headers
"""
from typing import Iterable

from scapy.packet import Packet

from hash.protocols import config_dict, ProtocolConfig


def transport_hash(packet: Packet) -> int:
    """Create first-level hash from transport level of packet"""
    current_packet: Packet = packet
    transport_level: Packet | None = None
    supported_fields: list[str] | None = None
    supported_protocols: Iterable[str] = list(config_dict.keys())

    # TODO: definitely can be more efficient
    while hasattr(current_packet, "payload") and transport_level is None:
        if current_packet.name in supported_protocols:
            transport_level = current_packet.payload
            supported_fields = config_dict[current_packet.name].hash_fields
        else:
            current_packet = current_packet.payload

    return hash("".join([str(current_packet.fields[field_name]) for field_name in supported_fields]))


