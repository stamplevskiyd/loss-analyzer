"""
This module writes packages for file corresponding with its group name
"""

from scapy.all import wrpcap
from scapy.packet import Packet

from config import (
    SENT_GROUPS_SOLDER,
    RECEIVED_GROUPS_SOLDER
)
from hash import transport_hash


def write_packet(packet: Packet, packet_type: str, hash_value: int | None = None) -> str:
    """Get hash and save packet to correct folder"""
    if hash_value is None:
        hash_value = transport_hash(packet)

    folder: str = SENT_GROUPS_SOLDER if packet_type == "in" else RECEIVED_GROUPS_SOLDER
    filename: str = f"{folder}/{packet_type}_{hash_value}.pcap"
    wrpcap(filename=filename, pkt=packet)

    return filename
