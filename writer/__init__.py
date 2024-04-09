"""
This module writes packages for file corresponding with its group name
"""

from scapy.all import wrpcap
from scapy.packet import Packet

from hash.protocols import transport_hash
from utils import get_filename_from_hash


def write_packet(
    packet: Packet, packet_type: str, hash_value: int | None = None
) -> str:
    """Get hash and save packet to correct folder"""
    if hash_value is None:
        hash_value = transport_hash(packet)

    filename: str = get_filename_from_hash(
        hash_value=hash_value, packet_type=packet_type
    )
    wrpcap(filename=filename, pkt=packet)

    return filename
