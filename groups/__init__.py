import os.path
from typing import Callable

from scapy.packet import Packet

from custom_types import PacketType
from groups.packet_keys import get_packet_key
from groups.packet_processors import packet_to_bytes
from utils import get_filename_from_hash


def write_packet_to_file(
    packet: Packet,
    hash_value: bytes,
    packet_type: PacketType,
    processing_func: Callable[[Packet], bytes] = packet_to_bytes,
):
    """Write packet to certain file"""
    processed_packet: bytes = processing_func(packet)
    filename: str = get_filename_from_hash(hash_value=hash_value, packet_type=packet_type)
    with open(filename, "ab") as file:
        file.write(processed_packet + b"\n")


def split_packets_by_groups(
    packets: list[Packet],
    packet_type: PacketType,
    processing_func: Callable[[Packet], bytes] = packet_to_bytes,
) -> set[bytes]:
    """Split provided packets list by groups"""
    groups_ids: set[bytes] = set()

    for packet in packets:
        hash_value: bytes = get_packet_key(packet)
        groups_ids.add(hash_value)
        write_packet_to_file(packet, hash_value, packet_type, processing_func)

    return groups_ids
