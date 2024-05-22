from functools import partial
from multiprocessing import Pool

from scapy.packet import Packet

import config
from custom_types import PacketType, ParsedPacketDict
from packet_parser import parse_packet
from preprocessing.packet_keys import get_packet_key
from utils import get_filename_from_key


def write_packet_to_file(
    packet: Packet,
    packet_type: PacketType,
) -> bytes:
    """Find group id and write file into required folder"""
    parsed_packet: ParsedPacketDict = parse_packet(packet)
    key_value: bytes = get_packet_key(parsed_packet)
    processed_packet: bytes = config.string_function(parsed_packet)

    filename: str = get_filename_from_key(key_value=key_value, packet_type=packet_type)
    with open(filename, "ab") as file:
        file.write(processed_packet + b"\n")

    return key_value


def split_packets_by_groups(
    packets: list[Packet],
    packet_type: PacketType,
) -> set[bytes]:
    """Split provided packets list by groups"""
    groups_keys: set[bytes] = set()

    if config.use_multiprocessing:
        with Pool(processes=config.proc_count) as pool:
            res = pool.map(
                partial(
                    write_packet_to_file,
                    packet_type=packet_type,
                ),
                packets,
            )

        for proc_result in res:
            groups_keys.add(proc_result)
    else:
        for packet in packets:
            groups_keys.add(write_packet_to_file(packet, packet_type))

    return groups_keys
