import logging
from multiprocessing import Pool
from functools import partial

import config
from custom_types import PacketType
from utils import get_filename_from_hash

logger = logging.getLogger(__name__)


def compare_group(sent_packets: list[bytes], received_packets: list[bytes]) -> tuple[int, int]:
    """
    Compare packet groups and find, which packets are missing
    Saves sent but not received packets in sent_packets
    Saves received but not sent packets in received_packets
    """
    sent_idx: int = 0
    while sent_idx < len(sent_packets):
        sent_p: bytes = sent_packets[sent_idx]
        for received_idx, received_p in enumerate(received_packets):
            if sent_p == received_p:
                sent_packets.pop(sent_idx)
                received_packets.pop(received_idx)
                break
        else:
            sent_idx += 1

    return len(sent_packets), len(received_packets)


def get_loss_by_group_id(group_id: bytes, received_groups_ids: set[bytes]) -> tuple[int, int]:
    """Find loss based on group_id"""
    with open(get_filename_from_hash(group_id, PacketType.sent), "rb") as sent_file:
        sent_packets: list[bytes] = sent_file.readlines()

    if group_id not in received_groups_ids:
        return len(sent_packets), 0

    with open(get_filename_from_hash(group_id, PacketType.received), "rb") as received_file:
        received_packets: list[bytes] = received_file.readlines()

    return compare_group(sent_packets, received_packets)


def find_packet_loss(
    sent_groups_ids: set[bytes],
    received_groups_ids: set[bytes],
) -> tuple[int, int]:
    """Find lost packets after data was split by groups"""
    sent_not_received: int = 0
    received_not_sent: int = 0

    if config.use_multiprocessing:
        with Pool(processes=config.proc_count) as pool:
            res = pool.map(
                partial(get_loss_by_group_id, received_groups_ids=received_groups_ids),
                sent_groups_ids,
            )

        for proc_result in res:
            sent_p, received_p = proc_result
            sent_not_received += sent_p
            received_not_sent += received_p
    else:
        for group_id in sent_groups_ids:
            sent_p, received_p = get_loss_by_group_id(group_id, received_groups_ids)
            sent_not_received += sent_p
            received_not_sent += received_p

    return sent_not_received, received_not_sent
