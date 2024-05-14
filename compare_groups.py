from typing import Callable

from scapy.packet import Packet


def compare_group(
    sent_packets: list[Packet], received_packets: list[Packet], compare_func: Callable[[..., ...], bool]
) -> tuple[list[Packet], list[Packet]]:
    """
    Compare packet groups and find, which packets are missing
    Saves sent but not received packets in sent_packets
    Saves received but not sent packets in received_packets
    """
    from scapy.all import raw

    sent_idx: int = 0
    while sent_idx < len(sent_packets):
        sent_p: Packet = sent_packets[sent_idx]
        for received_idx, received_p in enumerate(received_packets):
            # if compare_func(sent_p, received_p):
            if raw(sent_p) == raw(received_p):
                sent_packets.pop(sent_idx)
                received_packets.pop(received_idx)
                break
        else:
            sent_idx += 1

    return sent_packets, received_packets
