from scapy.compat import raw
from scapy.packet import Packet

# TODO: real string save and compare


def standard_compare(sent_p: Packet, received_p: Packet) -> bool:
    """Check if sent packet equals to received packet comparing them by symbols"""
    return raw(sent_p) == raw(received_p)


def tokenized_compare(sent_p: Packet, received_p: Packet) -> bool:
    """Check if sent packet equals to received packet comparing them by symbols"""
    return raw(sent_p) == raw(received_p)
