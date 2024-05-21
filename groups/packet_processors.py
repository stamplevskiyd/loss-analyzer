from scapy.compat import raw
from scapy.layers.inet import TCP, UDP, ICMP
from scapy.packet import Packet

from groups.packet_keys import get_packet_key_values


def packet_to_bytes(packet: Packet) -> bytes:
    """Copy packet symbols one by one"""
    return raw(packet).replace(b"\n", b"\\n")


def packet_to_hash(packet: Packet) -> bytes:
    """Split packet into tokens and take hash from them"""
    tokens: list[int] = list(map(hash, get_packet_key_values(packet)))
    body: bytes | None = None

    """Get body"""
    if packet.haslayer(TCP):
        body = raw(packet[TCP])
    elif packet.haslayer(UDP):
        body = raw(packet[UDP])
    elif packet.haslayer(ICMP):
        body = raw(packet[ICMP])

    if body:
        tokens.append(hash(body))

    return b"".join(map(bytes, tokens))
