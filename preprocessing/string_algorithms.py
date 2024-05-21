import hashlib

from scapy.compat import raw
from scapy.layers.inet import TCP, UDP, ICMP
from scapy.packet import Packet

from preprocessing.packet_keys import get_packet_key_values


def packet_to_bytes(packet: Packet) -> bytes:
    """Copy packet symbols one by one"""
    return raw(packet).replace(b"\n", b"\\n")


def tokens_and_body(packet: Packet) -> tuple[bytes, bytes]:
    """Split packets into header tokens and body"""
    tokens: list[int] = list(map(hash, get_packet_key_values(packet)))
    body: bytes | None = None

    """Get body"""
    if packet.haslayer(TCP):
        body = raw(packet[TCP].payload)
    elif packet.haslayer(UDP):
        body = raw(packet[UDP].payload)
    elif packet.haslayer(ICMP):
        body = raw(packet[ICMP].payload)

    processed_tokens: list[bytes] = [bytes(str(value), "utf-8") for value in tokens]
    return b"-".join(processed_tokens).replace(b"\n", b"\\n"), body


def packet_to_tokens(packet: Packet) -> bytes:
    """Split packet into tokens and take hash from them"""
    tokens, body = tokens_and_body(packet)
    return tokens + hashlib.md5(body).digest().replace(b"\n", b"\\n")


def packet_combined(packet: Packet) -> bytes:
    """Split header into tokens and use the same body"""
    tokens, body = tokens_and_body(packet)
    return tokens + body.replace(b"\n", b"\\n")
