import logging

from scapy.layers.inet import TCP, UDP, ICMP, IP
from scapy.layers.l2 import Ether
from scapy.packet import Packet

from config.constant_fields import (
    ether_const_fields,
    ip_const_fields,
    tcp_const_fields,
    udp_const_fields,
    icmp_const_fields,
)

logger = logging.getLogger(__name__)


def get_packet_key_values(packet: Packet) -> list[int]:
    """Get list of values of constant packet fields"""
    key_values: list[int] = []
    layers: list = packet.layers()

    """Process L2"""
    if Ether in layers:
        key_values.extend([packet[Ether].fields[field] for field in ether_const_fields])

    """Process L3"""
    if IP in layers:
        key_values.extend([packet[IP].fields[field] for field in ip_const_fields])

    """Process transport"""
    if TCP in layers:
        key_values.extend([packet[TCP].fields[field] for field in tcp_const_fields])
    elif UDP in layers:
        key_values.extend([packet[UDP].fields[field] for field in udp_const_fields])
    elif ICMP in layers:
        key_values.extend([packet[ICMP].fields[field] for field in icmp_const_fields])

    return key_values


def get_packet_key(packet: Packet) -> bytes:
    """Get key from packet fields"""
    key_values: list[int] = get_packet_key_values(packet)
    key_values_processed: list[bytes] = [bytes(str(value), "utf-8") for value in key_values]
    return b"-".join(key_values_processed)
