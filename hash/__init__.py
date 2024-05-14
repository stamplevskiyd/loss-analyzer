import logging

from scapy.layers.inet import TCP, UDP, ICMP, IP
from scapy.layers.l2 import Ether
from scapy.packet import Packet

logger = logging.getLogger(__name__)

ether_const_fields: list[str] = ["type"]  # Scapy seems to support not all of Ethernet fields
ip_const_fields: list[str] = ["version", "ihl", "len", "id", "frag", "proto"]
udp_const_fields: list[str] = ["len", "chksum"]
# TODO: support tcp flags
tcp_const_fields: list[str] = ["seq", "ack", "dataofs", "reserved", "urgptr"]
icmp_const_fields: list[str] = ["type", "id", "seq"]


def get_hash(packet: Packet) -> str:
    field_values: list[str] = []
    # Process L2
    if packet.haslayer(Ether):
        field_values.extend([packet[Ether].fields[field] for field in ether_const_fields])

    # Process L3
    if packet.haslayer(IP):
        field_values.extend([packet[IP].fields[field] for field in ip_const_fields])

    # Process transport level
    if packet.haslayer(TCP):
        field_values.extend([packet[TCP].fields[field] for field in tcp_const_fields])
    elif packet.haslayer(UDP):
        field_values.extend([packet[UDP].fields[field] for field in udp_const_fields])
    elif packet.haslayer(ICMP):
        field_values.extend([packet[ICMP].fields[field] for field in icmp_const_fields])

    return "-".join(map(str, field_values))
