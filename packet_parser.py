from scapy.compat import raw
from scapy.layers.inet import IP, TCP, UDP, ICMP
from scapy.layers.l2 import Ether
from scapy.packet import Packet

from custom_types import ParsedPacketDict


def parse_packet(packet: Packet) -> ParsedPacketDict:
    """Fetch packet headers and body"""
    data: ParsedPacketDict = {"Ethernet": None, "TCP": None, "IP": None, "UDP": None, "ICMP": None}
    layers: list = packet.layers()

    # Process L2
    if Ether in layers:
        data["Ethernet"] = packet[Ether].fields

    # Process L3
    if IP in layers:
        data["IP"] = packet[IP].fields

    # Process transport
    body: bytes | None = None

    if TCP in layers:
        data["TCP"] = packet[TCP].fields
        body = raw(packet[TCP].payload)
    elif UDP in layers:
        data["UDP"] = packet[UDP].fields
        body = raw(packet[UDP].payload)
    elif ICMP in layers:
        data["ICMP"] = packet[ICMP].fields
        body = raw(packet[ICMP].payload)

    data["body"] = body

    return data
