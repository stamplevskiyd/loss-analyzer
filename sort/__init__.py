"""
Sort packets
"""

from scapy.packet import Packet


def sort_packets(packets: list[Packet]) -> None:
    """Sort packets list"""
    # TODO: oversimplified version for MVP
    packets.sort(key=lambda packet: packet.time)
