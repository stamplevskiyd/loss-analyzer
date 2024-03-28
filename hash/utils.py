from scapy.packet import Packet


def get_transport_header(packet: Packet) -> Packet:
    """Fetch transport level header from packet"""
