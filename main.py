import logging
from pathlib import Path

from scapy.all import rdpcap
from scapy.plist import PacketList

from config import (
    SENT_FILE,
    RESULTS_FOLDER,
    RECEIVED_FILE,
    SENT_GROUPS_SOLDER,
    RECEIVED_GROUPS_SOLDER,
)
from hash.protocols import transport_hash
from writer import write_packet

logger = logging.getLogger(__name__)

"""Create results folder"""
Path(RESULTS_FOLDER).mkdir(parents=True, exist_ok=True)
Path(SENT_GROUPS_SOLDER).mkdir(parents=True, exist_ok=True)
Path(RECEIVED_GROUPS_SOLDER).mkdir(parents=True, exist_ok=True)

"""Group sent and received packets"""
sent_packets: PacketList = rdpcap(SENT_FILE)
for packet in sent_packets:
    hash_value: int = transport_hash(packet)
    write_packet(packet=packet, packet_type="in", hash_value=hash_value)

received_packets: PacketList = rdpcap(RECEIVED_FILE)
for packet in received_packets:
    hash_value: int = transport_hash(packet)
    write_packet(packet=packet, packet_type="out", hash_value=hash_value)
