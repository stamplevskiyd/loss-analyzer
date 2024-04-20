import logging
from pathlib import Path
from datetime import datetime

from scapy.layers.inet import TCP, UDP, ICMP, IP
from scapy.layers.l2 import Ether
from scapy.packet import Packet
from scapy.utils import rdpcap, wrpcap

import config
from utils import get_filename_from_hash

logger = logging.getLogger(__name__)


class PacketProcessor:
    """Main class to process packets"""

    """
    List of constant fields in protocols
    """
    ether_const_fields: list[str] = ["type"]  # Scapy seems to support not all of Ethernet fields
    ip_const_fields: list[str] = ["version", "ihl", "len", "id", "frag", "proto"]
    udp_const_fields: list[str] = ["len", "chksum"]
    # TODO: support tcp flags
    tcp_const_fields: list[str] = ["seq", "ack", "dataofs", "reserved", "urgptr"]
    icmp_const_fields: list[str] = ["type", "id", "seq"]

    def __init__(
        self,
        results_folder: str = "results",
        sent_groups_folder: str = "sent_groups",
        received_groups_folder: str = "received_groups",
    ):
        self._sent_groups: set[str] = set()
        self._received_groups: set[str] = set()

        self._sent_groups_folder: str = sent_groups_folder
        self._received_groups_folder: str = received_groups_folder
        self._results_folder: str = results_folder

        self._init_folders()

        self._start_datetime: datetime | None = None
        self._end_datetime: datetime | None = None

        self._sent_count: int = 0
        self._received_count: int = 0

    def find_loss(self, print_statistics: bool = True) -> None:
        sent_not_received, received_not_sent = self._find_lost_packets()
        if print_statistics:
            self.print_statistics(sent_not_received, received_not_sent)

    def _init_folders(self) -> None:
        """Create required folders if it does not exist"""
        Path(self._results_folder).mkdir(parents=True, exist_ok=True)
        Path(self._sent_groups_folder).mkdir(parents=True, exist_ok=True)
        Path(self._received_groups_folder).mkdir(parents=True, exist_ok=True)

    def _load_packets(self, filename: str, file_type: str) -> tuple[set[str], int]:
        """Load packets of some group"""
        packets: list[Packet] = rdpcap(filename).res
        groups: set[str] = set()

        for packet in packets:
            hash_value: str = self.get_hash(packet)
            groups.add(hash_value)
            filename: str = get_filename_from_hash(hash_value=hash_value, packet_type=file_type)
            wrpcap(filename=filename, pkt=packet)

        return groups, len(packets)

    def load_sent_packets(self) -> None:
        """Load and split sent packets"""
        self._sent_groups, sent_inc = self._load_packets(config.SENT_FILE, "sent")
        self._sent_count += sent_inc

    def load_received_packets(self) -> None:
        """Load and split received packets"""
        self._received_groups, received_inc = self._load_packets(config.RECEIVED_FILE, "received")
        self._received_count += received_inc

    @classmethod
    def get_hash(cls, packet: Packet) -> str:
        field_values: list[str] = []
        # Process L2
        if packet.haslayer(Ether):
            field_values.extend([packet[Ether].fields[field] for field in cls.ether_const_fields])

        # Process L3
        if packet.haslayer(IP):
            field_values.extend([packet[IP].fields[field] for field in cls.ip_const_fields])

        # Process transport level
        if packet.haslayer(TCP):
            field_values.extend([packet[TCP].fields[field] for field in cls.tcp_const_fields])
        elif packet.haslayer(UDP):
            field_values.extend([packet[UDP].fields[field] for field in cls.udp_const_fields])
        elif packet.haslayer(ICMP):
            field_values.extend([packet[ICMP].fields[field] for field in cls.icmp_const_fields])

        return "-".join(map(str, field_values))

    @staticmethod
    def compare_groups(sent_packets: list[Packet], received_packets: list[Packet], sort_func=None) -> None:
        """
        Compare packet groups and find, which packets are missing
        Saves sent but not received packets in sent_packets
        Saves received but not sent packets in received_packets
        """
        if sort_func:
            sent_packets = sort_func(sent_packets)
            received_packets = sort_func(received_packets)

        sent_idx: int = 0
        while sent_packets and received_packets:
            for received_idx, received_p in enumerate(received_packets):
                if sent_packets[sent_idx] == received_p:
                    sent_packets.pop(sent_idx)
                    received_packets.pop(received_idx)
                    break

    def _find_lost_packets(self) -> tuple[list[Packet], list[Packet]]:
        """Find packets that were not delivered"""
        # TODO: can be parallel
        self._start_datetime = datetime.now()
        sent_not_received: list[Packet] = []
        received_not_sent: list[Packet] = []
        for sent_group_id in self._sent_groups:
            logger.info(f"Processing group {sent_group_id}")
            sent_filename = get_filename_from_hash(sent_group_id, "sent")

            sent_packets: list[Packet] = rdpcap(sent_filename).res
            received_packets: list[Packet] = []

            if sent_group_id in self._received_groups:
                received_filename = get_filename_from_hash(sent_group_id, "received")
                received_packets: list[Packet] = rdpcap(received_filename).res
                self.compare_groups(sent_packets, received_packets, None)

            sent_not_received.extend(sent_packets)
            received_not_sent.extend(received_packets)

        self._end_datetime = datetime.now()

        return sent_not_received, received_not_sent

    def print_statistics(self, sent_not_received: list[Packet], received_not_sent: list[Packet]) -> None:
        """Get lost packets and print statistics"""
        line: str = "=" * 15 + "\n"
        line += f"Sent packets count: {self._sent_count}\n"
        line += f"Received packets count: {self._received_count}\n"
        line += "-" * 15 + "\n"
        line += f"Count of packets that were sent but were not received: {len(sent_not_received)}\n"
        line += f"Count of packets that were received but were not sent: {len(received_not_sent)}\n"
        line += f"Percentage of packets that were sent but were not received: {len(sent_not_received) / self._sent_count}\n"
        line += "-" * 15 + "\n"
        line += f"Time spent: {(self._end_datetime - self._start_datetime)}\n"
        line += "=" * 15 + "\n"
        print(line)