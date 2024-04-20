from pathlib import Path

from scapy.layers.inet import TCP, UDP, ICMP, IP
from scapy.layers.l2 import Ether
from scapy.packet import Packet
from scapy.utils import rdpcap, wrpcap

import config
from utils import get_filename_from_hash


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

    def _init_folders(self) -> None:
        """Create required folders if it does not exist"""
        Path(self._results_folder).mkdir(parents=True, exist_ok=True)
        Path(self._sent_groups_folder).mkdir(parents=True, exist_ok=True)
        Path(self._received_groups_folder).mkdir(parents=True, exist_ok=True)

    def _load_packets(self, filename: str, file_type: str) -> set[str]:
        """Load packets of some group"""
        packets: list[Packet] = rdpcap(filename).res
        groups: set[str] = set()

        for packet in packets:
            hash_value: str = self.get_hash(packet)
            groups.add(hash_value)
            filename: str = get_filename_from_hash(hash_value=hash_value, packet_type=file_type)
            wrpcap(filename=filename, pkt=packet)

        return groups

    def load_sent_packets(self) -> None:
        """Load and split sent packets"""
        self._sent_groups = self._load_packets(config.SENT_FILE, "sent")

    def load_received_packets(self) -> None:
        """Load and split received packets"""
        self._received_groups = self._load_packets(config.RECEIVED_FILE, "received")

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

    def find_lost_packets(self) -> None:
        """Find packets that were not delivered"""
        # TODO: can be parallel
        sent_not_received: list[Packet] = []
        received_not_sent: list[Packet] = []
        for in_group_id in self._sent_groups:

            # Load sent packets
            sent_filename = get_filename_from_hash(in_group_id, "sent")

            # If group not in received, just load all to missing ones
            if in_group_id not in self._received_groups:
                # TODO: can just copy it?
                sent_packets: list[Packet] = rdpcap(sent_filename).res
                filename = "lost_packets.pcap"  # TODO: move to config
                for p in sent_packets:
                    wrpcap(filename=filename, pkt=p)
                continue

            # Have suitable received group, load and sort then
            received_filename = get_filename_from_hash(in_group_id, "received")

            sent_packets: list[Packet] = rdpcap(sent_filename).res
            # sent_packets = sorted(sent_packets, key=lambda packet: packet.time)

            received_packets: list[Packet] = rdpcap(received_filename).res
            # received_packets = sorted(received_packets, key=lambda packet: packet.time)

            self.compare_groups(sent_packets, received_packets, None)
            sent_not_received.extend(sent_packets)
            received_not_sent.extend(received_packets)

        print(sent_not_received)
        print(received_not_sent)
