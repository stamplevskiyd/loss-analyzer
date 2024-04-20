import logging
import os
import multiprocessing
from pathlib import Path
from datetime import datetime

from scapy.layers.inet import TCP, UDP, ICMP, IP
from scapy.layers.l2 import Ether
from scapy.packet import Packet
from scapy.utils import rdpcap, wrpcap
from scapy.all import raw

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
        self._sent_groups: list[str] = []
        self._received_groups: list[str] = []

        self._sent_groups_folder: str = sent_groups_folder
        self._received_groups_folder: str = received_groups_folder
        self._results_folder: str = results_folder

        self._init_folders()

        self._start_datetime: datetime | None = None
        self._end_datetime: datetime | None = None

        self._sent_count: int = 0
        self._received_count: int = 0

    def find_loss(self, print_statistics: bool = True) -> None:
        self._start_datetime = datetime.now()

        self._load_sent_packets()
        self._load_received_packets()
        sent_not_received, received_not_sent = self._find_lost_packets()

        self._end_datetime = datetime.now()
        if print_statistics:
            self._print_statistics(sent_not_received, received_not_sent)

        # self._remove_folders()

    def _init_folders(self) -> None:
        """Create required folders if it does not exist"""
        Path(self._results_folder).mkdir(parents=True, exist_ok=True)
        Path(self._sent_groups_folder).mkdir(parents=True, exist_ok=True)
        Path(self._received_groups_folder).mkdir(parents=True, exist_ok=True)

    def _remove_folders(self) -> None:
        """Remove outdated folders"""
        os.remove(self._received_groups_folder)
        os.remove(self._sent_groups_folder)

    def _load_packets(self, filename: str, file_type: str) -> tuple[list[str], int]:
        """Load packets of some group"""
        packets: list[Packet] = rdpcap(filename).res
        groups: list[str] = []

        for packet in packets:
            hash_value: str = self._get_hash(packet)
            groups.append(hash_value)
            filename: str = get_filename_from_hash(hash_value=hash_value, packet_type=file_type)
            wrpcap(filename=filename, pkt=packet, append=True)

        return groups, len(packets)

    def _load_sent_packets(self) -> None:
        """Load and split sent packets"""
        self._sent_groups, sent_inc = self._load_packets(config.SENT_FILE, "sent")
        self._sent_count += sent_inc

    def _load_received_packets(self) -> None:
        """Load and split received packets"""
        self._received_groups, received_inc = self._load_packets(config.RECEIVED_FILE, "received")
        self._received_count += received_inc

    @classmethod
    def _get_hash(cls, packet: Packet) -> str:
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

    def _compare_group(self, group_id: str) -> tuple[list[Packet], list[Packet]]:
        """
        Compare packet groups and find, which packets are missing
        Saves sent but not received packets in sent_packets
        Saves received but not sent packets in received_packets
        """
        print("Processing group", group_id)
        sent_filename: str = get_filename_from_hash(group_id, "sent")
        sent_packets: list[Packet] = rdpcap(sent_filename).res
        if group_id not in self._received_groups:
            return sent_packets, []

        received_filename: str = get_filename_from_hash(group_id, "received")
        received_packets: list[Packet] = rdpcap(received_filename).res

        sent_idx: int = 0
        while sent_idx < len(sent_packets):
            for received_idx, received_p in enumerate(received_packets):
                if raw(sent_packets[sent_idx]) == raw(received_p):
                    sent_packets.pop(sent_idx)
                    received_packets.pop(received_idx)
                    break
            else:
                sent_idx += 1

        return sent_packets, received_packets

    def _compare_groups(self, groups_ids: list[str], output_queue: multiprocessing.Queue) -> None:
        """Compare multiple groups"""
        sent_not_received, received_not_sent = [], []
        for i, group_id in enumerate(groups_ids):
            print(f"starting group {i} out of {len(groups_ids)}")
            s, r = self._compare_group(group_id)
            sent_not_received.extend(s)
            received_not_sent.extend(r)

        output_queue.put((sent_not_received, received_not_sent))

    def _find_lost_packets(self) -> tuple[list[Packet], list[Packet]]:
        """Find packets that were not delivered"""
        sent_not_received: list[Packet] = []
        received_not_sent: list[Packet] = []

        n_proc = 4
        subgroups = [[] for _ in range(n_proc)]
        for i, group_id in enumerate(self._sent_groups):
            subgroups[i % n_proc].append(group_id)

        output_queue = multiprocessing.Queue()
        processes = []

        for subgroup in subgroups:
            process = multiprocessing.Process(target=self._compare_groups, args=(subgroup, output_queue), daemon=True)
            processes.append(process)
            process.start()

        while not output_queue.empty():
            send_lost, received_lost = output_queue.get()
            sent_not_received.extend(send_lost)
            received_not_sent.extend(received_lost)

        for process in processes:
            process.join()


        return sent_not_received, sent_not_received

    def _print_statistics(self, sent_not_received: list[Packet], received_not_sent: list[Packet]) -> None:
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
