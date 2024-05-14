import logging
import os
from datetime import datetime
from multiprocessing import Pool
from pathlib import Path

from scapy.packet import Packet
from scapy.utils import rdpcap, wrpcap

import config
from comparator.functions import standard_compare
from compare_groups import compare_group
from hash import get_hash
from utils import get_filename_from_hash

logger = logging.getLogger(__name__)


class PacketProcessor:
    """Main class to process packets"""

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
        if os.path.exists(self._received_groups_folder):
            os.remove(self._received_groups_folder)
        if os.path.exists(self._sent_groups_folder):
            os.remove(self._sent_groups_folder)

    def _load_packets(self, filename: str, file_type: str) -> tuple[list[str], int]:
        """Load packets of some group"""
        packets: list[Packet] = rdpcap(filename).res
        groups: set[str] = set()

        for packet in packets:
            hash_value: str = get_hash(packet)
            groups.add(hash_value)
            filename: str = get_filename_from_hash(hash_value=hash_value, packet_type=file_type)
            wrpcap(filename=filename, pkt=packet, append=True)

        return list(groups), len(packets)

    def _load_sent_packets(self) -> None:
        """Load and split sent packets"""
        self._sent_groups, self._sent_count = self._load_packets(config.SENT_FILE, "sent")

    def _load_received_packets(self) -> None:
        """Load and split received packets"""
        self._received_groups, self._received_count = self._load_packets(config.RECEIVED_FILE, "received")

    def get_loss(self, group_id) -> tuple[list, list]:
        sent_packets: list[Packet] = rdpcap(get_filename_from_hash(group_id, "sent")).res
        if group_id not in self._received_groups:
            return sent_packets, []

        received_packets: list[Packet] = rdpcap(get_filename_from_hash(group_id, "received")).res

        return compare_group(
            sent_packets, received_packets, compare_func=standard_compare
        )

    def _find_lost_packets(self) -> tuple[list[Packet], list[Packet]]:
        """Find packets that were not delivered"""
        sent_not_received: list[Packet] = []
        received_not_sent: list[Packet] = []

        if config.USE_MULTIPROCESSING:
            with Pool(processes=config.PROC_COUNT) as pool:
                res = pool.map(self.get_loss, self._sent_groups)

            for proc_result in res:
                sent_p, received_p = proc_result
                sent_not_received.extend(sent_p)
                received_not_sent.extend(received_p)
        else:
            for group in self._sent_groups:
                sent_p, received_p = self.get_loss(group)
                sent_not_received.extend(sent_p)
                received_not_sent.extend(received_p)

        return sent_not_received, received_not_sent

    def _print_statistics(
        self, sent_not_received: list[Packet], received_not_sent: list[Packet]
    ) -> None:
        """Get lost packets and print statistics"""
        line: str = "=" * 15 + "\n"
        line += f"Sent packets count: {self._sent_count}\n"
        line += f"Received packets count: {self._received_count}\n"
        line += "-" * 15 + "\n"
        line += f"Count of packets that were sent but were not received: {len(sent_not_received)}\n"
        line += f"Count of packets that were received but were not sent: {len(received_not_sent)}\n"
        line += f"Percentage of packets that were sent but were not received: {len(sent_not_received) * 100 / self._sent_count}\n"
        line += "-" * 15 + "\n"
        line += f"Time spent: {(self._end_datetime - self._start_datetime)}\n"
        line += "=" * 15 + "\n"
        print(line)
