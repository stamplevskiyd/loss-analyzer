import logging
import os
from datetime import datetime
from pathlib import Path
from typing import Callable

from scapy.packet import Packet
from scapy.utils import rdpcap

import config
from custom_types import PacketType, StringAlgorithmType
from groups import split_packets_by_groups
from groups.packet_processors import packet_to_hash, packet_to_bytes
from loss_finder import find_packet_loss

logger = logging.getLogger(__name__)


class PacketProcessor:
    """Main class to process packets"""

    def __init__(
        self,
        sent_groups_folder: str,
        received_groups_folder: str,
        string_algorithm: StringAlgorithmType,
    ):
        self._start_load_datetime: datetime | None = None
        self._start_compare_datetime: datetime | None = None
        self._end_datetime: datetime | None = None

        self._sent_count: int = 0
        self._received_count: int = 0

        self._sent_groups_ids: set[bytes] = set()
        self._received_groups_ids: set[bytes] = set()

        self._sent_groups_folder: str = sent_groups_folder
        self._received_groups_folder: str = received_groups_folder

        self._string_algorithm: Callable[[Packet], bytes] = (
            packet_to_hash if string_algorithm == StringAlgorithmType.tokenized else packet_to_bytes
        )

        self._init_folders()

    def find_loss(self, print_statistics: bool = True) -> None:
        """Find total packets loss"""
        """Load packets and split by groups"""
        self._start_load_datetime = datetime.now()

        sent_packets: list[Packet] = rdpcap(config.SENT_FILE).res
        self._sent_count = len(sent_packets)
        self._sent_groups_ids = split_packets_by_groups(sent_packets, PacketType.sent, processing_func=self._string_algorithm)

        received_packets: list[Packet] = rdpcap(config.RECEIVED_FILE).res
        self._received_count = len(received_packets)
        self._received_groups_ids = split_packets_by_groups(received_packets, PacketType.received, processing_func=self._string_algorithm)

        """Compare groups"""
        self._start_compare_datetime = datetime.now()
        sent_not_received, received_not_sent = find_packet_loss(
            sent_groups_ids=self._sent_groups_ids,
            received_groups_ids=self._received_groups_ids,
        )
        self._end_datetime = datetime.now()

        """Print statistics if needed"""
        if print_statistics:
            self.print_statistics(sent_not_received, received_not_sent)

        try:
            self._remove_folders()
        except Exception:
            logger.warning("Failed to delete tmp folders. You need to delete them manually")

    def print_statistics(self, sent_not_received: int, received_not_sent: int) -> None:
        """Get lost packets and print statistics"""
        line: str = "=" * 15 + "\n"
        line += f"Sent packets count: {self._sent_count}\n"
        line += f"Received packets count: {self._received_count}\n"
        line += "-" * 15 + "\n"
        line += f"Count of packets that were sent but were not received: {sent_not_received}\n"
        line += f"Count of packets that were received but were not sent: {received_not_sent}\n"
        line += f"Percentage of packets that were sent but were not received: {sent_not_received * 100 / self._sent_count}\n"
        line += "-" * 15 + "\n"
        line += f"Time spent: {(self._end_datetime - self._start_load_datetime)}\n"
        line += f"Time spent on packet load: {(self._start_compare_datetime - self._start_load_datetime)}\n"
        line += (
            f"Time spent on packet compare: {(self._end_datetime - self._start_compare_datetime)}\n"
        )
        line += "=" * 15 + "\n"
        print(line)

    def _init_folders(self) -> None:
        """Create required folders if it does not exist"""
        Path(self._sent_groups_folder).mkdir(parents=True, exist_ok=True)
        Path(self._received_groups_folder).mkdir(parents=True, exist_ok=True)

    def _remove_folders(self) -> None:
        """Remove outdated folders"""
        if os.path.exists(self._received_groups_folder):
            os.remove(self._received_groups_folder)
        if os.path.exists(self._sent_groups_folder):
            os.remove(self._sent_groups_folder)
