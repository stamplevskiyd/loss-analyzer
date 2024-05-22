import logging
from datetime import datetime

from scapy.packet import Packet
from scapy.utils import rdpcap

import config
from custom_types import PacketType
from comparator import find_packet_loss
from preprocessing.write import split_packets_by_groups
from utils import create_tmp_folders_if_needed, remove_tmp_folders

logger = logging.getLogger(__name__)


class LossAnalyzer:
    """Main class to process packets"""

    def __init__(self):
        self._start_load_datetime: datetime | None = None
        self._start_compare_datetime: datetime | None = None
        self._end_datetime: datetime | None = None

        self._sent_count: int = 0
        self._received_count: int = 0

        self._sent_groups_keys: set[bytes] = set()
        self._received_groups_keys: set[bytes] = set()

        create_tmp_folders_if_needed()

    def find_loss(self, print_statistics: bool = True) -> None:
        """Find total packets loss"""
        self._start_load_datetime = datetime.now()

        """Load packets and split by groups"""
        sent_packets: list[Packet] = rdpcap(config.sent_file).res
        self._sent_count = len(sent_packets)
        self._sent_groups_keys = split_packets_by_groups(
            sent_packets,
            PacketType.sent,
        )

        received_packets: list[Packet] = rdpcap(config.received_file).res
        self._received_count = len(received_packets)
        self._received_groups_keys = split_packets_by_groups(
            received_packets,
            PacketType.received,
        )

        """Compare groups"""
        self._start_compare_datetime = datetime.now()
        sent_not_received, received_not_sent = find_packet_loss(
            sent_groups_keys=self._sent_groups_keys,
            received_groups_keys=self._received_groups_keys,
        )
        self._end_datetime = datetime.now()

        """Print statistics if needed"""
        if print_statistics:
            self.print_statistics(sent_not_received, received_not_sent)

        try:
            remove_tmp_folders()
        except Exception:
            logger.warning("Failed to delete tmp folders. You need to delete them manually")

    def print_statistics(self, sent_not_received: int, received_not_sent: int) -> None:
        """Get lost packets and print statistics"""
        line: str = "=" * 15 + "\n"
        line += f"String algorithm: {config.string_algorithm}\n"
        if config.use_multiprocessing:
            line += f"Multiprocess version with {config.proc_count} processs\n"
        else:
            line += "Single-process version\n"

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
        line += f"Sent groups count: {len(self._sent_groups_keys)}, received groups count: {len(self._received_groups_keys)}\n"
        line += "=" * 15 + "\n"
        print(line)
