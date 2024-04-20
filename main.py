import logging
from pathlib import Path

from config import (
    RESULTS_FOLDER,
    SENT_GROUPS_SOLDER,
    RECEIVED_GROUPS_SOLDER,
)
from packet_processor import PacketProcessor

logger = logging.getLogger(__name__)

"""Create results folder"""
Path(RESULTS_FOLDER).mkdir(parents=True, exist_ok=True)
Path(SENT_GROUPS_SOLDER).mkdir(parents=True, exist_ok=True)
Path(RECEIVED_GROUPS_SOLDER).mkdir(parents=True, exist_ok=True)

packet_processor: PacketProcessor = PacketProcessor()

packet_processor.load_sent_packets()
packet_processor.load_received_packets()

packet_processor.find_lost_packets()
