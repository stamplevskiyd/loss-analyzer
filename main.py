from multiprocessing import freeze_support

from config import (
    RESULTS_FOLDER,
    SENT_GROUPS_SOLDER,
    RECEIVED_GROUPS_SOLDER,
)
from packet_processor import PacketProcessor

if __name__ == "__main__":
    freeze_support()
    packet_processor: PacketProcessor = PacketProcessor(
        results_folder=RESULTS_FOLDER,
        sent_groups_folder=SENT_GROUPS_SOLDER,
        received_groups_folder=RECEIVED_GROUPS_SOLDER,
    )
    packet_processor.find_loss()
