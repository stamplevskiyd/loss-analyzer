from multiprocessing import freeze_support

from config import SENT_GROUPS_SOLDER, RECEIVED_GROUPS_SOLDER, USE_MULTIPROCESSING, STRING_ALGORITHM
from packet_processor import PacketProcessor

if __name__ == "__main__":
    if USE_MULTIPROCESSING:
        freeze_support()

    packet_processor: PacketProcessor = PacketProcessor(
        sent_groups_folder=SENT_GROUPS_SOLDER,
        received_groups_folder=RECEIVED_GROUPS_SOLDER,
        string_algorithm=STRING_ALGORITHM,
    )
    packet_processor.find_loss()
