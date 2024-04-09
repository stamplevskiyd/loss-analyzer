from config import SENT_GROUPS_SOLDER, RECEIVED_GROUPS_SOLDER


def get_filename_from_hash(hash_value: int, packet_type: str) -> str:
    """Get hash and packet type and create filename"""
    folder: str = SENT_GROUPS_SOLDER if packet_type == "in" else RECEIVED_GROUPS_SOLDER
    filename: str = f"{folder}/{packet_type}_{hash_value}.pcap"

    return filename


def get_hash_from_filename(filename: str) -> int:
    """Get packet hash from filename"""
    return int(filename.split(".pcap")[0].split("_")[1])
