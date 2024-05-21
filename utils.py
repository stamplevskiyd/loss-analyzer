from config import SENT_GROUPS_SOLDER, RECEIVED_GROUPS_SOLDER
from custom_types import PacketType


def get_filename_from_hash(hash_value: bytes, packet_type: PacketType) -> str:
    """Get hash and packet type and create filename"""
    folder: str = SENT_GROUPS_SOLDER if packet_type == "sent" else RECEIVED_GROUPS_SOLDER
    filename: str = f"{folder}/{packet_type}_{str(hash_value, 'utf-8')}.tmp"

    return filename
