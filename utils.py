import os
from pathlib import Path

import config
from config import sent_groups_folder, received_groups_folder
from custom_types import PacketType


def get_filename_from_key(key_value: bytes, packet_type: PacketType) -> str:
    """Get key and packet type and create filename"""
    folder: str = sent_groups_folder if packet_type == "sent" else received_groups_folder
    filename: str = f"{folder}/{packet_type}_{str(key_value, 'utf-8')}.tmp"

    return filename


def create_tmp_folders_if_needed() -> None:
    """Create required folders if it does not exist"""
    Path(config.received_groups_folder).mkdir(parents=True, exist_ok=True)
    Path(config.sent_groups_folder).mkdir(parents=True, exist_ok=True)


def remove_tmp_folders() -> None:
    """Remove outdated folders"""
    if os.path.exists(config.received_groups_folder):
        os.remove(config.received_groups_folder)
    if os.path.exists(config.sent_groups_folder):
        os.remove(config.sent_groups_folder)
