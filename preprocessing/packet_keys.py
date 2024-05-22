import logging

from config import selected_key_fields
from custom_types import ParsedPacketDict

logger = logging.getLogger(__name__)


def get_packet_key_values(parsed_packet: ParsedPacketDict) -> list[int]:
    """Get list of values of constant packet fields"""
    key_values: list[int] = []

    for protocol_name, protocol_values in selected_key_fields.items():
        if protocol_name in parsed_packet.keys() and parsed_packet[protocol_name]:
            key_values.extend([value for key, value in parsed_packet[protocol_name].items() if key in protocol_values])

    return key_values


def get_packet_key(parsed_packet: ParsedPacketDict) -> bytes:
    """Get key from packet fields"""
    key_values: list[int] = get_packet_key_values(parsed_packet)
    key_values_processed: list[bytes] = [bytes(str(value), "utf-8") for value in key_values]
    return b"".join(key_values_processed)
