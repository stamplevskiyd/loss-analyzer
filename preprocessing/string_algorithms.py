import hashlib

from config import supported_key_fields
from custom_types import ParsedPacketDict


def packet_to_bytes(parsed_packet: ParsedPacketDict) -> bytes:
    """Copy packet symbols one by one"""
    key_values: list[int] = []

    for protocol_name, protocol_values in supported_key_fields.items():
        if protocol_name in parsed_packet.keys() and parsed_packet[protocol_name]:
            key_values.extend([value for key, value in parsed_packet[protocol_name].items() if key in protocol_values])
    headers_compressed: list[bytes] = [bytes(str(value), "utf-8") for value in key_values]
    return b"".join(headers_compressed + [parsed_packet["body"]]).replace(b"\n", b"\\n")


def packet_to_tokens(parsed_packet: ParsedPacketDict) -> bytes:
    """Split packet into tokens and take hash from them"""
    key_values: list[int] = []

    for protocol_name, protocol_values in supported_key_fields.items():
        if protocol_name in parsed_packet.keys() and parsed_packet[protocol_name]:
            key_values.extend([value for key, value in parsed_packet[protocol_name].items() if key in protocol_values])

    tokens: list[bytes] = [hashlib.md5(bytes(str(value), "utf-8")).digest() for value in key_values] + [hashlib.md5(parsed_packet["body"]).digest()]
    return b"".join(tokens).replace(b"\n", b"\\n")
