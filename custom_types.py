from enum import StrEnum
from typing import TypedDict, Optional


class PacketType(StrEnum):
    """Types of packets based on received/sent origin"""

    sent = "sent"
    received = "received"


class StringAlgorithmType(StrEnum):
    """Supported types of functions-preprocessor for group file create"""

    standard = "standard"
    tokenized = "tokenized"
    combined = "combined"


class ParsedPacketDict(TypedDict):
    """Structure of dict of packet headers and body"""
    Ethernet: Optional[dict[str, any]]
    IP: Optional[dict[str, any]]
    TCP: Optional[dict[str, any]]
    UDP: Optional[dict[str, any]]
    ICMP: Optional[dict[str, any]]
    body: Optional[bytes]
