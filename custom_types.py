from enum import StrEnum


class PacketType(StrEnum):
    """Types of packets based on received/sent origin"""
    sent = "sent"
    received = "received"


class PreprocessFuncType(StrEnum):
    """Supported types of functions-preprocessor for group file create"""
    standard = "standard"
    tokenized = "tokenized"

