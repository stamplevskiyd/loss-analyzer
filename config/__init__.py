"""
User config may be incomplete or incorrect
This module fixes all missing data
"""

import multiprocessing
from typing import Callable

from config.constant_fields import (
    ether_const_fields,
    ip_const_fields,
    tcp_const_fields,
    udp_const_fields,
    icmp_const_fields, supported_key_fields
)
from custom_types import StringAlgorithmType
from preprocessing.string_algorithms import packet_to_tokens, packet_to_bytes
from custom_types import ParsedPacketDict

#################################################################
# Default values
#################################################################

sent_file: str = "sent.pcap"
received_file: str = "received.pcap"
sent_groups_folder: str = "sent_groups"
received_groups_folder: str = "received_groups"
use_multiprocessing: bool = False
proc_count: int = 1
string_algorithm: StringAlgorithmType = StringAlgorithmType.tokenized


selected_key_fields: dict[str, list[str]] = supported_key_fields

#################################################################
# Overriding default with user input
#################################################################

from user_config import *

#################################################################
# Fixing user input
#################################################################

if use_multiprocessing:
    proc_count = min(proc_count, multiprocessing.cpu_count())

string_function: Callable[[ParsedPacketDict], bytes] = packet_to_bytes

if string_algorithm == StringAlgorithmType.tokenized:
    string_function = packet_to_tokens
