ether_const_fields: list[str] = ["type"]  # Scapy seems to support not all of Ethernet fields
ip_const_fields: list[str] = ["version", "ihl", "len", "id", "frag", "proto"]
udp_const_fields: list[str] = ["len", "chksum"]
tcp_const_fields: list[str] = [
    "seq",
    "ack",
    "dataofs",
    "reserved",
    "urgptr",
]  # TODO: support tcp flags
icmp_const_fields: list[str] = ["type", "id", "seq"]
