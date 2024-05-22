ether_const_fields: list[str] = ["type"]  # Scapy seems to support not all of Ethernet fields
ip_const_fields: list[str] = ["version", "ihl", "len", "id", "frag", "proto"]
udp_const_fields: list[str] = ["len", "chksum"]

# TODO: support tcp flags
tcp_const_fields: list[str] = [
    "seq",
    "ack",
    "dataofs",
    "reserved",
    "urgptr",
]
icmp_const_fields: list[str] = ["type", "id", "seq"]

supported_key_fields: dict[str, list[str]] = {
    "Ethernet": ether_const_fields,
    "IP": ip_const_fields,
    "TCP": tcp_const_fields,
    "UDP": udp_const_fields,
    "ICMP": icmp_const_fields,
}
