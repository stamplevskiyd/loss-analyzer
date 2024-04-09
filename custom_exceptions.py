class NoTransportLayerException(Exception):
    def __init__(self):
        super().__init__(
            "Packet does not have transport layer or transport layer protocol currently is not supported"
        )
