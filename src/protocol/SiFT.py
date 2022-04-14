from SiFTterito.src.protocol.SiFT_MTP import MessageBase


class SiFT:
    def __init__(self) -> None:
        pass

    def getFactory() -> None:
        print("getFactory")


class SiFTMessageFactory:
    def __init__(self) -> None:
        pass

    def CreateMessage(message_type: str) -> MessageBase:
        print(message_type)


