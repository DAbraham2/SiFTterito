
from asyncio import Transport
from lib.SiFTMTP import MTPMessage


class Executor:
    def executeFromMessage(message: MTPMessage, *, transport : Transport) -> MTPMessage:
        pass
