
from asyncio import Transport
from lib.SiFTMTP import MTPMessage
from lib.cryptoStuff import getHash

class Executor:
    def executeFromMessage(message: MTPMessage, *, transport : Transport) -> MTPMessage:
        request_hash = getHash(message.content)
        pass
