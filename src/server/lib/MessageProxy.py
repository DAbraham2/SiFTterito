from asyncio import Transport
from SiFTMTP import MTPMessage, MessageFactory


class SiFTProxy:
    def __init__(self) -> None:
        self.server_sqn = 0
        self.client_sqn = 0

    def receive_msg(self, message : bytes) -> MTPMessage:
        header = message[:16]
        body = message[16:]

        sqn = header[6:8]
        if sqn != self.client_sqn + 1:
            raise ValueError('Received client sequence is not incremental in a correct way')
        
        self.client_sqn = sqn
        return MessageFactory.create(header, body)

    def send_msg(self, message : MTPMessage, transport : Transport):
        
        
        pass