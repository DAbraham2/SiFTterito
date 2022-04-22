from asyncio import Transport
from lib.SiFTMTP import MTPMessage, MessageFactory


class SiFTProxy:
    def __init__(self) -> None:
        self.server_sqn = 2
        self.client_sqn = 1

    def receive_msg(self, message: bytes) -> MTPMessage:
        header = message[:16]
        body = message[16:]

        sqn = header[6:8]
        if sqn != self.client_sqn + 1:
            raise ValueError(
                'Received client sequence is not incremental in a correct way')

        self.client_sqn = sqn
        return MessageFactory.create(header, body)

    def send_msg(self, header: bytes, payload: bytes, transport: Transport):
        try:
            header[6:8] = self.server_sqn.to_bytes(2, 'big')
            self.server_sqn = self.server_sqn + 1
            message = MessageFactory.create(header, payload)
            transport.write(message.getMessageAsBytes)
        except:
            raise ValueError()
