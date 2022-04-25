from asyncio import Transport
from DirectoryManager import DirManager
from MessageCommandProcessor import MTPv1CommandFactory
from SiFTMTP import MTPv1Message
from lib.SiFTMTP import MTPMessage, MessageFactory


class SiFTProxy:
    def __init__(self, transport : Transport, final_transfer_key : bytes, username : str) -> None:
        self.server_sqn = 2
        self.client_sqn = 1
        self.transport = transport
        self.directoryManager = DirManager(username)
        self.transfer_key = final_transfer_key

    def receive_msg(self, message: bytes) -> MTPMessage:
        header = message[:16]
        body = message[16:]

        sqn = header[6:8]
        if sqn != self.client_sqn + 1:
            raise ValueError(
                'Received client sequence is not incremental in a correct way')

        self.client_sqn = sqn
        return MessageFactory.create(header, body)


    def executeMessage(self, message : MTPv1Message):
        cmd = MTPv1CommandFactory.getCommandFromMessage(message)
        header, payload = cmd.do(dm=self.directoryManager)

        self.send_msg(header, bytes(payload, 'utf-8'))
        pass
        

    def send_msg(self, header: bytes, payload: bytes):
        try:
            header[6:8] = self.server_sqn.to_bytes(2, 'big')
            self.server_sqn = self.server_sqn + 1
            message = MessageFactory.create(header, payload)
            self.transport.write(message.getMessageAsBytes)

            #TODO download protocol
        except:
            raise ValueError()

    def close(self):
        self.transport.close()
