from asyncio import Transport

from SiFTterito.src.server.lib.constants import MTPConstants

from lib.DirectoryManager import DirManager
from lib.MessageCommandProcessor import MTPv1CommandFactory
from lib.SiFTMTP import MessageFactory, MTPMessage, MTPv1Message


SEGMENT_SIZE = 1024

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
        return MessageFactory.create(header, 
                                        body, 
                                        transfer_key=self.transfer_key)


    def executeMessage(self, message : MTPv1Message):
        if message.typ is MTPConstants.DownloadRequestType:
            self.DnlProtocol(message.content.decode('utf-8'))
        else:
            cmd = MTPv1CommandFactory.getCommandFromMessage(message)
            header, payload = cmd.do(dm=self.directoryManager)
            self.send_msg(header, bytes(payload, 'utf-8'))
        
        

    def send_msg(self, header: bytes, payload: bytes):
        try:
            header[6:8] = self.server_sqn.to_bytes(2, 'big')
            self.server_sqn = self.server_sqn + 1
            message = MessageFactory.create(header, payload, transfer_key=self.transfer_key)
            self.transport.write(message.getMessageAsBytes)
        except:
            raise ValueError()


    def DnlProtocol(self, content: str) -> None:
        if(content is 'Ready'):
            with open(self.directoryManager.file_to_download, 'rb') as f:
                while True:
                    data = f.read(SEGMENT_SIZE)
                    if data is b'':
                        break
                    header = getRes0Header() if len(data) == SEGMENT_SIZE else getRes1Header()
                    self.send_msg(header, data)
        else:
            self.directoryManager.file_to_download = None

    def close(self):
        self.transport.close()



def getRes0Header()->bytes:
    return MTPv1Message(typ=MTPConstants.Download0ResponseType).getHeader()

def getRes1Header()->bytes:
    return MTPv1Message(typ=MTPConstants.Download1ResponseType).getHeader()