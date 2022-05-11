import logging
from asyncio import Transport

from lib.constants import MTPConstants
from lib.DirectoryManager import DirManager
from lib.MessageCommandProcessor import MTPv1CommandFactory
from lib.SiFTMTP import MessageFactory, MTPMessage, MTPv1Message

logger = logging.getLogger(__name__)

SEGMENT_SIZE = 1024


class SiFTProxy:
    def __init__(self, transport: Transport, final_transfer_key: bytes, username: str) -> None:
        self.server_sqn = 2
        self.client_sqn = 1
        self.transport = transport
        self.directoryManager = DirManager(username)
        self.transfer_key = final_transfer_key
        self.logger = logging.getLogger(__name__)
        self.logger.debug('Proxy __init__(final_transfer_key: {}, username: {})'.format(
            final_transfer_key.hex(), username))

    def receive_msg(self, message: bytes) -> MTPMessage:
        self.logger.debug(f'msg reveiced: {message}')
        header = message[:16]
        body = message[16:]

        sqn = header[6:8]
        sqn = int.from_bytes(sqn, 'big')
        if sqn != self.client_sqn + 1:
            self.logger.error('Incorrect sequence number: required: {}, arrived: {}'.format(
                self.client_sqn+1, sqn))
            raise ValueError(
                'Received client sequence is not incremental in a correct way')

        self.client_sqn = sqn
        return MessageFactory.create(header,
                                     body,
                                     transfer_key=self.transfer_key)

    def executeMessage(self, message: MTPv1Message):
        if message.typ is MTPConstants.DownloadRequestType:
            self.logger.info('Started download protocol')
            self.DnlProtocol(message.content.decode('utf-8'))
        else:
            cmd = MTPv1CommandFactory.getCommandFromMessage(message)
            header, payload = cmd.do(dm=self.directoryManager)
            if not payload == '' or not header == b'':
                self.logger.debug('message is being sent')
                self.send_msg(header, payload.encode('utf-8'))
            else:
                self.logger.debug('message not sent')

    def send_msg(self, header: bytes, payload: bytes):
        try:
            mHead = header[0:6] + \
                self.server_sqn.to_bytes(2, 'big') + header[8:16]
            self.server_sqn = self.server_sqn + 1
            message = MessageFactory.create(
                mHead, payload, transfer_key=self.transfer_key)
            self.transport.write(message.getMessageAsBytes())
        except BaseException as err:
            self.logger.error('Error in send_msg ' + err)
            raise ValueError(err)

    def DnlProtocol(self, content: str) -> None:
        self.logger.debug(f'DnlProtocol with content: {content}')
        if(content == 'Ready'):
            with open(self.directoryManager.file_to_download, 'rb') as f:
                while True:
                    data = f.read(SEGMENT_SIZE)
                    if data == b'':
                        break
                    header = getRes0Header() if len(data) == SEGMENT_SIZE else getRes1Header()
                    self.send_msg(header, data)
            self.logger.info('Download protocol executed')
        else:
            self.logger.info('Download protocol cancelled')
            self.directoryManager.file_to_download = None

    def close(self):
        self.logger.info('Transport is closed')
        self.transport.close()


def getRes0Header() -> bytes:
    return MTPv1Message(typ=MTPConstants.Download0ResponseType).getHeader()


def getRes1Header() -> bytes:
    return MTPv1Message(typ=MTPConstants.Download1ResponseType).getHeader()
