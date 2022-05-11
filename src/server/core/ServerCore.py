import asyncio
import logging

from lib.MessageProxy import SiFTProxy

from core.LoginProtocol import handle_Login

logger = logging.getLogger(__name__)


class SiFTMainServer(asyncio.Protocol):
    def connection_made(self, transport: asyncio.Transport):
        peername = transport.get_extra_info('peername')
        logger.info('Connection from {}'.format(peername))
        try:
            final_transfer_key, username = handle_Login(
                transport, window=120)

            self.proxy = SiFTProxy(transport, final_transfer_key, username)
            logger.info('Connection successfully made')
        except BaseException as e:
            print(e)
            logger.error(e)
            transport.close()

    def data_received(self, data: bytes) -> None:
        try:
            d = data
            while d != b'':
                _len = int.from_bytes(d[4: 6], 'big')
                rec_seq = d[:_len]
                d = d[_len:]
                mtp_message = self.proxy.receive_msg(rec_seq)
                logger.info('{} type message arrived'.format(mtp_message.typ))
                self.proxy.executeMessage(mtp_message)
                if d == b'':
                    logger.info('No more data')
                    break
                
        except BaseException as e:
            print(e)
            logger.error(e)
            self.proxy.close()
