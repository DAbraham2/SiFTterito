import asyncio
from lib.MessageProxy import SiFTProxy

from core.LoginProtocol import handle_Login
from core.SiFTExecutor import Executor


class SiFTMainServer(asyncio.Protocol):
    def connection_made(self, transport: asyncio.Transport):
        peername = transport.get_extra_info('peername')
        print('Connection from {}'.format(peername))
        try:
            final_transfer_key, username = handle_Login(
                transport.get_extra_info('socket'))
            self.proxy = SiFTProxy(transport, final_transfer_key, username)
        except:
            transport.close()

    def data_received(self, data: bytes) -> None:
        try:
            mtp_message = self.proxy.receive_msg(data)
            header, payload = Executor.executeFromMessage(mtp_message)
            self.proxy.send_msg(header, payload, self.transport)
        except:
            self.proxy.close()
