import asyncio
from lib.MessageProxy import SiFTProxy

from core.LoginProtocol import handle_Login
from core.SiFTExecutor import Executor


class SiFTMainServer(asyncio.Protocol):
    def connection_made(self, transport: asyncio.Transport):
        peername = transport.get_extra_info('peername')
        print('Connection from {}'.format(peername))
        try:
            self.final_transfer_key, self.username = handle_Login(
                transport.get_extra_info('socket'))
            self.proxy = SiFTProxy()
            self.transport = transport
        except:
            transport.close()

    def data_received(self, data: bytes) -> None:
        try:
            mtp_message = self.proxy.receive_msg(data)
            response = Executor.executeFromMessage(mtp_message)
            self.proxy.send_msg(response, self.transport)
        except:
            self.transport.close()
