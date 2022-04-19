import asyncio
from MessageProxy import SiFTProxy

from server.core.LoginProtocol import handle_Login

class SiFTMainServer(asyncio.Protocol):
    def connection_made(self, transport : asyncio.Transport):
        peername = transport.get_extra_info('peername')
        print('Connection from {}'.format(peername))
        try:
            self.final_transfer_key = handle_Login(transport.get_extra_info('socket'))
            self.proxy = SiFTProxy()
            self.transport = transport
            #TODO login protocol
            #TODO set MessageProxy
        except:
            transport.close()
        
        

    def data_received(self, data: bytes) -> None:
        mtp_message = self.proxy.receive_msg(data)
        #TODO execute shit
        self.proxy.send_msg(mtp_message, self.transport)