import asyncio

DEFAULT_BUFFER_SIZE = 1024


class SiFTMainServer(asyncio.Protocol):
    def connection_made(self, transport : asyncio.Transport):
        peername = transport.get_extra_info('peername')
        print('Connection from {}'.format(peername))
        self.transport = transport
        #TODO login protocol
        #TODO set MessageProxy
        

    def data_received(self, data: bytes) -> None:
        message = data.decode()
        print('Data received: {!r}'.format(message))
        self.transport.write(data)

        self.transport.close()