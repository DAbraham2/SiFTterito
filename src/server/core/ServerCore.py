import asyncio

DEFAULT_BUFFER_SIZE = 1024


class SiFTMainServer(asyncio.Protocol):
    def connection_made(self, transport):
        peername = transport.get_extra_info('peername')
        print('Connection from {}'.format(peername))
        #Custom logic
        self.transport = transport

    def data_received(self, data: bytes) -> None:
        message = data.decode()
        print('Data received: {!r}'.format(message))
        self.transport.write(data)

        self.transport.close()