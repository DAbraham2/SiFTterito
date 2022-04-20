import asyncio
from socket import AF_INET
from core import SiFTMainServer

PORT = 5150
#Requirement - serving clients on TCP port 5150


if __name__ == "__main__":
    loop = asyncio.get_event_loop()
    serverLoop = loop.create_server(SiFTMainServer, 'localhost', PORT, family=AF_INET)
    server = loop.run_until_complete(serverLoop)
    print('Serving on {}'.format(server.sockets[0].getsockname()))
    loop.run_forever()
