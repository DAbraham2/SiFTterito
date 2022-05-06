import asyncio
from socket import AF_INET
from core import SiFTMainServer

import logging

logging.basicConfig(level=logging.DEBUG,
                    format='%(asctime)s %(name)-12s %(levelname)-8s %(message)s',
                    datefmt='%m-%d %H:%M:%S',
                    filename='log/siftserver.log')

console = logging.StreamHandler()
console.setLevel(logging.INFO)
formatter = logging.Formatter('%(name)-12s: %(levelname)-8s %(message)s')
console.setFormatter(formatter)
logging.getLogger('').addHandler(console)

PORT = 5150
#Requirement - serving clients on TCP port 5150


if __name__ == "__main__":
    loop = asyncio.get_event_loop()
    serverLoop = loop.create_server(SiFTMainServer, 'localhost', PORT, family=AF_INET)
    server = loop.run_until_complete(serverLoop)
    print('Serving on {}'.format(server.sockets[0].getsockname()))
    logging.info('Server startert on {}'.format(server.sockets[0].getsockname()))
    loop.run_forever()
