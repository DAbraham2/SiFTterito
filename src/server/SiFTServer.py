import argparse
import asyncio
import logging
from socket import AF_INET

from core import SiFTMainServer

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
# Requirement - serving clients on TCP port 5150

parser = argparse.ArgumentParser()

parser.add_argument('--host', type=str, help='hostname to serve on')
parser.add_argument('--port', type=int, help='A port to listen to')

if __name__ == "__main__":
    host = ''
    port = PORT
    args = parser.parse_args()

    if args.host:
        host = args.host

    if args.port:
        port = args.port

    logging.info(f'host: {host}\tport: {port}')
    loop = asyncio.get_event_loop_policy().get_event_loop()
    sLoop = loop.create_server(SiFTMainServer, host, port, family=AF_INET)
    server = loop.run_until_complete(sLoop)
    logging.info(f'Serving on {server.sockets[0].getsockname()}')
    loop.run_forever()
