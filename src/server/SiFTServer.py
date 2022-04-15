import logging
import socketserver
from datetime import datetime, timezone

from SiFTterito.src.server.lib.ClientManager import ClientManager

class SiFTserverTCPHandler(socketserver.BaseRequestHandler):
    """

    """

    def __init__(self, request, client_address, server) -> None:
        self.logger = logging.getLogger('SiFTserverTCPHandler')
        self.logger.debug('__init__')
        self.logger.debug('client address: ' + client_address[0])
        
        super().__init__(request, client_address, server)

    def setup(self) -> None:
        self.logger.debug('setup')
        return super().setup()

    def handle_login(self, data) -> None:
        self.logger.debug('handle_login')
        cm = ClientManager()
        cm.logged_in_clients

    def handle(self) -> None:
        self.logger.debug('handle')
        self.logger.debug(self.client_address[0])
        
        data = self.request.recv(1024).strip()
        cm = ClientManager()
        if not cm.logged_in_clients:
            handle_login(self)

        if (data != bytes("feri")): 
            raise ValueError()
        self.request.sendall(data.upper())


class SiFTServer(socketserver.TCPServer):
    def __init__(self, server_address: str, RequestHandlerClass, bind_and_activate: bool = True) -> None:
        self.logger = logging.getLogger(self.__class__.__name__)
        super().__init__((server_address, 5150), RequestHandlerClass, bind_and_activate)

    def handle_error(self, request, client_address) -> None:
        self.logger.error('{}:Error from client: '.format(datetime.now(timezone.utc)) + client_address[0])
        request.close()


if __name__ == "__main__":
    HOST = 'localhost'
    logging.basicConfig(filename='server.log',
                        encoding='utf-8', level=logging.DEBUG)
    with SiFTServer(HOST, SiFTserverTCPHandler) as server:
        # Activate the server; this will keep running until you
        # interrupt the program with Ctrl-C
        server.serve_forever()
