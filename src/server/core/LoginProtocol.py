from socket import socket
from time import time
from SiFTMTP import LoginRequest, LoginResponse, MessageFactory
from Crypto.Hash import SHA256
from Crypto.Random import get_random_bytes
from cryptoStuff import loginFunction


def handle_Login(socket : socket, window : int = 2) -> bytes:
    """
    This method implements the login protocol according to the specification

    ...

    Arguments
    ---------

    socket : socket
        the socket which the client connected to.

    window : int
        The tolerable time window that the message originated from. Default is 2 seconds
    """
    data = socket.recv(1024)
    recieved_time = time.time_ns()
    header = data[:16]
    body = data[16:]
    msg = MessageFactory.create(header, body)
    if isinstance(msg, LoginRequest):
        raise ValueError()

    ns_window = window * 500000000 # 1e9 / 2
    upper_range = recieved_time + ns_window
    lower_range = recieved_time - ns_window
    delta = recieved_time - msg.timestamp

    if delta not in range(lower_range, upper_range):
        raise ValueError()
    
    if not loginFunction(msg.username, msg.password):
        raise ValueError()

    payload = '{}\n{}\n{}\n{}'.format(msg.timestamp, msg.username, msg.password, msg.client_random.hex())
    h = SHA256.new()
    h.update(payload)
    content = h.hexdigest()
    server_random = get_random_bytes(16)

    response_payload = '{}\n{}'.format(content, server_random.hex())
    response = LoginResponse(response_payload, bytes.fromhex('0001'), tk=msg.temporary_key)

    socket.sendall(response.getMessageAsBytes)
    return msg.client_secret + server_random