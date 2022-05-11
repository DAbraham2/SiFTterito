import asyncio
import errno
import logging
import time
from socket import socket

from Crypto.Hash import SHA256
from Crypto.Random import get_random_bytes
from lib.cryptoStuff import deriveTransferKey, loginFunction
from lib.SiFTMTP import LoginRequest, LoginResponse, MessageFactory

logger = logging.getLogger(__name__)

def recv_nonblock(soc : socket) -> bytes:
    data = None
    while True:
        try:
            data = soc.recv(1024)
            if not data is None:
                break
        except OSError as e:
            if e.errno != errno.EWOULDBLOCK:
                logger.error('OSError errno: {}'.format(e.errno))
                raise e
    return data

def handle_Login(transport : asyncio.Transport, window : int = 2) -> tuple[bytes, str]:
    """
    This method implements the login protocol according to the specification

    ...

    Arguments
    ---------

    transport : Transport
        the socket which the client connected to.

    window : int
        The tolerable time window that the message originated from. Default is 2 seconds
    """
    logger.info('Login protocol started')
    data = recv_nonblock(transport.get_extra_info('socket')) # this pops an OSError blocking
    recieved_time = time.time_ns()
    header = data[:16]
    body = data[16:]
    msg = MessageFactory.create(header, body)
    if not isinstance(msg, LoginRequest):
        raise ValueError('Not loginRequest')

    ns_window = window * 500000000 # 1e9 / 2
    upper_range = recieved_time + ns_window
    lower_range = recieved_time - ns_window
    delta = recieved_time - msg.timestamp

    if not msg.timestamp in range(lower_range, upper_range):
        raise ValueError('Timestamp not in range')
    
    if not loginFunction(msg.username, msg.password):
        raise ValueError('Username or password failure')

    payload = '{}\n{}\n{}\n{}'.format(msg.timestamp, msg.username, msg.password, msg.client_secret.hex())
    h = SHA256.new()
    h.update(payload.encode('utf-8'))
    content = h.hexdigest()
    
    server_random = get_random_bytes(16)

    response_payload = '{}\n{}'.format(content, server_random.hex())
    response = LoginResponse(response_payload.encode('utf-8'), bytes.fromhex('0001'), tk=msg.temporary_key)

    transport.write(response.getMessageAsBytes())
    logger.info('Login protocol successful')
    return (deriveTransferKey((msg.client_secret + server_random), bytes.fromhex(content)), msg.username)
