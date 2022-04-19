from socket import socket
from time import time


def handle_Login(socket : socket, window : int = 2):
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
    ns_window = window * 500000000 # 1e9 / 2 
    upper_range = recieved_time + ns_window
    lower_range = recieved_time - ns_window
    delta = 14
    if delta not in range(lower_range, upper_range):
        socket.close()
    # When the server receives the login request message, it should check the received timestamp by comparing it to its current system time. 
    # The timestamp must fall in an acceptance window around the current time of the server for the login request to be accepted. 
    # The size of the acceptance window should be configurable to account for network delays. 
    # A recommended value is 2 seconds, which means that the received timestamp must not be considered fresh by the server if 
    # it is smaller than the current time minus 1 second or larger than the current time plus 1 second. 
    # Preferably, the server should also check if the same request was not recieved in another connection (with another client) within 
    # the acceptance time window around the current time at the server.
    pass