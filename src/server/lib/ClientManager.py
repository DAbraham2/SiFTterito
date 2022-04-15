
class ClientManager(object):
    """
        A singleton class to represent the session management functionality

        ...

        Attributes
        ----------
        loggen_in_client : Dictionary
            A nested dictionary containing a dictionary of { "server_sqn" : number, "client_sqn" : number, "loggedIn": boolean }
    """

    def __new__(cls) -> Self:
        if not hasattr(cls, 'instance'):
            cls.instance = super(ClientManager, cls).__new__(cls)
        return cls.instance

    def __init__(self) -> None:
        self.logged_in_clients = {}

    def handle_login(self, data) -> None:
        """
        When the server receives the login request message, it should check the received timestamp by comparing it to its current system time.
        The timestamp must fall in an acceptance window around the current time of the server for the login request to be accepted.
        The size of the acceptance window should be configurable to account for network delays.
        A recommended value is 2 seconds, which means that the received timestamp must not be considered fresh by the server if it is smaller than the current time minus 1 second or larger than the current time plus 1 second.
        Preferably, the server should also check if the same request was not recieved in another connection (with another client) within the acceptance time window around the current time at the server.

        Then the server must check the username and password received, by computing the password hash of the password and comparing it to the password hash stored by the server for the given username.
        It is not part of this specification to define which password hash function the server should use and how; this is left for implementations.
        It is recommended, however, to follow best practices in this matter, which means that a secure password hash function, such as PBKDF2, scrypt, or Argon2, should be used with appropriate streching and salting parameters.

        If the verification of timestamp or the verification of the username and password fails, then the server must not respond to the client, but it must close the connection.
        Otherwise, if all verifications succeed, then the server must compute the SHA-256 hash of the payload of the received login request
        (converted to a byte string) to fill in the <request-hash> field of the login response and it must generate a 16-byte fresh random value
        using a cryptographic random number generator to fill in the <server_random> field of the login response.
        The login response is then handed over to the MTP protocol entity of the server in order to send it to the client.
        """

        keys = self.logged_in_clients.keys()
        
        pass
