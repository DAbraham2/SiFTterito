import os.path
from msvcrt import getch
from os import system
from os import name as osname
import socket
import sys
import logging
from Crypto.Hash import SHA256
from Crypto.Protocol.KDF import HKDF
from os.path import exists


file_dir = os.path.dirname(__file__)
protocol_dir = os.path.join(file_dir, '../', 'protocol')
sys.path.append(protocol_dir)
from SiFT_MTP import LoginRequestMessage, LoginResponseMessage, CommandRequestMessage, CommandResponseMessage, \
    UploadRequest0Message, UploadRequest1Message, UploadResponseMessage


class SiFTClient:
    def __init__(self, HOST, PORT, pubkey_path):
        logging.basicConfig(filename='SiFTClient.log', encoding='utf-8', level=logging.DEBUG)
        self.logger = logging.getLogger(__name__)
        self.logger.debug('__init__')
        self.logger.info("Initialization")
        self.ui = self.UI()
        self.host = HOST
        self.port = PORT
        self.logged_in = False
        self.pubkey_path = pubkey_path
        self.sqn = b'\x00\x00'
        self.final_key = None
        self.sock = None

    def connect(self):
        self.logger.debug('connect')
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.connect((self.host, self.port))
            self.logger.info("Connection established")
            return sock
        except Exception as e:
            self.logger.error(f"Error during connecting: {e}")

    def increase_sqn(self):
        self.sqn = (int.from_bytes(self.sqn, 'big') + 1).to_bytes(2, byteorder='big')

    def client_login(self):
        self.logger.debug('login')
        username, password = self.ui.login_window(self.logged_in)
        self.increase_sqn()
        self.logger.info("Starting Login Protocol")
        login_req_message, message_hash, client_random, temp_key = LoginRequestMessage(self.pubkey_path,
                                                                                       [username, password],
                                                                                       self.sqn).login_request()
        self.logger.debug(f"Login request: \nUsername: {username}\n"
                          f"Password: {password}\n"
                          f"SQN: {self.sqn}\n"
                          f"Login request message: {login_req_message}\n"
                          f"Message hash: {message_hash}\n"
                          f"My random: {client_random}\n"
                          f"Temp key: {temp_key}")
        return login_req_message, message_hash, client_random, temp_key, username, password

    def response_decrypt(self, res, key, message_hash):
        self.logger.info("Response decrypt")
        self.logger.debug(f"Response: {res}")
        dec_payload, self.sqn = LoginResponseMessage(res, self.sqn, key,
                                                     message_hash).parse_message()
        return dec_payload

    def command_message(self, command):
        formatted_message = self.command_format(command)
        self.logger.debug(formatted_message)
        command_req_message, message_hash = CommandRequestMessage(formatted_message, self.sqn,
                                                                  self.final_key).command_request()
        self.logger.debug(
            f"SQN: {self.sqn}\n"
            f"Request message: {command_req_message}\n"
            f"Message hash: {message_hash}\n")
        return command_req_message, message_hash

    def upload_request(self, command):
        size = os.path.getsize(command[1])
        upload_file = open(command[1], 'rb')
        l = upload_file.read(1024)  # each time we only send 1024 bytes of data
        msg_hash = None
        while size > 0:
            print('File uploading...')
            if size <= 1024:
                file_fragment, msg_hash = UploadRequest1Message(l, self.sqn, self.final_key).send_file_last_fragment()
                self.sock.sendall(file_fragment)
                self.logger.info("File sent")
            else:
                file_fragment, msg_hash = UploadRequest0Message(l, self.sqn, self.final_key).send_file_fragment()
                self.sock.sendall(file_fragment)
                l = upload_file.read(1024)
            self.increase_sqn()
            size = size - 1024
        print("File Uploaded Successfully!")
        received_msg = self.sock.recv(1024)
        '''
        self.logger.debug(f"Upload response: {received_msg}")
        h = SHA256.new()
        while True:
            data = upload_file.read(1024)
            if not data:
                break
            h.update(data)
        msg_hash = h.digest()
        self.logger.debug(f"file hash: {h.hexdigest()}")
        '''
        upload_file.close()
        decrypted_message = UploadResponseMessage(received_msg, self.sqn, self.final_key,
                                                  msg_hash).upload_response()
        result = decrypted_message
        print(result)
        getch()

    def download_request(self, client_sure, command, result):
        formatted_message = self.command_format(command)
        self.logger.debug(formatted_message)
        if exists(command[1]):
            print("File already exists")
            self.logger.info(f"File already exists: {command[1]}")
            getch()
        else:
            if client_sure:
                downloaded_file = open(command[1], 'wb')
                msg = DnloadRequestMessage("Ready", self.sqn, self.final_key).download_request()
                self.sock.sendall(msg)
                last_dnl_res = False
                print("File downloading...")
                self.increase_sqn()
                while not last_dnl_res:
                    received_file_fragment = self.sock.recv(2048)
                    decrypted_fragment, last_dnl_res = DnloadResponseMessage(received_file_fragment, self.sqn,
                                                                             self.final_key).dnl_response()
                    downloaded_file.write(decrypted_fragment)
                h = SHA256.new()
                '''
                while True:
                    data = (downloaded_file.read(1024))
                    if not data:
                        break
                    h.update(data)
                hashed = h.digest()
                self.logger.debug(f"File hash: {h.hexdigest()}")
                if hashed != result[4]:
                    self.logger.debug(f"File hashes do not match: {hashed} and {result[4]}")
                    self.sock.close()
                if len(downloaded_file) != int(result[3]):
                    self.logger.debug(f"File sizes do not match: {len(downloaded_file)} to {int(result[3])}")
                    self.sock.close()
                '''
                downloaded_file.close()
            else:
                msg = DnloadRequestMessage("Cancel", self.sqn, self.final_key, ).download_request()
                self.sock.sendall(msg)
                print("Client declined the download process!")
                getch()

    def operation(self):
        self.logger.debug('operation')
        self.sock = self.connect()
        try:
            # LOGIN
            login_req_message, message_hash, client_random, temp_key, username, password = self.client_login()
            try:
                self.sock.sendall(login_req_message)
                self.logger.info("Message sent")
            except Exception as e:
                print(e)
                self.logger.error(f"MS: {e}")

            login_res = self.sock.recv(1024)
            self.logger.debug(f"Login response: {login_res}")

            dec_payload = self.response_decrypt(login_res, temp_key, message_hash)

            if not dec_payload:
                self.sock.close()
                self.logger.info("Connection closed")
            self.generate_final_key(client_random, dec_payload[1], message_hash)
            self.logger.info("END OF LOGIN")
            # END OF LOGIN

            command = self.ui.command_window(username)
            self.logger.debug(command)
            while command[0] != "exit":
                command_req_message, message_hash = self.command_message(command)
                self.increase_sqn()
                self.logger.debug(command_req_message)
                self.logger.debug(message_hash)
                try:
                    self.sock.sendall(command_req_message)
                    self.logger.info("Message sent!")
                except Exception as e:
                    self.logger.error(f"Problem with sending the message: {e}")

                received_msg = self.sock.recv(1024)
                self.logger.debug(f"Command response: {received_msg}")

                decrypted_message, sqn = CommandResponseMessage(received_msg, self.sqn, self.final_key,
                                                                message_hash).command_response()
                result = decrypted_message  # .split('\n')
                print(result)
                self.ui.result_window(result)
                if result[2] == "accept":
                    if command[0] == "dnl":
                        if self.ui.make_sure_window(f"start downloading {command[1]}"):
                            self.download_request(True, command, result)
                        else:
                            self.download_request(False, command)
                    else:
                        self.upload_request(command)
                command = self.ui.command_window(username)
        except Exception as e:
            print(e)
            self.logger.error(f"An error was occurred during the process: {e}")

    def generate_final_key(self, client_random, server_random, request_hash):
        self.logger.debug("generate_final_key")
        # bytenak kell lenniuk
        salt = request_hash
        print(request_hash.hex())
        print(client_random + server_random)
        self.final_key = HKDF(bytes.fromhex(client_random) + bytes.fromhex(server_random), 32, salt, SHA256, 1)
        self.logger.debug(f"FINAL KEY: {self.final_key}")

    def command_format(self, command):
        self.logger.debug("command_format")
        if command[0] == "upl":
            size = os.path.getsize(command[1])
            upload_file = open(command[1], 'rb')
            hash_file = SHA256.new()

            chunk = 0
            while chunk != b'':
                chunk = upload_file.read(1024)
                hash_file.update(chunk)
            hashed = hash_file.hexdigest()
            self.logger.debug(f"File hash: {hashed}")

            command.append(str(size))
            command.append(hashed)
            upload_file.close()
        message = command[0]
        for param in range(1, len(command)):
            message = message + '\n' + command[param]
        return message

    class UI:
        def __init__(self):
            pass

        def clear_screen(self):
            if osname == 'nt':
                _ = system('cls')
            else:
                _ = system('clear')

        def validate(self, form, name):
            if not len(form) > 0:
                print("You have to promt a " + name)
                return False
            return True

        def login_window(self, logged_in):
            username = ""
            password = ""
            if not logged_in:
                self.clear_screen()
                while True:
                    print("You have to log in first:")
                    username = input("Username: ")
                    if self.validate(username, "username"):
                        break
                while True:
                    password = input("Password: ")
                    if self.validate(password, "password"):
                        break
            return username, password

        def command_window(self, username):
            while True:
                self.clear_screen()
                print(f"Hello {username}\n"
                      f"+-----------------------------+")
                print("1. pwd\n"
                      "2. lst\n"
                      "3. chd\n"
                      "4. mkd\n"
                      "5. del\n"
                      "6. upl\n"
                      "7. dnl\n"
                      "9. Log out\n")
                print("\nSelect a command number: ")
                command = getch()
                if self.validate(command, "command number"):
                    if command.isdigit():
                        match int(command):
                            case 1:
                                return ["pwd"]
                            case 2:
                                return ["lst"]
                            case 3:
                                directory = input("Directory name: ")
                                return ["chd", directory]
                            case 4:
                                directory = input("Directory name to create: ")
                                return ["mkd", directory]
                            case 5:
                                filename = input("File or directory to delete: ")
                                return ["del", filename]
                            case 6:
                                filename = input("File to upload: ")
                                return ["upl", filename]  # size and hash are added in message format function
                            case 7:
                                filename = input("File to download: ")
                                return ["dnl", filename]
                            case 9:
                                return ["exit"]

        def make_sure_window(self, text):
            while True:
                self.clear_screen()
                print(f"Are you sure you want to {text}?")
                answer = input("Y/N")
                if answer.upper() == "Y":
                    return True
                else:
                    if answer.upper() == "N":
                        return False

        def result_window(self, result):
            # not tested
            self.clear_screen()
            print(f"Requested command: {result[0]}")
            print(f"Result of command: {result[2]}")
            if result[2] == "failure":
                print(f"Reason of failure: {result[3]}")
            if result[2] == "reject":
                if result[0] == "dnl":
                    print(f"Download rejected: {result[3]}")
                else:
                    print(f"Upload rejected: {result[3]}")
            if result[2] == "success":
                print(f"Result:")
                for r in range(2, len(result)):
                    print(f"{result[r]}")
            if result[2] == "accept":
                '''
                if result[0] == "dnl":
                    answer = self.make_sure_window("start download")
                    if answer:
                        print("Downloading is about to start...")
                    else:
                        print("Download is interrupted")

                else:
                    answer = self.make_sure_window("start upload")
                    if answer:
                        print("Uploading is about to start...")
                    else:
                        print("Upload is interrupted")
                return answer
                '''
                pass
            getch()


if __name__ == "__main__":
    print("Starting...")
    SiFTClient("localhost", 5150, "pub.pem").operation()
