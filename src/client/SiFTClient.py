import os.path
from msvcrt import getch
from os import system
from os import name as osname
import socket
import sys
from Crypto.Hash import SHA256
from Crypto.Protocol.KDF import HKDF

file_dir = os.path.dirname(__file__)
protocol_dir = os.path.join(file_dir, '..', 'protocol')
sys.path.append(protocol_dir)
from SiFT_MTP import LoginRequestMessage, LoginResponseMessage


class SiFTClient:
    def __init__(self, HOST, PORT, pubkey_path):
        print("Initialization...")
        self.ui = self.UI()
        self.host = HOST
        self.port = PORT
        self.logged_in = False
        self.pubkey_path = pubkey_path
        self.sqn = 0
        self.final_key = None
        self.operation()

    def operation(self):
        print("Connection is about to start:")
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.connect((self.host, self.port))
                print("Connection established")
                # LOGIN
                username, password = self.ui.login_window(self.logged_in)
                self.sqn = (self.sqn + 1).to_bytes(2, byteorder='big')
                print("Starting Login Protocol")
                login_req_message, message_hash, client_random, temp_key = LoginRequestMessage(self.pubkey_path,
                                                                                               [username, password],
                                                                                               self.sqn).login_request()
                print(f"Login request: \nUsername: {username}\n"
                      f"Password: {password}\n"
                      f"SQN: {self.sqn}\n"
                      f"Login request message: {login_req_message}\n"
                      f"Message hash: {message_hash}\n"
                      f"My random: {client_random}\n"
                      f"Temp key: {temp_key}")
                try:
                    sock.sendall(login_req_message)
                    print("Message sent!")
                except Exception as e:
                    print(e)
                login_res = str(sock.recv(1024), "utf-8")
                print(f"Login response: {login_res}")
                server_random, self.sqn = LoginResponseMessage(login_res, self.sqn, temp_key,
                                                               message_hash).parse_message()
                if server_random == 0:
                    sock.close()
                self.generate_final_key(client_random, server_random, message_hash)
                sleep(10)
                command = self.ui.command_window(username)
                while command[0] != "exit":
                    command = self.ui.command_window(username)
                    formatted_message = self.command_format(command)

                sock.sendall(bytes("test", "utf-8"))
                received = str(sock.recv(1024), "utf-8")
        except Exception as e:
            print("An error was occured during the process")

    def generate_final_key(self, client_random, server_random, request_hash):
        salt = request_hash
        self.final_key = HKDF(client_random + server_random, 32, salt, SHA256, 1)

    def command_format(self, command):
        if command[0] == "upl":
            size = os.path.getsize(command[1])
            upload_file = open(command[1], 'rb')
            hash_file = SHA256.new()

            chunk = 0
            while chunk != b'':
                chunk = upload_file.read(1024)
                hash_file.update(chunk)
            hashed = hash_file.hexdigest()
            print(f"File hash: {hashed}")

            command.append(str(size))
            command.append(hashed)

        message = command[0] + '\n'
        for com in command:
            message = message + com + '\n'
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
                                return ["upl", filename, ]  # size and hash are added in message format function
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
                if answer.upper() == "Y" or answer.upper == "N":
                    return answer

        '''
        def result_window(self, result):
            if result[2] == "failed":
                print(f"FAIL COMMAND: {result[3]}")
            else:
                if result[2] == "reject":
                    if result[0] == "dnl":
                        print(f"FAILED DOWNLOAD: {result[3]}")
                    else:
                        print(f"FAILED UPLOAD: {result[3]}")
                else:
                    for row in result:
                        print(row)
        '''

print("Starting...")
SiFTClient("localhost", 5150, "public.pem")
