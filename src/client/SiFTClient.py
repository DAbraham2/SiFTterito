import os.path
from msvcrt import getch
from os import system
from os import name as osname
import socket
import sys
from Crypto.Hash import SHA256

'''
HOST, PORT = 'localhost', 5150

with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
    sock.connect((HOST, PORT))
    sock.sendall(bytes("fasztapicsadba", "utf-8"))
    received = str(sock.recv(1024), "utf-8")
    sock.sendall(bytes('feri', "utf-8"))
    received2 = str(sock.recv(1024), "utf-8")

print('Sent:        {}'.format("fasztapicsadba"))
print('Received:    {}'.format(received))
'''


class SiFTClient:
    def __init__(self, HOST, PORT):
        self.ui = self.UI()
        self.host = HOST
        self.port = PORT
        self.logged_in = False
        username, password = self.ui.login_window(self.logged_in)
        command = self.ui.command_window(username)
        while command[0] != "exit":
            command = self.ui.command_window(username)
            message = self.command_format(command)

    def connect_to_sercer(self):
        pass

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
        getch()
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
                if answer.upper() == "Y" or answer.uppoer == "N":
                    return answer

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


SiFTClient("localhost", 5015)
