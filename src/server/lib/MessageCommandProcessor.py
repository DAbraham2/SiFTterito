
from asyncio import Transport
from DirectoryManager import DirManager
from SiFTMTP import MTPv1Message

from constants import MTPConstants

class CommandBase:

    def do(self, *, dm : DirManager) -> str:
        pass


class MTPv1Processor:
    def executeCommand(command: CommandBase, *, directoryManager : DirManager) -> str:
        return command.do()


class MTPv1CommandFactory:
    def getCommandFromContent(data: bytes) -> CommandBase:
        typ = data[2:4]
        cmd = CommandBase()
        match typ:
            case MTPConstants.LoginRequestType:
                print('Login')
                cmd = LoginCommand()
            case MTPConstants.CommandRequestType:
                print('Command')
            case MTPConstants.DownloadRequestType:
                print('Download')
            case MTPConstants.UploadRequest0Type:
                print('Upload0')
            case MTPConstants.UploadRequest1Type:
                print('Upload1')
            case _:
                raise ValueError('')

        return cmd

    def getCommandFromMessage(message: MTPv1Message):
        cmd = CommandBase()
        match message.typ:
            case MTPConstants.LoginRequestType:
                raise ValueError('Login should not happen here.')
            case MTPConstants.CommandRequestType:
                print('Command')
            case MTPConstants.DownloadRequestType:
                print('Download')
            case MTPConstants.UploadRequest0Type:
                print('Upload0')
            case MTPConstants.UploadRequest1Type:
                print('Upload1')
            case _:
                raise ValueError('Unkown message type')

        return cmd


class LoginCommand(CommandBase):
    """
    Login command protocol initiater
    """

    def __init__(self, data: bytes, request, sender) -> None:
        self.request = request
        self.sender = sender
        self.data = data

    def do(*, dm: DirManager) -> str:
        pass


class PwdCommand(CommandBase):
    """
    Print current working directory: 

    Returns to the client the name of the current working directory on the server.
    """

    pass


class LstCommand(CommandBase):
    """
    List content of the current working directory: 

    Returns to the client the list of files and directories in the current working directory on the server.
    """

    pass


class ChdCommand(CommandBase):
    """
    Change directory: 

    Changes the current working directory on the server. The name of the target directory is provided as an argument to the chd command.
    """
    def __init__(self, _path: str) -> None:
        self.path = _path

    def do(self, *, dm: DirManager) -> str:
        if dm is None:
            raise ValueError('Directory manager cannot be null to execute this command')
        return dm.chd(self.path)

class MkdCommand(CommandBase):
    """
    Make directory: 

    Creates a new directory on the server. The name of the directory to be created is provided as an argument to the mkd command.
    """

    pass


class DelCommand(CommandBase):
    """
    Delete file or directory: 

    Deletes a file or a directory on the server. The name of the file or directory to be deleted is provided as an argument to the del command.
    """

    pass


class UplCommand(CommandBase):
    """
    Upload file: 

    Uploads a file from the client to the server. The name of the file to be uploaded is provided as an argument to the upl command and the file is put in the current working directory on the server.
    """

    pass


class DnlCommand(CommandBase):
    """
    Download file: 

    Downloads a file from the current working directory of the server to the client. The name of the file to be downloaded is provided as an argument to the dnl command.
    """

    pass
