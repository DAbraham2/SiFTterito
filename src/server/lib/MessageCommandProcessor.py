
from typing_extensions import Self

from SiFTterito.src.server.lib.constants import MTPCommandRequestType, MTPConstants, MTPDownloadRequestType, MTPLoginRequestType


class CommandBase:

    def do() -> None:
        pass


class MTPv1Processor:
    def executeCommand(command: CommandBase):
        command.do()


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


class LoginCommand(CommandBase):
    """
    Login command protocol initiater
    """
    
    def __init__(self, data: bytes, request, sender) -> None:
        self.request = request
        self.sender = sender
        self.data = data

    def do() -> None:
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

    pass


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
