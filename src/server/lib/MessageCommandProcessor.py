
from asyncio import Transport

from requests import head

from lib.constants import MTPConstants
from lib.cryptoStuff import getHash
from lib.DirectoryManager import DirManager
from lib.SiFTMTP import MTPv1Message


class CommandBase:
    def __init__(self, payload: bytes) -> None:
        self.req_hash = getHash(payload)

    def do(self, *, dm: DirManager) -> tuple[bytes, str]:
        pass


class MTPv1Processor:
    def executeCommand(command: CommandBase, *, directoryManager: DirManager) -> str:
        return command.do()


class MTPv1CommandFactory:
    def getCommandFromContent(data: bytes) -> CommandBase:
        typ = data[2:4]
        cmd = CommandBase()
        match typ:
            case MTPConstants.LoginRequestType:
                raise ValueError('')
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

    def getCommandFromMessage(message: MTPv1Message) -> CommandBase:
        cmd = CommandBase()
        match message.typ:
            case MTPConstants.LoginRequestType:
                raise ValueError('Login should not happen here.')
            case MTPConstants.CommandRequestType:
                com = message.content.decode('utf-8')
                match com.split('\n')[0]:
                    case 'chd':
                        cmd = ChdCommand(message.content, com.split('\n')[1])
                    case 'pwd':
                        cmd = PwdCommand(message.content)
                    case 'lst':
                        cmd = LstCommand(message.content)
                    case 'mkd':
                        cmd = MkdCommand(message.content)
                    case 'del':
                        cmd = DelCommand(message.content)
                    case 'dnl':
                        cmd = DnlCommand(message.content)
                    case _:
                        raise ValueError('Unkown message type')
            case MTPConstants.DownloadRequestType:
                print('Download')
            case MTPConstants.UploadRequest0Type:
                print('Upload0')
            case MTPConstants.UploadRequest1Type:
                print('Upload1')
            case _:
                raise ValueError('Unkown message type')

        return cmd


class PwdCommand(CommandBase):
    """
    Print current working directory: 

    Returns to the client the name of the current working directory on the server.
    """

    def do(self, *, dm: DirManager) -> tuple[bytes, str]:
        if dm is None:
            raise ValueError('')

        r = 'pwd\n{}\n'.format(self.req_hash)
        r = r + dm.pwd()
        header = MTPv1Message(typ=MTPConstants.CommandResponseType).getHeader()
        return (header, r)


class LstCommand(CommandBase):
    """
    List content of the current working directory: 

    Returns to the client the list of files and directories in the current working directory on the server.
    """

    def do(self, *, dm: DirManager) -> tuple[bytes, str]:
        if dm is None:
            raise ValueError('DirManager cannot be null')
        header = MTPv1Message(typ=MTPConstants.CommandResponseType).getHeader()
        list = dm.lst()
        return (header, 'lst\n{}\n{}'.format(self.req_hash, list))


class ChdCommand(CommandBase):
    """
    Change directory: 

    Changes the current working directory on the server. The name of the target directory is provided as an argument to the chd command.
    """

    def __init__(self, payload: bytes, _path: str) -> None:
        super().__init__(payload)
        self.path = _path

    def do(self, *, dm: DirManager) -> tuple[bytes, str]:
        if dm is None:
            raise ValueError(
                'Directory manager cannot be null to execute this command')

        header = MTPv1Message(typ=MTPConstants.CommandResponseType).getHeader()
        return (header, 'chd\n{}\n{}'.format(self.req_hash, dm.chd(self.path)))


class MkdCommand(CommandBase):
    """
    Make directory: 

    Creates a new directory on the server. The name of the directory to be created is provided as an argument to the mkd command.
    """

    def __init__(self, payload: bytes) -> None:
        super().__init__(payload)
        com = payload.decode('utf-8')
        lines = com.split('\n')
        self.dirName = lines[1]

    def do(self, *, dm: DirManager) -> tuple[bytes, str]:
        if dm is None:
            raise ValueError('')
        header = MTPv1Message(typ=MTPConstants.CommandResponseType).getHeader()
        result = dm.mkd(self.dirName)

        return (header, 'mkd\n{}\n{}'.format(self.req_hash, result))


class DelCommand(CommandBase):
    """
    Delete file or directory: 

    Deletes a file or a directory on the server. The name of the file or directory to be deleted is provided as an argument to the del command.
    """

    def __init__(self, payload: bytes) -> None:
        super().__init__(payload)
        lines = payload.decode('utf-8').split('\n')
        self.path = lines[1]

    def do(self, *, dm: DirManager) -> tuple[bytes, str]:
        if dm is None:
            raise ValueError()
        res = dm.delete(self.path)
        header = MTPv1Message(typ=MTPConstants.CommandResponseType).getHeader()

        return (header, 'del\n{}\n{}'.format(self.req_hash, res))


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

    def __init__(self, payload: bytes) -> None:
        super().__init__(payload)
        lines = payload.decode('utf-8').split('\n')
        self.path = lines[1]

    def do(self, *, dm: DirManager) -> tuple[bytes, str]:
        if dm in None:
            raise ValueError('')

        res = dm.init_dnl(self.path)
        header = MTPv1Message(typ=MTPConstants.CommandResponseType)
        return (header, 'dnl\n{}\n{}'.format(self.req_hash, res))

