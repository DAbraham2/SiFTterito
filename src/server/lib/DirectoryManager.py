import logging
import os
import re
from os.path import commonprefix, getsize, normcase, normpath, splitdrive
from pathlib import Path

from lib.constants import get_base_folder
from lib.cryptoStuff import getFileHash


class DirManager:
    def __init__(self, username: str) -> None:
        self.logger = logging.getLogger(__name__)
        self.user = username
        self.current_working_dir = Path(normcase(
            normpath(get_base_folder() / 'server_content/users/{}'.format(self.user))))
        self.home_directory = self.current_working_dir
        print(self.current_working_dir)
        if(not self.current_working_dir.exists() or not self.current_working_dir.is_dir()):
            os.makedirs(self.current_working_dir)

        self.logger.info('DirManager __init__(username: {})\nHomedir: {}'.format(
            username, self.home_directory))

    def chd(self, directory: str) -> str:
        try:
            self.logger.debug('chd(dir: {})'.format(directory))
            cleaned_tail = cleanPath(directory)

            if self.preventEscape(cleaned_tail):
                self.logger.error('Escape attempt cought')
                raise ValueError('You\'re caged AF.')

            dir = self.current_working_dir / cleaned_tail
            if(not dir.is_dir()):
                self.logger.error('Directory not exists: {}'.format(dir))
                raise ValueError('Directory not exists')
            self.current_working_dir = Path(normpath(dir))
            self.logger.debug('Cwd changed to {}'.format(
                self.current_working_dir))
            return success('')
        except BaseException as err:
            self.logger.error(f'Error in chd\n{err}')
            return failure(err)

    def pwd(self) -> str:
        try:
            cwd = self.current_working_dir.as_posix()
            hd = self.home_directory.as_posix()
            p = cwd.removeprefix(hd)
            if p is '':
                p = '~/'
            return success(p)
        except BaseException as err:
            self.logger.error(f'Error in pwd\n{err}')
            return failure(err)

    def lst(self) -> str:
        try:
            self.logger.debug('lst called')
            list = ''
            for item in self.current_working_dir.iterdir():
                list = list + '{}\n'.format(item.name)

            list = list.removesuffix('\n')
            self.logger.debug('lst result: \n{}'.format(list))
            return success(list)
        except BaseException as err:
            self.logger.error(f'Error in lst\n{err}')
            return failure(err)

    def mkd(self, directory: str) -> str:
        try:
            self.logger.debug('mkd(dir: {})'.format(directory))
            clean = cleanPath(directory)

            if self.preventEscape(clean):
                self.logger.error(
                    'Escape attempt cought with path: {}'.format(clean))
                raise ValueError('You\'re caged AF.')

            dir = self.current_working_dir / clean
            dir = Path(normpath(dir))
            if dir.exists():
                self.logger.error('Directory already exists')
                raise ValueError('Directory already exists')

            dir.mkdir()

            return success('')
        except BaseException as err:
            self.logger.error(f'Error in mkd\n{err}')
            return failure(err)

    def delete(self, path: str) -> str:
        try:
            self.logger.debug('delete(path: {})'.find(path))
            clean = cleanPath(path)
            if self.preventEscape(clean):
                self.logger.error('Escape attempt cought')
                raise ValueError('You\'re caged AF.')

            if self.is_home() and clean is '':
                raise ValueError('Cannot delete home directory')

            p = self.current_working_dir / clean
            if not p.exists():
                raise ValueError('Path not exists')

            if p.is_file():
                os.remove(p)
            else:
                p.rmdir()

            return success('')
        except BaseException as err:
            self.logger.error(f'Error in delete\n{err}')
            return failure(err)

    def init_dnl(self, path: str) -> str:
        try:
            self.logger.debug('init_dnl(path: {})'.format(path))
            c = cleanPath(path)
            if self.preventEscape(c):
                raise ValueError('You\'re caged AF.')

            p = Path(normpath(self.current_working_dir/c))
            if not p.is_file():
                raise ValueError('Requested path is not a file.')

            siz = getsize(p)
            hash = getFileHash(p)
            self.file_to_download = p
            return accept('{}\n{}'.format(siz, hash))
        except BaseException as err:
            self.file_to_download = None
            self.logger.error(f'Error in init_dnl\n{err}')
            return reject(err)

    def init_upl(self, path: str, hash: str, size: int) -> str:
        try:
            self.logger.debug(
                'init_upl(path: {}, hash: {}, size: {})'.format(path, hash, size))
            c = cleanPath(path)
            if self.preventEscape(c):
                raise ValueError('You\'re caged AF.')

            p = Path(normpath(self.current_working_dir/c))
            if p.exists():
                raise ValueError('File already exists')

            self.file_to_upload = p
            self.upload_size = size
            self.upload_hash = hash

            return accept()
        except BaseException as err:
            self.file_to_upload = None
            self.upload_size = None
            self.upload_hash = None
            self.logger.error(f'Error in init_upl\n{err}')
            return reject(err)

    def is_home(self) -> bool:
        return self.current_working_dir == self.home_directory

    def preventEscape(self, path: str) -> bool:
        p = normpath(self.current_working_dir / path)
        common = commonprefix([p, self.home_directory])
        if not (len(common) is len(str(self.home_directory))):
            return True

        return self.is_home() and (path.startswith(('/..', '\\..', '//..', '..')))


def success(text: str = '') -> str:
    s = 'success'
    t = text.strip()
    if t is '':
        return s
    else:
        s = s + '\n{}'.format(text)

    return s


def accept(text: str = '') -> str:
    return 'accept\n'+text


def failure(err: BaseException) -> str:
    return 'failure\n{}'.format(err)


def reject(err: BaseException) -> str:
    return 'reject\n{}'.format(err)


def cleanPath(p: str) -> str:
    cleaned_dir = re.sub('[^A-Za-z0-9\/:.]+', '', p)
    _, tail = splitdrive(cleaned_dir)
    return normpath(normcase(tail))
