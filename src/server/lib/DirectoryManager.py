import os
import re
from os.path import normcase, normpath, splitdrive
from pathlib import Path

from lib.constants import get_base_folder


class DirManager:
    def __init__(self, username: str) -> None:
        self.user = username
        self.current_working_dir = Path(normcase(
            normpath(get_base_folder() / 'server_content/users/{}'.format(self.user))))
        self.home_directory = self.current_working_dir
        print(self.current_working_dir)
        if(not self.current_working_dir.exists() or not self.current_working_dir.is_dir()):
            os.makedirs(self.current_working_dir)

    def chd(self, directory: str) -> str:
        try:
            cleaned_tail = cleanPath(directory)

            if self.preventEscape(cleaned_tail):
                raise ValueError('You\'re caged AF.')

            dir = self.current_working_dir / cleaned_tail
            if(not dir.is_dir()):
                raise ValueError('Directory not exists')
            self.current_working_dir = Path(normpath(dir))

            return success(None)
        except BaseException as err:
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
            return failure(err)

    def lst(self) -> str:
        try:
            list = ''
            for item in self.current_working_dir.iterdir():
                list = list + '{}\n'.format(item.name)

            list = list.removesuffix('\n')
            return success(list)
        except BaseException as err:
            return failure(err)

    def mkd(self, directory: str) -> str:
        try:
            clean = cleanPath(directory)

            if self.preventEscape(clean):
                raise ValueError('You\'re caged AF.')

            dir = self.current_working_dir / clean
            dir = Path(normpath(dir))
            if dir.exists():
                raise ValueError('Directory already exists')

            dir.mkdir()

            return success('')
        except BaseException as err:
            return failure(err)

    def delete(self, path: str) -> str:
        try:
            clean = cleanPath(path)
            if self.preventEscape(clean):
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
            return failure(err)

    def is_home(self) -> bool:
        return self.current_working_dir == self.home_directory

    def preventEscape(self, path: str) -> bool:
        return self.is_home() and (path.startswith(('/..', '\\..', '//..', '..')))


def success(text: str = '') -> str:
    s = 'success'
    t = text.strip()
    if t is '':
        return s
    else:
        s = s + '\n{}'.format(text)

    return s


def failure(err: BaseException) -> str:
    return 'failure\n{}'.format(err)


def cleanPath(p: str) -> str:
    cleaned_dir = re.sub('[^A-Za-z0-9\/:.]+', '', p)
    _, tail = splitdrive(cleaned_dir)
    return normpath(normcase(tail))
