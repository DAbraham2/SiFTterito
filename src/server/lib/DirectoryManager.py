from genericpath import isdir
from lib2to3.pytree import Base
from pathlib import Path
import os
from os.path import splitdrive, normpath, normcase
import re
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
            cleaned_dir = re.sub('[^A-Za-z0-9\/:.]+', '', directory)
            _, tail = splitdrive(cleaned_dir)
            cleaned_tail = normpath(normcase(tail))

            if self.is_home() and (cleaned_tail.startswith(('/..', '\\..', '//..', '..'))):
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

    def is_home(self) -> bool:
        return self.current_working_dir == self.home_directory


def success(text: str) -> str:
    s = 'success'
    if text is not '' or text is not None:
        s = s + '\n{}'.format(text)
    return s


def failure(err: BaseException) -> str:
    return 'failure\n{}'.format(err)
