from genericpath import isdir
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
        print(self.current_working_dir)
        if(not self.current_working_dir.exists() or not self.current_working_dir.is_dir()):
            os.makedirs(self.current_working_dir)

    def chd(self, directory: str) -> str:
        try:
            cleaned_dir = re.sub('[^A-Za-z0-9\/:]+', '', directory)
            _, tail = splitdrive(cleaned_dir)
            cleaned_tail = normpath(normcase(tail))
            dir = self.current_working_dir / cleaned_tail
            if(not isdir(dir)):
                raise ValueError('Directory not exists')
            self.current_working_dir = dir
        except:
            return 'failure'
