"""
Prettyprint filestats
    1 Ok dates for MAC time
    2 uid och gid for the system
Prettyprint the extended attributes
Fix PEP warnings
choose working directory
add gui with drag and drop
how to handle unknown system
delete a file or directory
remove os
Create multiple requirements files
"""

import argparse
import os
import platform
import socket
from datetime import datetime
from zipfile import ZipFile
import hashlib
import sqlite3
import subprocess
import importlib
from pathlib import Path
import psutil
from collections import namedtuple

'''
Problems importing xattr in windows
'''
try:
    importlib.import_module('xattr')
    import xattr
    module_xattr = True
except ImportError:
    module_xattr = False

'''
'''
try:
    importlib.import_module('getpwuid')
    from pwd import getpwuid
    from grp import getgrgid
    module_getpwuid = True
except ImportError:
    module_xattr = False

class Csystem:
    def __init__(self):
        self.platform = platform.system()
        self.fqdn = socket.getfqdn()
        if self.platform == 'Linux':
            try:
                self.uuid = os.popen('cat /etc/machine-id').read().strip()
            except:
                print('no uuid found')
                self.uuid = '1'
        elif self.platform == 'Windows':
            try:
                self.uuid = str(subprocess.check_output('wmic csproduct get UUID')).split()[1].strip('\\r\\n')
                #self.uuid = subprocess.check_output('reg query HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Cryptography /v MachineGuid')
            except:
                print('no uuid found')
                self.uuid = '1'
        elif self.platform == 'Darwin':
            try:
                proc1 = subprocess.Popen(['ioreg', '-rd1', '-c', 'IOPlatformExpertDevice'], stdout=subprocess.PIPE)
                proc2 = subprocess.Popen(['grep', 'IOPlatformUUID'], stdin=proc1.stdout, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                proc1.stdout.close()
                out, err = proc2.communicate()
                self.uuid = out.decode('utf-8').split()[-1].strip('"')
            except:
                print('no uuid found')
                self.uuid = '1'
        else:
            print('Unknown system')
            self.uuid = '0'

    def get_system(self):
        return (self.uuid, self.fqdn, self.platform)

    def sliceit(self, iterable, tup):
        return iterable[tup[0]:tup[1]].strip()

    '''
    Help functions for getting windows file owner.
    Should be rewritten
    '''
    def convert_cat(self, line):
        # Column Align Text indicies from cmd
        # Date time dir filesize owner filename
        Stat = namedtuple('Stat', 'date time directory size owner filename')
        stat_index = Stat(date=(0, 11),
                          time=(11, 18),
                          directory=(18, 27),
                          size=(27, 35),
                          owner=(35, 59),
                          filename=(59, -1))

        stat = Stat(date=self.sliceit(line, stat_index.date),
                    time=self.sliceit(line, stat_index.time),
                    directory=self.sliceit(line, stat_index.directory),
                    size=self.sliceit(line, stat_index.size),
                    owner=self.sliceit(line, stat_index.owner),
                    filename=self.sliceit(line, stat_index.filename))
        return stat
    '''
    end
    '''

    def get_file_owner(self, file):
        if self.platform == 'Windows':
            session = subprocess.Popen(['cmd', '/c', 'dir', '/q', file], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            result = session.communicate()[0].decode('cp1252')
            tst = file.owner()
            if file.is_dir():
                line = result.splitlines()[5]
                return self.convert_cat(line)
            else:
                for line in result.splitlines()[5:]:
                    filename = file.name
                    if filename in line:
                        return self.convert_cat(line)
                else:
                    raise Exception('Could not locate file')


class Cdb:
    def __init__(self, db):
        self.db = db
        self.conn = sqlite3.connect(db)
        self.cur = self.conn.cursor()
        self.cur.execute(''' SELECT COUNT(name) FROM sqlite_master WHERE type='table' AND name='FILE' ''')
        if self.cur.fetchone()[0] == 1:
            None
        else:
            self.init_db()
            
    def close_db(self):
        self.conn.close()

    def init_db(self):
        self.cur.execute('''CREATE TABLE SYSTEM ([UUID] Text, [HostName] Text, [Platform] Text, [Start] DateTime, [Last] Date)''')
        self.cur.execute('''CREATE TABLE FILE ([FULLPATH] Text, [MD5] Text, [SHA256] Text, [SEIZEDATE] Date, [STAT] Text, [XATTR] Text, [FSYSTEM] Text)''')
        self.conn.commit()

    def add_file(self, info):
        sql = '''INSERT INTO FILE (FULLPATH, MD5, SHA256, SEIZEDATE, STAT, XATTR, FSYSTEM) VALUES (?,?,?,?,?,?,?)'''
        self.cur.execute(sql, info)
        self.conn.commit()

    def add_system(self, system_info):
        sql = '''INSERT INTO SYSTEM (UUID, HostName, Platform, Start, Last) VALUES (?,?,?,?,?)'''
        sys = system_info + (datetime.now(), None)
        self.cur.execute(sql, sys)
        self.conn.commit()

    def check_system(self, system_info):
        sql = '''SELECT * FROM SYSTEM'''
        self.cur.execute(sql)
        sys_info = self.cur.fetchone()
        if sys_info[0:3] == system_info:
            return True
        else:
            return False

    def check_file(self, file):
        self.cur.execute('SELECT * FROM FILE WHERE FULLPATH=?',(file.as_posix(),))
        file_info = self.cur.fetchone()
        if not file_info:
            return False
        else:
            return True

    def check_any_file(self):
        self.cur.execute('SELECT * FROM FILE')
        files = self.cur.fetchall()
        return files

    def output_db(self):
        sql = '''SELECT * FROM SYSTEM'''
        self.cur.execute(sql)
        sys_info = self.cur.fetchone()
        print('Unique ID\t{}'.format(sys_info[0]))
        print('Hostname\t{}'.format(sys_info[1]))
        print('Platform\t{}'.format(sys_info[2]))
        print('Created date\t{}'.format(sys_info[3]))
        print('Last added\t{}'.format(sys_info[4]))
        files = self.check_any_file()
        print('-----------------')
        for file in files:
            print('Filename and path\t{}'.format(file[0]))
            print('MD5 checksum\t\t{}'.format(file[1]))
            print('SHA256 checksum\t\t{}'.format(file[2]))
            print('Date seized\t\t{}'.format(file[3]))
            print('File stats\t\t{}'.format(file[4]))
            print('Extended attributes\t{}'.format(file[5]))
            print('Filesystem type\t\t{}'.format(file[6]))
            print('-----------------')

class Cvault:
    def __init__(self, vault):
        # self.vault = Path(vault)
        # self.wdir = os.path.dirname(os.path.realpath(__file__))
        self.wdir = Path(__file__).resolve().parents[0]
        os.chdir(self.wdir)
        self.vault = Path(vault).resolve()
        self.sys = Csystem()
        self.del_list = {}
        if not self.vault.is_file():
            # No archive exists, this could be ok
            self.state = 0
        else:
            if self.extract_db():
                # An archive found without a db, this is not ok
                self.state = 2
            else:
                # An archive found and db extracted
                self.state = 1

    def extract_db(self):
        try:
            with ZipFile(self.vault, 'r') as zip:
                zip.extract('4n6.db')
        except:
            print('This is not a fsvault archive')
            return True
        self.db = Cdb(self.wdir / '4n6.db')
        return False

    def create_db(self):
        try:
            self.db = Cdb(self.wdir / '4n6.db')
            self.db.add_system(self.sys.get_system())
            return False
        except:
            return True


#    def md5(self, fname):
#        hash_md5 = hashlib.md5()
#        with open(fname, "rb") as f:
#            for chunk in iter(lambda: f.read(4096), b""):
#                hash_md5.update(chunk)
#        return hash_md5.hexdigest()

    def md5zip(self, vault, fname):
        hash_md5 = hashlib.md5()
        archive = ZipFile(vault)
        f = archive.open(Path(*fname.parts[1:]).as_posix(), 'r')
        for chunk in iter(lambda: f.read(4096), b""):
            hash_md5.update(chunk)
        return hash_md5.hexdigest()

#    def sha256(self, fname):
#        hash_sha256 = hashlib.sha256()
#        with open(fname, "rb") as f:
#            for chunk in iter(lambda: f.read(4096), b""):
#                hash_sha256.update(chunk)
#        return hash_sha256.hexdigest()

    def sha256zip(self, vault, fname):
        hash_sha256 = hashlib.sha256()
        archive = ZipFile(vault)
        f = archive.open(Path(*fname.parts[1:]).as_posix(), 'r')
        for chunk in iter(lambda: f.read(4096), b""):
            hash_sha256.update(chunk)
        return hash_sha256.hexdigest()

#    def add_file_info(self, file, cdb):
#        if module_xattr:
#            x = xattr.xattr(file)
#            info = (file.as_posix(), self.md5(file), self.sha256(file), datetime.now(), '{}'.format(os.stat(file)), '{}'.format(x.items()))
#        else:
#            info = (file.as_posix(), self.md5(file), self.sha256(file), datetime.now(), '{}'.format(os.stat(file)), '{}'.format(''))
#        cdb.add_file(info)

    def add_file_info_zip(self, file, cdb):
        chkmd5 = self.md5zip(self.vault, file)
        chksha256 = self.sha256zip(self.vault, file)
        fsystem = self.get_fs_type(str(file.parent))
        fowner = self.sys.get_file_owner(file)
        if module_xattr:
            x = xattr.xattr(file)
            info = (file.as_posix(), chkmd5, chksha256, datetime.now(), '{}'.format(os.stat(file)), '{}'.format(x.items()), fsystem)
        else:
            info = (file.as_posix(), chkmd5, chksha256, datetime.now(), '{}'.format(os.stat(file)), '{}'.format(''), fsystem)
        cdb.add_file(info)

    def add_file(self, file):
        file_with_path = Path(file).resolve()
        if self.db.check_file(file_with_path):
            print('File already in vault {}'.format(file_with_path))
            return
        if file_with_path.is_symlink():
            print('File {} is a symlink, will not follow'.format(file_with_path))
            return
        with ZipFile(self.vault, 'w') as zip:
            zip.write(file_with_path)
        self.add_file_info_zip(file_with_path, self.db)

    def add_dir(self, dir):
        file_list = []
        with ZipFile(self.vault, 'w') as zip:
            for path, subdirs, files in os.walk(dir):
                for name in files:
                    file_with_path = Path(path).resolve() / name
                    if self.db.check_file(file_with_path):
                        print('File already in vault {}'.format(file_with_path))
                        continue
                    if file_with_path.is_symlink():
                        print('File {} is a symlink, will not follow'.format(file_with_path))
                        continue
                    zip.write(file_with_path.as_posix())
                    file_list.append(file_with_path)
        for file in file_list:
            self.add_file_info_zip(file, self.db)

    def add_object(self, object):
        if os.path.isfile(object):
            self.add_file(object)
        elif os.path.isdir(object):
            self.add_dir(object)
        else:
            print('{} in not a valid filesystem object'.format(object))

    def del_object(self, object):
        print('Not implemented yet')

    def write_back_db(self):
        with ZipFile(self.vault, 'a') as zip:
            zip.write('4n6.db')
        zip.close()

    def close(self):
        self.db.close_db()
        os.remove(self.db.db)

    def list_vault(self):
        self.db.output_db()

    def get_fs_type(self, mypath):
        root_type = ""
        for part in psutil.disk_partitions():
            if part.mountpoint == '/':
                root_type = part.fstype
                continue
            if mypath.startswith(part.mountpoint):
                return part.fstype
        return root_type


if __name__ == '__main__':
    privesc_parameter = {}
    parser = argparse.ArgumentParser(description='fsvault v0.1')
    parser.add_argument('-a', '--add', help='Add file or directory to vault', required=False)
    parser.add_argument('-l', '--list', help='List files in vault', required=False, action='store_true')
    parser.add_argument('-d', '--delete', help='Delete files from vault', required=False)
    #parser.add_argument('-l', '--lock', help='Lock vault', required=False)
    #parser.add_argument('-u', '--unlock', help='Unlock vault', required=False)
    parser.add_argument('vault', help='File System Vault')
    args = parser.parse_args()

    vault = Cvault(args.vault)
    if args.add:
        if vault.state > 1:
            print('Vault {} is not a fsvault'.format(args.vault))
            exit(1)
        elif vault.state == 1 or vault.state == 0:
            if vault.state == 0:
                if vault.create_db():
                    print('Unable to create the datbase {}'.format(vault.wdir / '4n6.db'))
                    exit(1)
            else:
                if not vault.db.check_system(vault.sys.get_system()):
                    print('Don\'t mix files from different systems')
                    exit(1)
            vault.add_object(args.add)
            vault.write_back_db()
            vault.close()
    elif args.list:
        if not vault.state == 1:
            print('No such vault {}'.format(args.vault))
            exit(1)
        vault.list_vault()
        vault.close()
    elif args.delete:
        if not vault.state == 1:
            print('None or faulty fsvault {}'.format(args.vault))
        vault.del_object(args.delete)




