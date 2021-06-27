# choose working directory
# add gui with drag and drop
# add list db functions
# how to handle unknown system
# Readme file of fsvault
# delete a file or directory
# add filesystem info

import argparse
import os
import platform
import socket
from datetime import datetime
from zipfile import ZipFile
import hashlib
import sqlite3
import sys
import subprocess
import importlib
from pathlib import Path

try:
    importlib.import_module('xattr')
    module_xattr = True
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
        elif self.platform == 'Windows':
            self.uuid = subprocess.check_output('wmic csproduct get UUID')
            print(self.uuid)
            #self.uuid = subprocess.check_output('reg query HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Cryptography /v MachineGuid')
        elif self.platform == 'Darwin':
            proc1 = subprocess.Popen(['ioreg', '-rd1', '-c', 'IOPlatformExpertDevice'], stdout=subprocess.PIPE)
            proc2 = subprocess.Popen(['grep', 'IOPlatformUUID'], stdin=proc1.stdout,
                         stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            proc1.stdout.close()
            out, err = proc2.communicate()
            self.uuid = out.decode('utf-8').split()[-1].strip('"')
            print(self.uuid)
        else:
            print('Unknown system')
            self.uuid = '0'

    def get_system(self):
        return (self.uuid, self.fqdn, self.platform)


class Cdb:
    def __init__(self, db):
        self.conn = sqlite3.connect(db)
        self.cur = self.conn.cursor()
        self.cur.execute(''' SELECT COUNT(name) FROM sqlite_master WHERE type='table' AND name='FILE' ''')
        if self.cur.fetchone()[0] == 1:
            None
        else:
            self.init_db()

    def init_db(self):
        self.cur.execute('''CREATE TABLE SYSTEM ([UUID] Text, [HostName] Text, [Platform] Text, [Start] DateTime, [Last] Date)''')
        self.cur.execute('''CREATE TABLE FILE ([FULLPATH] Text, [MD5] Text, [SHA256] Text, [SEIZEDATE] Date, [STAT] Text, [XATTR] Text)''')
        self.conn.commit()

    def add_file(self, info):
        sql = '''INSERT INTO FILE (FULLPATH, MD5, SHA256, SEIZEDATE, STAT, XATTR) VALUES (?,?,?,?,?,?)'''
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
            print(file[0])
            print(file[1])
            print(file[2])
            print(file[3])
            print(file[4])
            print(file[5])
            print('-----------------')

class Cvault:
    def __init__(self, vault):
        #self.vault = Path(vault)
        #self.wdir = os.path.dirname(os.path.realpath(__file__))
        self.wdir = Path(__file__).resolve().parents[0]
        os.chdir(self.wdir)
        self.vault = Path(vault).resolve()
        self.sys = Csystem()
        self.del_list = {}
        if not self.vault.is_file():
            # No db exists, this could be ok
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
        self.db = Cdb(os.path.join(self.wdir, '4n6.db'))
        return False

    def create_db(self):
        try:
            self.db = Cdb(self.wdir / '4n6.db')
            self.db.add_system(self.sys.get_system())
            return False
        except:
            return True


    def md5(self, fname):
        hash_md5 = hashlib.md5()
        with open(fname, "rb") as f:
            for chunk in iter(lambda: f.read(4096), b""):
                hash_md5.update(chunk)
        return hash_md5.hexdigest()

    def md5zip(self, vault, fname):
        hash_md5 = hashlib.md5()
        archive = ZipFile(vault)
        print('file: {}'.format(fname))
        f = archive.open(fname)
        for chunk in iter(lambda: f.read(4096), b""):
            hash_md5.update(chunk)
        return hash_md5.hexdigest()

    def sha256(self, fname):
        hash_sha256 = hashlib.sha256()
        with open(fname, "rb") as f:
            for chunk in iter(lambda: f.read(4096), b""):
                hash_sha256.update(chunk)
        return hash_sha256.hexdigest()

    def sha256zip(self, vault, fname):
        hash_sha256 = hashlib.sha256()
        archive = ZipFile(vault)
        f = archive.open(fname)
        for chunk in iter(lambda: f.read(4096), b""):
            hash_sha256.update(chunk)
        return hash_sha256.hexdigest()

    def add_file_info(self, file, cdb):
        if module_xattr:
            x = xattr.xattr(file)
            info = (file, self.md5(file), self.sha256(file), datetime.now(), '{}'.format(os.stat(file)), '{}'.format(x.items()))
        else:
            info = (file, self.md5(file), self.sha256(file), datetime.now(), '{}'.format(os.stat(file)), '{}'.format(''))
        cdb.add_file(info)

    def add_file_info_zip(self, file, cdb):
        chkmd5 = self.md5zip(self.vault, file)
        chksha256 = self.sha256zip(self.vault, file)
        if module_xattr:
            x = xattr.xattr(file)
            info = (file, chkmd5, chksha256, datetime.now(), '{}'.format(os.stat(file)), '{}'.format(x.items()))
        else:
            info = (file, chkmd5, chksha256, datetime.now(), '{}'.format(os.stat(file)), '{}'.format(''))
        cdb.add_file(info)

    def add_file(self, file):
        file_with_path = Path(file).resolve().parents[0]
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
                    file_with_path = Path(path) / name
                    if self.db.check_file(file_with_path):
                        print('File already in vault {}'.format(file_with_path))
                        continue
                    if file_with_path.is_symlink():
                        print('File {} is a symlink, will not follow'.format(file_with_path))
                        continue
                    zip.write(file_with_path)
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

    def close(self):
        db = os.path.join(self.wdir, '4n6.db')
        with ZipFile(os.path.join(self.wdir, self.vault), 'a') as zip:
            zip.write('4n6.db')
        os.remove(db)

    def list_vault(self):
        self.db.output_db()


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
            # output error and quit
            None
        elif vault.state == 1 or vault.state == 0:
            if vault.state == 0:
                if vault.create_db():
                    # output error and quit
                    None
            vault.add_object(args.add)
            vault.close()
    elif args.list:
        if not vault.state == 1:
            # output error and quit
            None
        vault.list_vault()
    elif args.delete:
        if not vault.state == 1:
            # output error and quit
            None
        vault.del_object(args.delete)




