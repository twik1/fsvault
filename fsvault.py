# checksum in the archive
# choose working directory
# add gui with drag and drop
# add file info to db
# add extended attribute to db
# add list db functions
# uuid for mac
# how to handle unknown system

import argparse
import os
import platform
import socket
import xattr
from datetime import datetime
from zipfile import ZipFile
import hashlib
import sqlite3

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
        elif self.platform == 'Darwin':
            None
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
        self.cur.execute('SELECT * FROM FILE WHERE FULLPATH=?',(file,))
        file_info = self.cur.fetchone()
        if not file_info:
            return False
        else:
            return True

class Cvault:
    def __init__(self, vault):
        self.wdir = os.path.dirname(os.path.realpath(__file__))
        os.chdir(self.wdir)
        self.vault = vault
        self.sys = Csystem()
        if not os.path.exists(vault):
            self.new = True
            self.db = Cdb(os.path.join(self.wdir, '4n6.db'))
            self.db.add_system(self.sys.get_system())
        else:
            self.new = False
            with ZipFile(os.path.join(self.wdir, self.vault), 'r') as zip:
                zip.extract('4n6.db')
            self.db = Cdb(os.path.join(self.wdir, '4n6.db'))
            if not self.db.check_system(self.sys.get_system()):
                print('Current achive is not for this system')
                os.remove('4n6.db')
                exit(1)


    def md5(self, fname):
        hash_md5 = hashlib.md5()
        with open(fname, "rb") as f:
            for chunk in iter(lambda: f.read(4096), b""):
                hash_md5.update(chunk)
        return hash_md5.hexdigest()

    def sha256(self, fname):
        hash_sha256 = hashlib.sha256()
        with open(fname, "rb") as f:
            for chunk in iter(lambda: f.read(4096), b""):
                hash_sha256.update(chunk)
        return hash_sha256.hexdigest()

    def add_file_info(self, file, cdb):
        x = xattr.xattr(file)
        info = (file, self.md5(file), self.sha256(file), datetime.now(), '{}'.format(os.stat(file)), '{}'.format(x.items()))
        cdb.add_file(info)

    def add_file(self, file):
        file_with_path = os.path.abspath(file)
        if self.db.check_file(file_with_path):
            print('File already in vault {}'.format(file_with_path))
            return
        self.add_file_info(file_with_path, self.db)
        with ZipFile(os.path.join(self.wdir, self.vault), 'w') as zip:
            zip.write(file_with_path)

    def add_dir(self, dir):
        with ZipFile(os.path.join(self.wdir, self.vault), 'w') as zip:
            for path, subdirs, files in os.walk(dir):
                for name in files:
                    file_with_path = os.path.abspath(os.path.join(path, name))
                    if self.db.check_file(file_with_path):
                        print('File already in vault {}'.format(file_with_path))
                        continue
                    self.add_file_info(file_with_path, self.db)
                    zip.write(file_with_path)

    def add_object(self, object):
        if os.path.isfile(object):
            self.add_file(object)
        elif os.path.isdir(object):
            self.add_dir(object)
        else:
            print('{} in not a valid filesystem object'.format(object))

    def close(self):
        db = os.path.join(self.wdir, '4n6.db')
        with ZipFile(os.path.join(self.wdir, self.vault), 'a') as zip:
            zip.write('4n6.db')
        os.remove(db)


if __name__ == '__main__':
    privesc_parameter = {}
    parser = argparse.ArgumentParser(description='fsvault v0.1')
    parser.add_argument('-a', '--add', help='Add file or directory to vault', required=False)
    #parser.add_argument('-l', '--lock', help='Lock vault', required=False)
    #parser.add_argument('-u', '--unlock', help='Unlock vault', required=False)
    parser.add_argument('vault', help='File System Vault')
    args = parser.parse_args()

    vault = Cvault(args.vault)
    vault.add_object(args.add)
    vault.close()



