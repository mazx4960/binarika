"""
<filename>.py

Author: Desmond Tan
"""

import os
import fnmatch
import hashlib
import json

import requests
import socket


BUFFER = 65536
META_CACHE_FILE = r'meta_cache.txt'
SENT_CACHE_FILE = r'sent_cache.txt'


class BinarikaAgent(object):
    def __init__(self, root=r'/'):
        self.root = root
        self.server_url = 'http://localhost'
        self.server_port = '5000'
        self.api_url = '/api'
        self.full_url = self.server_url + ':' + self.server_port + self.api_url
        self.file_upload_url = self.server_url + ':' + self.server_port + '/upload'
        self.meta_cache = [] if not os.path.isfile(META_CACHE_FILE) else self.get_cache(META_CACHE_FILE)
        self.sent_cache = [] if not os.path.isfile(SENT_CACHE_FILE) else self.get_cache(SENT_CACHE_FILE)

    def get_cache(self, cache_file):
        with open(cache_file, 'r') as cache_file:
            cache = json.load(cache_file)
        return cache

    def write_cache(self, cache_file, cache):
        with open(cache_file, 'w') as cache_file:
            json.dump(cache, cache_file)

    def filehandler(self):
        for root, basename in self.get_pefiles():
            file_details = FileExtractor(root, basename).get_file_details()
            if file_details in self.meta_cache:
                print '[*] Skipping sending metadata:', file_details['filename']
            else:
                self.meta_cache.append(file_details)
                self.export_details(file_details)

            if file_details['hashed'] in self.sent_cache:
                print '[*] Skipping sending file:', file_details['filename']
            else:
                self.sent_cache.append(file_details['hashed'])
                self.export_file(root, basename, file_details['hashed'])

            self.write_cache(META_CACHE_FILE, self.meta_cache)
            self.write_cache(SENT_CACHE_FILE, self.sent_cache)

    def get_pefiles(self):
        for root, _, files in os.walk(self.root):
            for basename in files:
                if fnmatch.fnmatch(basename, '*.exe') or fnmatch.fnmatch(basename, '*.dll'):
                    yield root, basename

    def export_details(self, file_details):
        response = requests.post(self.full_url, data=file_details)
        if response.status_code == 400:
            print '[!] Error sending over metadata:', file_details['filename']
        else:
            print '[*] Sent metadata:', file_details['filename']

    def export_file(self, root, basename, hashed):
        filepath = os.path.join(root, basename)
        files = {'file': (hashed, open(filepath, 'rb'))}

        response = requests.post(self.file_upload_url, files=files)
        if response.status_code == 400:
            print '[!] Error sending over file:', basename
        else:
            print '[*] Sent file:', basename


class FileExtractor(object):
    def __init__(self, root, basename):
        self.filepath = os.path.join(root, basename)
        self.root = root
        self.basename = basename

        self.hostname = socket.gethostname()

    def get_file_details(self):
        """
        MD5, Filename, File type (exe of dll), Hostname, Containing directory, File size
        """
        file_details = {
            'hostname': self.hostname,
            'filename': self.basename,
            'root': self.root,
            'hashed': self._get_md5_hash(),
            'file_type': self.basename[self.basename.rindex('.') + 1:],
            'file_size': os.path.getsize(self.filepath)
        }

        return file_details

    def _get_md5_hash(self):
        hashed = hashlib.sha256()

        with open(self.filepath, 'rb') as myfile:
            contents = myfile.read(BUFFER)

            while len(contents) > 0:
                hashed.update(contents)
                contents = myfile.read(BUFFER)

        return hashed.hexdigest()


def main():
    agent = BinarikaAgent()
    agent.filehandler()


if __name__ == '__main__':
    main()
