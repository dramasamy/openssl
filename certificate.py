# Python3
from OpenSSL import crypto
import os, sys, base64

class Certificate(object):
    """docstring for Certificate"""
    def __init__(self, name, group, key_file=None, csr_file=None):
        self.name = name
        self.group = group
        self._key = None
        self._csr = None

        self.key = None
        self.csr = None

        self.key_encoded = None
        self.csr_encoded = None

        self.key_file = f"/cert/{self.name}.pem" if key_file is None else key_file 
        self.csr_file = f"/cert/{self.name}.csr" if csr_file is None else csr_file

    def generate_key(self, type=crypto.TYPE_RSA, bits=2048):
        if self._key is None:
            self._key = crypto.PKey()
            self._key.generate_key(type, bits)
            print(f"key Generated")
            self.key = crypto.dump_privatekey(crypto.FILETYPE_PEM, self._key).decode('utf=8')
            self.key_encoded = base64.b64encode(self.key.encode('utf-8')).decode('utf-8')
            self._write_file(self.key_file, self.key)
        else:
            print(f"key Generated")

    def generate_req(self, type=crypto.TYPE_RSA, bits=2048):
        if self._csr is None:
            self._csr = crypto.X509Req()
            self._csr.get_subject().CN = f"users:{self.name}"
            self._csr.get_subject().O = self.group
            self._csr.set_pubkey(self._key)
            self._csr.sign(self._key, "sha1")
            self.csr = crypto.dump_certificate_request(crypto.FILETYPE_PEM, self._csr).decode('utf-8')
            self.csr_encoded = base64.b64encode(self.csr.encode('utf-8')).decode('utf-8')
            self._write_file(self.csr_file, self.csr)
            print(f"csr Generated")
        else:
            print(f"csr Generated")

    def _write_file(self, filename, content):
        if os.path.exists(filename):
            print(f"File {filename} already exists, aborting")
            sys.exit(1)
        else:
            with open(filename, "w") as file:
                file.write(content)
