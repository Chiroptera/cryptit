import os
import sys
import base64
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend

from pickle import dump, dumps, load, loads

import argparse
from getpass import getpass

backend = default_backend()


def encrypt(data):
    # derive
    salt = os.urandom(16)
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=backend
    )

    key = base64.urlsafe_b64encode(kdf.derive(getpass('password: ').encode('utf-8')))
    f = Fernet(key)

    epayload = f.encrypt(payload)
    hello_token = f.encrypt(b'hello')
    return {'data': epayload, 'hello': hello_token, 'salt': salt}


def decrypt(data, hello_token, salt):

    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=backend
    )

    key = base64.urlsafe_b64encode(kdf.derive(getpass('password: ').encode('utf-8')))
    f = Fernet(key)
    hello = f.decrypt(hello_token)
    if hello != b'hello':
        print('incorrect password')
        sys.exit(0)

    ddata = f.decrypt(data)

    return ddata


def get_file(path):
    with open(path, 'rb') as f:
        data = load(f)
        if not isinstance(data, dict):
            raise TypeError('Bad file format.')
        if 'hello' not in data:
            raise TypeError('Bad file structure.')
        if 'salt' not in data:
            raise TypeError('Bad file structure.')
        if 'data' not in data:
            raise TypeError('Bad file structure.')

        return data

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Encrypt / decrypt files')
    parser.add_argument('paths', metavar='N', type=str, nargs='+',
                        help='paths of files to use (files to encrypt or files to decrypt')
    parser.add_argument('--encrypt', action='store_true',
                        help='encrypt files')
    parser.add_argument('--decrypt', action='store_true',
                        help='decrypt files')

    args = parser.parse_args()

    if args.encrypt and args.decrypt:
        print('Only one option should be chosen: encrypt or decrypt.')
        sys.exit(0)

    if not (args.encrypt or args.decrypt):
        print('At least one option should be chosen: encrypt or decrypt.')
        sys.exit(0)

    if len(args.paths) < 1:
        print('No file specified.')
        sys.exit(0)

    if args.encrypt:
        files = args.paths
        files_content = {}
        for file in files:
            with open(file, 'rb') as f:
                files_content[os.path.basename(file)] = f.read()
        payload = dumps(files_content)

        dest_path = input('Destination filename: ') + '.p'
        dest_data = encrypt(payload)
        dest_f = open(dest_path, 'wb')
        dump(dest_data, dest_f)

    elif args.decrypt:
        files = args.paths
        for file in files:
            try:
                data = get_file(file)
            except Exception as e:
                print(e, sys.exc_info()[-1])
                print('Bad file: {}'.format(file))
                continue

            ddata = decrypt(data['data'], data['hello'], data['salt'])
            udata = loads(ddata)
            base = os.path.basename(file + '_content')
            if not os.path.exists(os.path.join(os.path.abspath('.'), base)):
                print('creating folder ', base)
                os.makedirs(base)

            for data_file, content in udata.items():
                with open(os.path.join(base, data_file), 'wb') as f:
                    f.write(content)

        print('Done.')

    sys.exit(0)
