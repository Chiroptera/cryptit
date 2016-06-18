from os import urandom, makedirs, walk, remove, chdir
from os.path import basename, isdir, isfile, join, abspath, exists, dirname
from glob import glob

import sys

from pickle import dump, dumps, load, loads

import argparse
from getpass import getpass

from io import BytesIO

from core_crypto import encrypt, decrypt, gen_key


def get_content(paths):
    cpaths = list(paths)
    payload = {}
    for path in paths:
        valid_paths = glob(path)
        if not valid_paths:
            continue
        for p in valid_paths:
            if isdir(p):
                fill_dir_payload(path, payload)
                continue
            elif isfile(p):
                payload[p] = get_file_payload(p)

    return payload


def fill_dir_payload(path, payload):
    for root, dirs, files in walk(path):
        if not files:
            continue
        for file in files:
            filepath = join(root, file)
            payload[filepath] = get_file_payload(filepath)


def get_file_payload(path):
    with open(path, 'rb') as f:
        return f.read()


def get_encrypted_file(path):
    with open(path, 'rb') as f:
        return BytesIO(f.read())


def reconsctruct(data):
    for path, payload in data.items():
        if not exists(dirname(path)):
            try:
                makedirs(dirname(path))
            except OSError as exc:  # Guard against race condition
                if exc.errno != errno.EEXIST:
                    raise
        with open(path, "wb") as f:
            f.write(payload)


def choose_filename():
    chosen = False
    while not chosen:
        dest_path = input('Destination filename: ') + '.enc'
        if exists(dest_path):
            yes_options = ('y', 'yes', 'Y', 'Yes', 'YES')
            if input('File exists. Replace? (y/n)') not in yes_options:
                continue
        return dest_path


def generate_decrypt_code(filepath):
    with open('decrypt_template.py', r) as f:
        lines = f.readlines()

        for i, line in enumerate(lines):
            if '{{filepath}}' in line:
                break

        lines[i] = line.replace('{{filepath}}', '\'{}\''.format(filepath))

        makedirs('build')
        with open('build/decryptioncode.py', 'w') as fw:
            fw.writelines(lines)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Encrypt / decrypt files')
    parser.add_argument('--encrypt', metavar='path', type=str, nargs='+',
                        help='paths of files to use (files to encrypt or files to decrypt')
    parser.add_argument('--decrypt', metavar='path', type=str, help='decrypt file with input path')

    args = parser.parse_args()

    if len(sys.argv) == 1:
        parser.print_help()

    if args.encrypt and args.decrypt:
        print('Only one option should be chosen: encrypt or decrypt.')
        sys.exit(0)

    if args.encrypt:
        # gather data
        payload = BytesIO()
        dump(get_content(args.paths), payload)
        dest_path = choose_filename()
        # encrypt
        password = getpass('password: ').encode('utf-8')
        key = gen_key(password)
        dest_data = encrypt(key, payload)
        with open(dest_path, 'wb') as dest_f:
            chunksize = 2**20  # read 1MB at a time
            dest_data.seek(0)
            while True:
                chunk = dest_data.read(chunksize)
                if len(chunk) == 0:
                    break
                dest_f.write(chunk)
        print('Done.')
        sys.exit(0)

    elif args.decrypt:
        if not exists(args.decrypt):
            print('file doesn\'t exist: {}'.format(args.decrypt))
            sys.exit(1)

        # read file
        try:
            infile = get_encrypted_file(args.decrypt)
        except Exception as e:
            print('Problem reading file: {}'.format(file))
            sys.exit(1)

        # decrypt data
        password = getpass('password: ').encode('utf-8')
        key = gen_key(password)
        try:
            ddata = decrypt(key, infile)
        except Exception as e:
            print(e)
            sys.exit(1)

        # reconstruct input
        udata = load(ddata)
        base = basename(args.decrypt + '_content')
        if not exists(base):
            print('creating folder ', base)
            makedirs(base)

        chdir(base)
        reconsctruct(udata)
        chdir('..')

        print('Done.')
        sys.exit(0)
