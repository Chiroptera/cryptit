from os import makedirs, chdir
from os.path import join, exists, basename
import sys
from subprocess import call
from uuid import uuid4 as uuid
from pickle import load, loads, dump, dumps
from glob import glob
from io import BytesIO

import cryptit

# create test folder to encrypt
main_test_dir = 'test_dir_{}'.format(uuid().hex)
dirs = [main_test_dir + '/dir1',
        main_test_dir + '/dir2',
        main_test_dir + '/dir2/dir3']
files = ['file0', 'file1', 'file2']
for d in dirs:
    makedirs(d)
for d in dirs:
    for file in files:
        with open(join(d, file), 'w') as f:
            f.write('akunamatata')


# check if all files were created
def check_all_files_created():
    for d in dirs:
        for file in files:
            if not exists(join(d, file)):
                print('not exists ', join(d, file))
                return False
    return True

if not check_all_files_created():
    print('files for test not created; could not proceed with test')
    sys.exit(1)


# encrypt test folder
encrypt_paths = [main_test_dir]

payload = BytesIO()
dump(cryptit.get_content(encrypt_paths), payload)
dest_path = 'test_dir_{}'.format(uuid().hex)
# encrypt
password = '123456'.encode('utf-8')
key = cryptit.gen_key(password)
dest_data = cryptit.encrypt(key, payload)
with open(main_test_dir + '.enc', 'wb') as dest_f:
    chunksize = 2**20  # read 1MB at a time
    dest_data.seek(0)
    while True:
        chunk = dest_data.read(chunksize)
        if len(chunk) == 0:
            break
        dest_f.write(chunk)

assert exists(main_test_dir + '.enc'), 'hello'

# delete test folder
cmds = ['rm', '-rf', main_test_dir]
call(cmds)

assert not exists(main_test_dir), 'folder was deleted'

# decrypt files
infile = cryptit.get_encrypted_file(main_test_dir + '.enc')

# decrypt data
password = '123456'.encode('utf-8')
key = cryptit.gen_key(password)
ddata = cryptit.decrypt(key, infile)

# reconstruct input
udata = load(ddata)
base = basename(main_test_dir + '.enc' + '_content')
if not exists(base):
    makedirs(base)

chdir(base)
cryptit.reconsctruct(udata)

assert check_all_files_created(), 'old structure recreated'

chdir('..')
cmds = ['rm', '-rf'] + glob('test_dir_*')
call(cmds)

print('ALL OK')
