import argparse

parser = argparse.ArgumentParser(description='Encrypt / decrypt files')
parser.add_argument('--encrypt', metavar='N', type=str, nargs='+',
                    help='paths of files to use (files to encrypt or files to decrypt')
parser.add_argument('--decrypt', type=str, help='decrypt files')

args = parser.parse_args()
print(args)
if args.decrypt:
    print('decrypt')

if args.encrypt:
    print('encrypt')