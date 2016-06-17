# cryptit
Simple software to (en|de)crypt a bundle of files. 

# usage
python cryptit.py [file1 file2 file3] [--encrypt, --decrypt]

When encrypting, the user is requested a password to generate the key and the name of the destination file.

When decrypting, the user is requested only the password to generate the key.

# development environment
```
sudo apt-get build-dep python-pygame
pip install cython
pip install hg+http://bitbucket.org/pygame/pygame
pip install kivy
```

# todo
 - GUI (Kivy)
 - package for windows
