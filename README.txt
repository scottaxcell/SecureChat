====================
SECURE CHAT
Author: Scott Axcell
Version: 1.0
====================

============
HOW TO BUILD
============
Linux (CSU CS capitol machines):
/usr/lib64/qt5/bin/qmake-qt5 SecureChat.pro
make all

==========
HOW TO RUN
==========
Server:
./SecureChat <other user public key file> <your private key file>

Example:
./SecureChat bob_rsa.pub my_rsa.priv


Client:
./SecureChat <other user public key file> <your private key file> -i <server ip address> -p <server port>

Example:
./SecureChat bob_rsa.pub my_rsa.priv -i 192.82.132.11 -p 63287


Note: 'other user public key file' is the public RSA key file of the person you
      are wanting to chat with. 'your private key file' is your own personal
      private RSA key file. So Alice would load Bob's public key and her own
      private key, while Bob would load Alice's public ket and his own private
      key.

