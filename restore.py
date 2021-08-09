#!/usr/bin/env python

##################################################################################
#
# 
# Decipher you backup with your private key, uncompress it
# Install Apache & Mysql
# Put your Wordpress files in place and restore the database
# V1.0                                                                           
# 08/08/2021                                                                     
#                                                                                                                                                 
##################################################################################

from Crypto.PublicKey import RSA
from Crypto.Cipher import AES, PKCS1_OAEP
import sys, os
from dotenv import load_dotenv
import argparse

load_dotenv()
### Parser
#load a parser to get the backup_filename

parser = argparse.ArgumentParser(description='Restore Wordpress site from your wp_backup.py backup')
parser.add_argument('filename', help='the backup filename you want to restore')
args = parser.parse_args()
print(args.accumulate(args.integers))
backup_filename=args.filename

### Variables ###

#Decrypt
private_keyyy = "./private.pem"

#dB info
db_name = os.getenv('MYSQL_DB')
db_user = os.getenv('MYSQL_USER')
db_password = os.getenv('MYSQL_PASSWORD')


#Filename from arg

file_in = open(backup_filename, "rb")
private_key = RSA.import_key(open(private_keyyy).read())

enc_session_key, nonce, tag, ciphertext = \
   [ file_in.read(x) for x in (private_key.size_in_bytes(), 16, 16, -1) ]

# Decrypt the session key with the private RSA key
cipher_rsa = PKCS1_OAEP.new(private_key)
session_key = cipher_rsa.decrypt(enc_session_key)

# Decrypt the data with the AES session key
cipher_aes = AES.new(session_key, AES.MODE_EAX, nonce)
data = cipher_aes.decrypt_and_verify(ciphertext, tag)

decrypted_backup_filename=backup_filename[:-4]

with open (decrypted_backup_filename, 'wb') as f:
    f.write(data)
    f.close()

#Untar and move files into respective's directories
os.system("sudo apt install -y apache2 php libapache2-mod-php mysql-server php-mysql")
os.system("sudo tar -xzvf " + decrypted_backup_filename)
if not os.path.exists('/var/www/wordpress'):
    os.makedirs('/var/www/wordpress')
os.system("sudo mv var/www/wordpress/ /var/www/wordpress/")
os.system("sudo mv etc/apache2/sites-available/* /etc/apache2/sites-available/*")
os.system("sudo a2ensite wordpress")
os.system("sudo mysql <<EOF")
os.system("CREATE USER "+ db_user +"@'localhost' IDENTIFIED BY "+ db_password+ " ; GRANT ALL ON wordpress.* TO "+db_user+"@'localhost';FLUSH PRIVILEGES;EOF")
db_filename = "backup/wordpress/wp_db_backup_" + backup_filename[15:25] + ".sql"
os.system("MYSQL_PWD=" + db_password + " mysql -u " + db_user +" " + db_name + " < " + db_filename)
os.system("sudo systemctl reload apache2")


