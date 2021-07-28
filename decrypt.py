from Crypto.PublicKey import RSA
from Crypto.Cipher import AES, PKCS1_OAEP
import time
### Variables ###

#Site info
site_path = "/var/www/wordpress"

backup_filename = localdir_backup + "wp_site_backup_" + date + ".tgz"
backup_enc = backup_filename + ".enc"
#Decrypt
private_keyyy = "./private.pem"


#input the filename
backup_filename=input("Please enter the backup's filename:\n")

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
#print(data)

decrypted_backup_filename=backup_filename[:-4]

with open (decrypted_backup_filename, 'wb') as f:
    f.write(data)
    f.close()
