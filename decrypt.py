from Crypto.PublicKey import RSA
from Crypto.Cipher import AES, PKCS1_OAEP
import time
### Variables ###

#Site info
site_name = "wordpress"
site_path = "/var/www/wordpress"

#dB info
db_name = "wordpress"
db_user = "wpuser"
db_password = "qsd123"

#SFTP info
sftp_user = "wpbackup"
sftp_private_key = "/home/administrator/.ssh/id_ed25519"
sftp_ip = "192.168.122.235"
sftp_port = 22
#Directories
localdir_backup = "/backup/wordpress/"
remotedir_backup = "~/backup/wordpress/"
# Date et heure
date = time.strftime("%Y-%m-%d")
backup_filename = localdir_backup + "wp_site_backup_" + date + ".tgz"
db_filename = localdir_backup + "wp_db_backup_" + date + ".sql"
backup_enc = backup_filename + ".enc"
#Encrypt
public_key = "/backup/wp_backup_public.pem"
private_keyyy = "/backup/private.pem"


#Open file and read the session key

file_in = open(backup_enc, "rb")

private_key = RSA.import_key(open(private_keyyy).read())

enc_session_key, nonce, tag, ciphertext = \
   [ file_in.read(x) for x in (private_key.size_in_bytes(), 16, 16, -1) ]

# Decrypt the session key with the private RSA key
cipher_rsa = PKCS1_OAEP.new(private_key)
session_key = cipher_rsa.decrypt(enc_session_key)

# Decrypt the data with the AES session key
cipher_aes = AES.new(session_key, AES.MODE_EAX, nonce)
data = cipher_aes.decrypt_and_verify(ciphertext, tag)

with open (backup_filename+ ".decrypted", 'wb') as f:
    f.write(data)
    f.close()

