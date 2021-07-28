#!/usr/bin/env python

##################################################################################
# Script de sauvegarde d'un site wordpress et de sa base de donnée associée      
# V0.1                                                                           
# 07/06/2021                                                                     
# Florian Simonot                                                                
#                                                                                
##################################################################################

import sys,os
import tarfile
import time
import paramiko
import pysftp
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
from Crypto.Cipher import AES, PKCS1_OAEP
import gnupg

### Variables ###

# Date et heure
date = time.strftime("%Y-%m-%d")
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
remotedir_backup = "/home/wpbackup/backup/wordpress/"
remote_backup = remotedir_backup + "wp_site_backup_" + date + ".tgz.enc"

backup_filename = localdir_backup + "wp_site_backup_" + date + ".tgz"
db_filename = localdir_backup + "wp_db_backup_" + date + ".sql"
backup_enc = backup_filename + ".enc"
#Encrypt
public_key = "/backup/wp_backup_public.pem"


### Functions ###

def backup_db():
    os.system("MYSQL_PWD=" + db_password + " mysqldump -u " + db_user +" " + db_name + " > " + db_filename)

def backup_site():
    tar = tarfile.open(backup_filename, "x:gz")
    for name in [site_path, db_filename]:
        tar.add(name)
    tar.close()
    os.remove(db_filename)

def encrypt_backup():
#Encrypt file using RSA asymmetric encryption of an AES session key.

    data = open(backup_filename, 'rb').read()
    file_out = open(backup_enc, 'wb')
    recipient_key = RSA.importKey(open(public_key).read())
    session_key = get_random_bytes(16)
    
    # Encrypt the session key with the public RSA key
    cipher_rsa = PKCS1_OAEP.new(recipient_key)
    enc_session_key = cipher_rsa.encrypt(session_key)

    # Encrypt the data with the AES session key
    cipher_aes = AES.new(session_key, AES.MODE_EAX)
    ciphertext, tag = cipher_aes.encrypt_and_digest(data)
    [ file_out.write(x) for x in (enc_session_key, cipher_aes.nonce, tag, ciphertext) ]
    file_out.close()
   
    #os.system("openssl enc -aes-256-cbc -pbkdf2 -in " + backup_filename + " -out "+ backup_enc +" -pass file:" + public_key)



def upload():
    private_key=paramiko.Ed25519Key.from_private_key_file(sftp_private_key)
    client = paramiko.SSHClient()
    client.load_system_host_keys()
    client.connect(sftp_ip, port=sftp_port, username=sftp_user, password=None, pkey=private_key)
    sftp = client.open_sftp()
    sftp.chdir(path=remotedir_backup)
    sftp.put(backup_enc,remote_backup)
    sftp.close()


def delete_local():
#delete 2nd last backup
    os.system("find "+ localdir_backup + " -type f -not -name " + "wp_site_backup_" + date + ".tgz*" + " -delete") 

def delete_remote():
#delete all backups older than 3rd

    private_key=paramiko.Ed25519Key.from_private_key_file(sftp_private_key)
    client = paramiko.SSHClient()
    client.load_system_host_keys()
    client.connect(sftp_ip, port=sftp_port, username=sftp_user, password=None, pkey=private_key)
    sftp = client.open_sftp()
    sftp.chdir(path=remotedir_backup)
    remote_files = sftp.listdir(remotedir_backup)
    sorted_remote_files = sorted(remote_files)
    for n in sorted_remote_files[:-3]:
        print('coucou')
        print(n+ 'file')
        print(sorted_remote_files)
        sftp.remove(n)
    sftp.close()

### Exec

backup_db()
backup_site()
encrypt_backup()
upload()
delete_local()
delete_remote()
