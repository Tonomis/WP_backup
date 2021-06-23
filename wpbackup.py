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
from Crypto.PublicKey import RSA

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
sftp_password = "qsd123"
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
#openssl via clé pub
    with open(public_key,'r') as fp:
	pub = fp.read()
	fp.close()
    public = RSA.importKey(pub)
    
    
    #os.system("openssl enc -aes-256-cbc -pbkdf2 -in " + backup_filename + " -out "+ backup_enc +" -pass file:" + public_key)

def upload():
    transport = Paramiko.Transport(sftp_ip,sftp_port)
    transport.connect(NONE,sftp_user,sftp_password)
    sftp = paramiko.SFTPClient.from_transport(transport)
    sftp.put(backup_enc,remotedir_backup)
    sftp.close()
    transport.close()

def delete_local():
#delete 2nd last backup
    os.system("find "+ localdir_backup + " -type f -not -name " + backup_filename + "-delete") 

#def delete_remote():
#delete 

### Exec

backup_db()
backup_site()
