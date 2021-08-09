### WP_backup Project
Is a couple of 2 scripts : 
**wpbackup.py** is backing up wordpress's site, generate a file with ACLs, compress all and create archive file.
Produce a cipher backup with a public_key (tried with RSA 2048). Transfer it to a distant server using SFTP protocol with ssh public key (ED25519)
Keep only 3 last backup on the distant server.

**restore.py** is deciphering you backup with your private key, uncompress it
Install Apache & Mysql
Put your Wordpress files in place and restore the database
    
## Installation

Install python3 and library listed in requierements.txt.
```bash
apt install python3
pip install -r requirements.txt
```

## Usage
fill the .env.example for your system configuration and rename it in .env
Don't forget to copy your public ssh key in your backup server.
```bash
ssh-copy-id wpbackup@YOUR_IP
```

generate a couple public/private key to cipher your archive
put you public key in your Wordpress machine, keep secretly your private one.

```bash
openssl genrsa -out private.pem 2048
openssl rsa -in private.pem -out public.pem -pubout -outform PEM
```

# Backup
On your actual WP machine :

```bash
sudo python3 wpbackup.py
```
# Restore
grab your encrypted archive, restore.py + .env file and your private key

```bash
sudo python3 restore.py YOUR_BACKUP_FILENAME
```
