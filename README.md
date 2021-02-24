# Auto Upload Server/Client

This application allows to setup an UPLOADING server and uses a client to periodically upload files over an encrypted connection over TLS.  
The users' authentication is done using by username and password.  
The passwords are stored encrypted by a strong (Argon2)[https://en.wikipedia.org/wiki/Argon2] hash.  
The uploaded files can be automatically deleted after the confirmed upload.  
For security, the files deleted are overwritten with random data before the cancellation. 
The upload can start upon condition that a certain network interface is
active. It can be useful to avoid heavy upload when connected over mobile
data and start the upload when you are under wifi coverage.
The server is multi-threaded and it can probably handle >1000 connections at the same time.
It has been created to transfer heavy files like video recordings.

The main components are:  

- auto-upload-server.py (server module)
- auto-upload-client.py (client module)
- adduser.py (utility to enable users)

## Requirements:

- python >= 3.8  
- Linux Operating system, tested on Debian 10  and Raspberry PI OS
- python3 libraries for openssl,argon2 and netifaces

## Installation:

- Debian and Raspeberry PI os:  
```bash
apt-get update  
apt-get upgrade  
apt-get install python3-openssl python3-argon2 python3-netifaces  
```

### TLS Certificate/Private Key
Get a TLS certificate and private key using any Certification Authority, for
example a free CA is: (https://certbot.eff.org)[https://certbot.eff.org]
once you have certificate and private key you can launche the server.  
  
### Firewall  
The server listens on port tcp/443, you should configure your firewall accordingly.  

### Add Users
You should add at the least one user:
```bash
python3 adduser.py -u usertest -p mypassword -f password.autoupload
```
-u = username  
-p = user password
-f = file name for password storage

### Remove Users
Edit the password file with any text editor, remove the line where the first
part is the username to remove and save.  

## Server Running
The server waits for connection on port 443 over TLS. To run it in
```bash
python3 auto-upload-server.py --pwdfilename=<passwordfilename> --certificatefilename=<fullchaincertificatefilename> --privatekeyfilename=<privatekeyfilename> --folder=<folderstorage>  
```
or  
```bash
python3  auto-upload-server.py -p <passwordfilename> -c <fullchaincertificatefilename> -k <privatekeyfilename> -f <folderstorage>
```  
for inline help:  
```bash
python3 auto-upload-server.py -h 
```
- p = filename of the password storage, the same used with adduser.py  
- c = the certificate signed from the certification authority in PEM format, it should include the root chain of the CA  
- f = the folder where to store the uploaded files, the server will create a sub folder for each username at the first upload


## Client Running
The client is the the component uploading the files to the server, to run it
from a bash/shell:  

```bash
python3 auto-upload-client.py --servername=<servername> --username=<username> --password=<password> --folder=<folder_to_upload> --inet=<networkinterface> --encrypt=<y/N> --deleteafterupload=<y/N>
```  
or  
```bash
 python3 auto-upload-client.py -s <servername> -u <username> -p <password> -f <folder_to_upload> -i <networkinterface> -e <y/N> -d=<y/N>
```
- servername,username,password and folder are mandatories  
- folder parameter should be path where the files to upload are located  
- inet,encrypt and deleteafterupload have a default value= n (No) if not set
- inet can limit the upload to when a specific network interface is up. A case usage is that you record video in a car and when it's back connected to a wifi network, the videos are uploaded.  
- deleteafteruploads allow to secure delete the uploaded files as soon the correct transfer has been confirmed.  


## TODO:

- Multi-layer Encryption/Decryption of the files with key exchange based on  Ephemeral Diffie-Hellman and Eliptic Curve;   
- Additional authetication layer ased on Time One Time Password;  
- Improve the controled management of network disconnections.  














