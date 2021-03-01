#!/usr/bin/python3
# Client to upload files automatically to a server

# import required modules
import socket
import ssl
import sys
import getopt
import os
import hashlib
import json
import glob 
import netifaces
import math
import pyotp
import tinyec
import secrets

############################# Functions code  #######################
# function to print the usage help
def print_usage():
   print("usage: python3 auto-upload-client.py --servername=<servername> --username=<username> --password=<password> --totp=<totpseed> --folder=<folder_to_upload> --inet=<networkinterface> --encrypt=<y/N> --deleteafterupload=<y/N>" )
   print("or")
   print("python3 auto-upload-client.py -s <servername> -u <username> -p <password> -t <totpseed> -f <folder_to_upload> -i <networkinterface> -e <y/N> -d=<y/N>" )
   print("- servername,username,password and folder are mandatories")
   print("- folder parameter should be  path where the files to upload are located")
   print("- inet,encrypt and deleteafterupload have a default value= n (No) if not set")
   print("- inet can limit the upload to when a specific network interface is up. A case usage is that you record video in a car and when it's back connected to a wifi network, the videos are uploaded.")
   return
# function to calculate sha2-512 of a file
def get_hash_file(filename):
    sha_hash = hashlib.sha512()
    with open(filename,"rb") as f:
       # Reads and updates hash string value in blocks of 4K
       for byte_block in iter(lambda: f.read(4096),b""):
           sha_hash.update(byte_block)
    # returns hash in hex decimal string  
    return sha_hash.hexdigest()
    
#function to secure delete a file over writing with random data and remove
def secure_delete(filename):
    with open(filename, "ba+") as delfile:
        length = delfile.tell()
        delfile.seek(0)
        x=math.ceil(length/32768)
        for y in range(x):
           delfile.write(os.urandom(length))
    os.remove(filename)    
    return
   
# function to upload file, return True once completed or False for failed upload
def upload_file(filename,servername,username,password,totp,deleteafterupload):
   flag=False
   # gets file size
   file_stats = os.stat(filename)
   filesize=file_stats.st_size
   # gets sha-512
   filehash=get_hash_file(filename)
   print("[Info] Sha2-512 hash: "+filehash)
   # compute the totp
   totpf = pyotp.TOTP(totp)
   totpc=totpf.now()   
   # compute an EC key pair
   curve = registry.get_curve('brainpoolP256r1')
   PrivKey = secrets.randbelow(curve.field.n)
   PubKey = PrivKey * curve.g   
   Publickey=compress(PubKey)
   # creates authentication message
   auth="{\"username\":\""+username+"\","
   auth=auth+"\"password\":\""+password+"\","
   auth=auth+"\"filename\":\""+filename+"\","
   auth=auth+"\"filesize\":\""+str(filesize)+"\","
   auth=auth+"\"filehash\":\""+filehash+"\","
   auth=auth+"\"totp\":\""+totpc+"\","
   auth=auth+"\"pubkey\":\""+PublicKey+"\""
   auth=auth+"}"
   print("[Debug] Authentication message: "+auth)
   ## opens connection over TLS to the upload servers
   context = ssl.create_default_context()
   with socket.create_connection((servername, 443)) as sock:
      with context.wrap_socket(sock, server_hostname=servername) as ssock:
          print("[Debug] TLS version: "+ssock.version())
          #send authentication message
          ssock.sendall(auth.encode('utf-8'))
          # read answer to authentication request
          msg = ssock.recv(1024)                 
          a=json.loads(msg.decode('ascii'))                    
          if "answer" in a.keys(): 
             if a["answer"]=="OK":
                # sending file 
                print("[Debug] Sending file:", filename)
                totbytes=0
                f=open(filename,"rb")
                while True:
                    bytes=f.read(32768);
                    if not bytes:
                       break
                    print("[Debug] Sending ",len(bytes)," bytes")
                    ssock.sendall(bytes)
                    totbytes=totbytes+len(bytes)
                    
                # file closing
                print("[Info] Bytes uploaded: ",totbytes)
                f.close()
                # waiting confirmation
                msg = ssock.recv(1024)
                confirmation=json.loads(msg.decode('ascii'))
                # secure delete 
                print("[Info] ",confirmation["message"])
                if confirmation["answer"]=="OK" and deleteafterupload=="y":
                    secure_delete(filename)
                flag=True
          #socket closing
          ssock.close()      
   return flag
# function to compress a public key in hex   
def compress(pubKey):
    return hex(pubKey.x) + hex(pubKey.y % 2)[2:]
   
############################# End functions code  ###################

############################# Main Code #############################
# set default values
servername=""
username=""
password=""
totp=""
folder=""
wifionly="n"
encrypt="n"
deleteafterupload="n"
inet=""
# gets command line parameters if any
try:
   opts, args = getopt.getopt(sys.argv[1:],"hs:u:p:t:f:i:e:d:",["servername","username=","password=","totp","folder","inet","encrypt","deleteafterupload"])
except getopt.GetoptError:
   print_usage()
   sys.exit(2)
for opt, arg in opts:
   if opt == '-h':
      print_usage()
      sys.exit()
   elif opt in ("-s", "--servername"):
      servername = arg     
   elif opt in ("-u", "--username"):
      username = arg
   elif opt in ("-p", "--password"):
      password = arg
   elif opt in ("-t", "--totp"):
      totp = arg     
   elif opt in ("-f", "--folder"):
      folder = arg
   elif opt in ("-i", "--inet"):
      inet = arg.lower()    
   elif opt in ("-e", "--encrypt"):
      encrypt = arg.lower()
   elif opt in ("-d", "--deleteafterupload"):
      deleteafterupload = arg.lower()              

# checks parameters
e=""
if len(servername)==0:
    e=e+"- servername is missing\n"
if len(username)==0:
    e=e+"- username is missing\n"
if len(password)==0:
    e=e+"- password is missing\n"
if len(totp)==0:
    e=e+"- totp seed is missing\n"    
if len(folder)==0:
    e=e+"- folder parameter is missing\n"    
# exits in case of missing/wrong parameters
if len(e)>0:
    print(e)
    print_usage()
    sys.exit()
# check for wifi/wired connection
upflag=True
if len(inet)>0:
   upflag=False
   for interface in netifaces.interfaces():
      if interface==inet:
        ip=netifaces.ifaddresses(interface)[netifaces.AF_INET][0]['addr']
        if ip!="0.0.0.0" and ip[0:7]!="169.254.":
           upflag=True
      
if upflag==False:
   print("[Info} Inet interface: ",inet," is down, upload is not possible")
   sys.exit(2)
# adding / to folder if missing
x=len(folder)
if folder[x-1] != "/":
   folder=folder+"/"
# upload files loop   
for fname in os.listdir(folder): 
    print("[Info] Uploading :",folder,fname) 
    result=upload_file(folder+fname,servername,username,password,totp,deleteafterupload)
    if result==True:
       print("[Info] Transfer successful")
    # auto delete if required
    if deleteafterupload=="y" and result==True:
        print("[Info] Secure deleting: "+folder+fname)
        secure_delete(folder+fname)
        print("[Info] Secure delete completed")

sys.exit()

    



