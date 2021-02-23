#!/usr/bin/python3
# Client to upload files automatically to a server

# import required modules
import socket
import ssl
import sys
import getopt
import os
import glob 
import hashlib

############################# Functions code  #######################
# function to print the usage help
def print_usage():
   print("usage: python3 auto-upload-client.py --servername=<servername> --username=<username> --password=<password> --folder=<folder_to_upload> --wifionly=<y/N> --encrypt=<y/N> --deleteafterupload=<y/N>" )
   print("- servername,username,password and folder are mandatories")
   print("- folder parameter may be a a path or a filename with support of wildcards in Linux style (* ? [range])")
   print("- wifionly,encrypt and deleteafterupload have a default value= n (No) if not set")
   
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
    
   
# function to upload file, return True once completed or False for failed upload
def upload_file(filename,servername,username,password):
   # gets file size
   file_stats = os.stat(filename)
   filesize=file_stats.st_size
   # gets sha-512
   filehash=get_hash_file(filename)
   print("[Info] Sha2-512 hash: "+filehash)
   # creates authentication message
   auth="{\"username\":\""+username+"\","
   auth=auth+"\"password\":\""+password+"\","
   auth=auth+"\"filename\":\""+filename+"\","
   auth=auth+"\"filesize\":\""+str(filesize)+"\","
   auth=auth+"\"filehash\":\""+filehash+"\"}"
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
          print (msg.decode('ascii'))
             
   return False
   
############################# End functions code  ###################

############################# Main Code #############################
# set default values
servername=""
username=""
password=""
folder=""
wifionly="n"
encrypt="n"
deleteafterupload="n"

# gets command line parameters if any
try:
   opts, args = getopt.getopt(sys.argv[1:],"hs:u:p:f:w:e",["servername","username=","password=","folder","wifionly","encrypt","autodelete"])
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
   elif opt in ("-f", "--folder"):
      folder = arg
   elif opt in ("-w", "--wifionly"):
      wifionly = arg.lower()    
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
if len(folder)==0:
    e=e+"- folder parameter is missing\n"    
if wifionly!="y" and wifionly!="n":
    e=e+"Wifi parameter is wrong, should be y/n\n"
# exits in case of missing/wrong parameters
if len(e)>0:
    print(e)
    print_usage()
    sys.exit()
# check for wifi/wired connection
print(hashlib.algorithms_guaranteed) 

# upload files
for name in glob.glob(folder,recursive=True): 
    print("[Info] Uploading :"+name) 
    result=upload_file(name,servername,username,password)
    # auto delete if required
    #if deleteafterupload=="y" and result==True:
sys.exit()

    



