#!/usr/bin/python3
# Auto-upload Server
# Waits for a connection on port 443, force protocol TLS 1.2 (the higher available in Python for the moment)
# Each connection is managed in a thread to allow multiple connections
import socket
import ssl
from _thread import *
import threading 
import json
import sys
import os
import getopt
import argon2
import hashlib
import pyotp
# renames method
thread_lock = threading.Lock() 

################################## Functions code #####################################    
## print usage parameters
def print_usage():
    print("python3 auto-upload-server.py --pwdfilename=<passwordfilename> --certificatefilename=<fullchaincertificatefilename> --privatekeyfilename=<privatekeyfilename> --folder=<folderstorage>")
    print("or")
    print("python3  auto-upload-server.py -p <passwordfilename> -c <fullchaincertificatefilename> -k <privatekeyfilename> -f <folderstorage>")
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
        
## communication session
def threaded_communication(conn,iporigin,pwdfile,folder):
    #set folder with / at the end
    x=len(folder)
    if folder[x-1] is not "/":
        folder=folder+"/"
    while True: 
        # wait for authentication message
        data = conn.recv(2048)
        if not data:
            break
        auth=data.decode('ascii')
        print("[Debug] Received authentication messagge: "+auth)
        print("[Debug] Password file name to check: "+pwdfile)
        # checking fields received in the json message
        try:
            d=json.loads(auth)
        except:
            print("[Info] Wrong authentication message")
            conn.close()
            thread_lock.release() 
            return
        username=""
        password=""
        filename=""
        filesize=""
        filehash=""
        totp=""
        if "username" in d.keys(): 
            username=d["username"]
        if "password" in d.keys(): 
            password=d["password"]
        if "filename" in d.keys(): 
            filename=d["filename"]        
        if "filesize" in d.keys(): 
            filesize=d["filesize"]        
        if "filehash" in d.keys(): 
            filehash=d["filehash"]
        if "totp" in d.keys(): 
            totp=d["totp"]
        if len(username)==0 or len(password)==0 or len(filesize)==0 or  len(filehash)==0 or len(totp)==0 :
            answer="{\"answer\":\"KO\",\"message\":\"Authorization denied\"}"
            conn.sendall(answer.encode('utf-8'))
            print("[Info] Authorizaton denied")
            break
        # check password validity
        if verify_credentials(username,password,totp,pwdfile)==False:
            answer="{\"answer\":\"KO\",\"message\":\"Authorization denied for wrong credentials\"}"
            conn.sendall(answer.encode('utf-8'))
            print("[Info] Authorizaton denied for wrong credentials")
            break
        #authorized message
        answer="{\"answer\":\"OK\",\"message\":\"Transfer Authorized - Waiting for data\"}"
        conn.sendall(answer.encode('utf-8'))
        print("[Info] Authorized file transfer:"+filename+" waiting for data")
        #create user folder if does not exist
        localfolder=folder+username
        if not os.path.exists(localfolder):
            try:
                print("[Debug] Creating folder: ",localfolder)
                os.mkdir(localfolder)
            except OSError:
                print ("[Error] Creation of the folder %s failed" % localfolder)
                conn.close()
                thread_lock.release() 
                return
        localfilename = localfolder+"/"+os.path.basename(filename)
        print("[Info] Local file name: "+localfilename)
        f=open(localfilename,"wb")
        # receiving data loop over TLS
        bytesrcv=0
        fsize=int(filesize)
        while bytesrcv<fsize:
            data = conn.recv(32768)
            print("[Debug] Received block of bytes: ",len(data))
            if not data:
                break
            f.write(data)
            bytesrcv=bytesrcv+len(data)
            print("[Debug] Total bytes received: ",bytesrcv," expected: ",fsize)
        #file closing
        f.close()
        print("[Debug] End of file transfer")
        #check hash of the file
        currenthash=get_hash_file(localfilename)
        if currenthash==filehash:
            # confirm file transfer 
            answer="{\"answer\":\"OK\",\"message\":\"File Transfer Completed\"}"
        else:
            answer="{\"answer\":\"KO\",\"message\":\"File Transfer Broken\"}"
        conn.sendall(answer.encode('utf-8'))
    # close connection and release thread
    print("[Info] Connection closed with: "+iporigin)
    conn.close()
    thread_lock.release() 
    return
# function to verify username/password and totp
def verify_credentials(username,password,totp,pwdfile):
    flag=False
    if os.path.exists(pwdfile)==False:
         print("[Info] Password file not found: " +pwdfile)
         return(False)
    f=open(pwdfile,"r")
    while(True):
        r=f.readline()
        if not r:
          break
        v=r.split("#")
        hash=v[2].replace("\n","")
        hash=hash.replace("\r","")
        if v[0]==username:
          # verify OTP
          totpf = pyotp.TOTP(v[1])
          if totpf.verify(totp)==False:
              print("[Info] Totp authentication failed. Totp:",totp," seed: ".v[1])
              return False
          # verify password with Argon2
          try:
              print("[Debug] Checking password: "+password+" hash: "+hash)
              flag=argon2.PasswordHasher().verify(hash,password)
              print("[Info] Credentials validity: "+ flag)
              return True
          except:
              print("[Info] Credentials validity exit for exception")
              return False
    print("[Info] Credentials not valid for username not found")
    return False
################################## End functions code #################################    

################################## Main code ##########################################    
# gets command line parameters if any
pwdfile=""
certificate=""
privatekey=""
folder=""

try:
   opts, args = getopt.getopt(sys.argv[1:],"hp:c:k:f:",["pwdfile","certificate","privatekey","folder"])
except getopt.GetoptError:
   print("###")
   print_usage()
   print(getopt.GetoptError)
   sys.exit(2)
for opt, arg in opts:
   if opt == '-h':
      print_usage()
      sys.exit()
   elif opt in ("-p", "--pwdfile"):
      pwdfile = arg
   elif opt in ("-c", "--certificate"):
      certificate = arg
   elif opt in ("-k", "--privatekey"):
      privatekey = arg
   elif opt in ("-f", "--folder"):
      folder = arg     
#check parameters
if len(pwdfile)==0 or len(certificate)==0 or len(privatekey)==0 or len(folder)==0:
    print_usage()
    sys.exit(2)
if not os.path.exists(certificate):
    print("[Error] Certificate file not found ",certificate)
    sys.exit(2)
if not os.path.exists(privatekey):
    print("[Error] Private key file not found ",privatekey)    
    sys.exit(2)
    
#server starting
print("[Info] Auto-upload-server starting")
context = ssl.SSLContext(ssl.PROTOCOL_TLSv1_2)
context.load_cert_chain(certificate, privatekey)

#waiting for connections on port 443
with socket.socket(socket.AF_INET, socket.SOCK_STREAM, 0) as sock:
    sock.bind(('0.0.0.0', 443))
    sock.listen(5)
    print("[Info] Auto-upload-server waiting for connection")
    with context.wrap_socket(sock, server_side=True) as ssock:
        while True:
            conn, addr = ssock.accept()
            print('[Info] Connection from:',addr[0], ':', addr[1]) 
            thread_lock.acquire() 
            print('[Info] Starting new communication thread')             
            start_new_thread(threaded_communication, (conn,addr[0],pwdfile,folder))
        sock.close() 