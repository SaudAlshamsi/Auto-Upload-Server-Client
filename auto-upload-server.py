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
from argon2 import PasswordHasher
# renames method
thread_lock = threading.Lock() 

################################## Functions code #####################################    
## print usage parameters
def print_usage():
    print("python3 auto-upload-server.py --pwdfilename=<passwordfilename> --certificatefilename=<fullchaincertificatefilename> --privatekeyfilename=<privatekeyfilename>")
    print("or")
    print("python3  auto-upload-server.py -p <passwordfilename> -c <fullchaincertificatefilename> -k <privatekeyfilename>")
    return
    
## communication session
def threaded_communication(conn,iporigin,pwdfile):
    while True: 
        # wait for authentication message
        data = conn.recv(2048)
        if not data:
            break
        auth=data.decode('ascii')
        print("[Debug] Received authentication messagge: "+auth)
        print("[Debug] Password file name to check: "+pwdfile)
        # checking fields received in the json message
        d=json.loads(auth)
        username=""
        password=""
        filesize=""
        filehash=""
        if "username" in d.keys(): 
            username=d["username"]
        if "password" in d.keys(): 
            password=d["password"]
        if "filesize" in d.keys(): 
            filesize=d["filesize"]        
        if "filehash" in d.keys(): 
            filehash=d["filehash"]
        if len(username)==0 or len(password)==0 or len(filesize)==0 or  len(filehash)==0 :
            answer="{\"answer\":\"KO\",\"message\":\"Authorization denied\"}"
            conn.sendall(answer.encode('utf-8'))
            print("[Info] Authorizaton denied")
            break
        # check password validity
        if verify_credentials(username,password,pwdfile)==False:
            answer="{\"answer\":\"KO\",\"message\":\"Authorization denied for wrong credentials\"}"
            conn.sendall(answer.encode('utf-8'))
            print("[Info] Authorizaton denied for wrong credentials")
            break
        
        #echo data back for testing
        conn.sendall(data)
    # close connection and release thread
    print("[Info] Connection closed with: "+iporigin)
    conn.close()
    thread_lock.release() 
    return
# function to verify username and password
def verify_credentials(username,password,pwdfile):
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
        hash=v[1].replace("\n","")
        if v[0]==username:
          try:
              print("[Debug] Checking password: "+password+" hash: "+hash)
              flag=argon2.PasswordHasher().verify(hash,password)
              print("[Info] Credentials validity: "+ flag)
          except:
              print("[Info] Credentials validity exit for exception")
              return True
    print("[Info] Credentials not valid for username not found")
    return False
################################## End functions code #################################    

################################## Main code ##########################################    
# gets command line parameters if any
pwdfilename=""
certificatefilename=""
privatekeyfilename=""

try:
   opts, args = getopt.getopt(sys.argv[1:],"hp:c:k:",["pwdfile","certificate","privatekey"])
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
#check parameters
if len(pwdfile)==0 or len(certificate)==0 or len(privatekey)==0:
    print("pwdfilename:" + pwdfile);
    print("certificate: "+certificate)
    print("privatekey: "+privatekey)
    print_usage()
    sys.exit(2)

#server starting
print("[Info] Auto-upload-server starting")
context = ssl.SSLContext(ssl.PROTOCOL_TLSv1_2)
context.load_cert_chain('/etc/letsencrypt/live/upload.umabot.ai/fullchain.pem', '/etc/letsencrypt/live/upload.umabot.ai/privkey.pem')

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
            start_new_thread(threaded_communication, (conn,addr[0],pwdfile))
        sock.close() 