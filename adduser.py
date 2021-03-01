#!/usr/bin/python3
# Auto-upload Server - Utility to add an user to a password file
from argon2 import PasswordHasher
import sys
import getopt
import os
import pyotp

#function to print the usage parameters
def print_usage():
    print("python3 adduser.py --username=<username> --password=<password> --filename=<passwordfilename>")
    print("or")    
    print("python3 adduser.py -u <username> -p <password> -f <passwordfilename>")
    return
# function to check the presence of username in the password file    
def check_free_username(username,filename):
    flag=True
    if os.path.exists(filename)==False:
       return(True)
    f=open(filename, "rt")
    while(True):
        r=f.readline()
        if not r:
          break
        v=r.split("#")
        if v[0]==username:
            flag=False
    f.close()
    return flag
    
# default settings
username=""
password=""
filename=""
try:
   opts, args = getopt.getopt(sys.argv[1:],"hu:p:f:",["username=","password=","filename="])
except getopt.GetoptError:
   print_usage()
   sys.exit(2)
for opt, arg in opts:
   if opt in ("-h", "--help"):
      print_usage()
      sys.exit()
   elif opt in ("-u", "--username"):
      username = arg
   elif opt in ("-p", "--password"):
      password = arg
   elif opt in ("-f", "--filename"):
      filename = arg
      
if len(username)==0 or len(password)==0 or len(filename)==0:
   print_usage()
   sys.exit(2)
if check_free_username(username,filename)==False:
    print("[Error] Username is already used")
    sys.exit(2)
# encode with argon2 the password
hash=PasswordHasher().hash(password)
# generate a TOTP seed
totp=pyotp.random_base32()
w=username+"#"+totp+"#"+hash+"\n"
print("[Info] Writing file: "+filename)
f=open(filename, "a+")
f.write(w)
f.close()
print("[Info] New user added with TOTP SEED:",totp," (please configure it in your client)");
sys.exit(0)



