#Checking password: mypwd hash: $argon2id$v=19$m=102400,t=2,p=8$EzLx2PAzeyAyfruUO8kVvw$wpFvzBwebsmbj74bemEsaQ
#import argon2
import socket
import ssl
from _thread import *
import threading 
import json
import sys
import os
import getopt
import argon2

password="mypwd"
hash="$argon2id$v=19$m=102400,t=2,p=8$EzLx2PAzeyAyfruUO8kVvw$wpFvzBwebsmbj74bemEsaQ"
print("[Debug] Checking password: "+password+" hash: "+hash)
flag=argon2.PasswordHasher().verify(hash,password)
print("[Info] Credentials validity: "+ flag)
