import netifaces

print (netifaces.interfaces())


#print (netifaces.ifaddresses('lo'))

#print (netifaces.AF_LINK)

#addrs=netifaces.ifaddresses('enp0s31f6')
#print(addrs)
#print(addrs[netifaces.AF_INET][0]['addr'])
print(netifaces.ifaddresses('enp0s31f6')[netifaces.AF_INET][0]['addr'])
#print(addrs[netifaces.AF_LINK])