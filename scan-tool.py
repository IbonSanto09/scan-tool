#!/usr/bin/python3

import nmap

print("""
   _____  _____          _   _     _______ ____   ____  _      
  / ____|/ ____|   /\   | \ | |   |__   __/ __ \ / __ \| |     
 | (___ | |       /  \  |  \| |______| | | |  | | |  | | |     
  \___ \| |      / /\ \ | . ` |______| | | |  | | |  | | |     
  ____) | |____ / ____ \| |\  |      | | | |__| | |__| | |____ 
 |_____/ \_____/_/    \_\_| \_|      |_|  \____/ \____/|______|
""")


ip=input("[+] IP Objetivo ==> ")
nm = nmap.PortScanner()
open_ports="-p #!/usr/bin/python3

print("""
Tool to scan ports by IbonSanto09
download at https://github.com/IbonSanto09/scan-tool
""")


ip=input("[+] IP Objetivo ==> ")
nm = nmap.PortScanner()
open_ports="-p "
results = nm.scan(hosts=ip,arguments="-sT -n -Pn -T4")
count=0
#print (results)
print("\nHost : %s" % ip)
print("State : %s" % nm[ip].state())
for proto in nm[ip].all_protocols():
	print("Protocol : %s" % proto)
	print()
	lport = nm[ip][proto].keys()
	sorted(lport)
	for port in lport:
		print ("port : %s\tstate : %s" % (port, nm[ip][proto][port]["state"]))
		if count==0:
			open_ports=open_ports+str(port)
			count=1
		else:
			open_ports=open_ports+","+str(port)

print("\nPuertos abiertos: "+ open_ports +" "+str(ip))"
results = nm.scan(hosts=ip,arguments="-sT -n -Pn -T4")
count=0
#print (results)
print("\nHost : %s" % ip)
print("State : %s" % nm[ip].state())
for proto in nm[ip].all_protocols():
	print("Protocol : %s" % proto)
	print()
	lport = nm[ip][proto].keys()
	sorted(lport)
	for port in lport:
		print ("port : %s\tstate : %s" % (port, nm[ip][proto][port]["state"]))
		if count==0:
			open_ports=open_ports+str(port)
			count=1
		else:
			open_ports=open_ports+","+str(port)

print("\nOpen ports: "+ open_ports +" "+str(ip))

#IbonSanto09