#!usr/bin/evn python3
import nmap
import argparse
import socket

#initialize the port scanner
nmScan = nmap.PortScanner()

def nmap_scanner(ip,port_range):

	nmScan.scan(ip,str(port_range))

	for host in nmScan.all_hosts():
		print(f"Host : {host} ({nmScan[host].hostname()}) ")
		print(f"State : {nmScan[host].state()}")

		for protocol in nmScan[host].all_protocols():
			print("-"*20)
			print(f"Protocol : {protocol}")

			lport = nmScan[host][protocol].keys()
			#lport.sort()

			for port in lport:
				print(f"Port : {port}\tState : {nmScan[host][protocol][port]['state']}")
'''
def banner_grabbing(host,port):

	sock = socket.socket(socket.AF_INET,socket.SOCK_STREAM) #TCP

	sock.connect((host,port))
	sock.send('GET HTTP/1.1 \r\n')

	ret = sock.recv(1024)
	print ('[+]' + str(ret))
'''
def main():
	
	parser = argparse.ArgumentParser(description="python scan_nmap.py  --host=<host ip>  --port=<port or port range separated by a '-' >")

	parser.add_argument('--host',action="store",dest = "host ip" , required=True)
	parser.add_argument('--port',action="store",dest = "port number(s)" ,required=True)
	
	args = parser.parse_args()
	host = args.host
	port = args.port

	if host == None or port == None:
		print(parser.usage)
	else:
		print(f"Scanning : {host} - {port}")

	nmap_scanner(host,port)
	#banner_grabbing(host,int(port))


if __name__ == '__main__':
	main()#!usr/bin/evn python3
import nmap
import argparse
import socket

#initialize the port scanner
nmScan = nmap.PortScanner()

def nmap_scanner(ip,port_range):

	nmScan.scan(ip,str(port_range))

	for host in nmScan.all_hosts():
		print(f"Host : {host} ({nmScan[host].hostname()}) ")
		print(f"State : {nmScan[host].state()}")

		for protocol in nmScan[host].all_protocols():
			print("-"*20)
			print(f"Protocol : {protocol}")

			lport = nmScan[host][protocol].keys()
			#lport.sort()

			for port in lport:
				print(f"Port : {port}\tState : {nmScan[host][protocol][port]['state']}")
'''
def banner_grabbing(host,port):

	sock = socket.socket(socket.AF_INET,socket.SOCK_STREAM) #TCP

	sock.connect((host,port))
	sock.send('GET HTTP/1.1 \r\n')

	ret = sock.recv(1024)
	print ('[+]' + str(ret))
'''
def main():
	
	parser = argparse.ArgumentParser(description="python scan_nmap.py  --host=<host ip>  --port=<port or port range separated by a '-' >")

	parser.add_argument('--host',action="store",dest = "host ip" , required=True)
	parser.add_argument('--port',action="store",dest = "port number(s)" ,required=True)
	
	args = parser.parse_args()
	host = args.host
	port = args.port

	if host == None or port == None:
		print(parser.usage)
	else:
		print(f"Scanning : {host} - {port}")

	nmap_scanner(host,port)
	#banner_grabbing(host,int(port))


if __name__ == '__main__':
	main()