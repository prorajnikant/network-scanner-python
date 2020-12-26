import nmap

#initialize the port scanner
nmScan = nmap.PortScanner()

def nmap_scanner(ip,port_range):

	nmScan.scan(ip,port_range)

	for host in nmScan.all_hosts():
		print(f"Host : {host} ({nmScan[host].hostname()}) ")
		print(f"State : {nmScan[host].state()}")

		for protocol in nmScan[host].all_protocols():
			print("-"*20)
			print(f"Protocol : {protocol}")

			lport = nmScan[host][protocol].keys()
			lport.sort()

			for port in lport:
				print(f"Port : {port}\tState : {nmScan[host][protocol][port]['state']}")


nmap_scanner('127.0.0.1','21-443')