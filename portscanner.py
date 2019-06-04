import nmap

first_port_scanner = nmap.PortScanner()

print("PORT SCANNER TOOL \n by Matia Pivirotto")


host_scan = input("Which HOST do you want to scan?")

first_port_scanner.scan(host_scan,"1-1024")

for host in first_port_scanner.all_hosts():
     print('Host : %s (%s)' % (host, nmScan[host].hostname()))
     print('State : %s' % nmScan[host].state())
     for proto in nmScan[host].all_protocols():
         print('----------')
         print('Protocol : %s' % proto)
 
         lport = nmScan[host][proto].keys()
         lport.sort()
         for port in lport:
             print ('port : %s\tstate : %s' % (port, nmScan[host][proto][port]['state'])
    

