import nmap

first_port_scanner = nmap.PortScanner()

print("PORT SCANNER TOOL \n by Matia Pivirotto")


host_scan = input("Which HOST do you want to scan?")

first_port_scanner.scan(host_scan,"1-1024")

for host in first_port_scanner.all_hosts():
     print('Host : %s (%s)' % (host, first_port_scanner[host].hostname()))
     print('State : %s' % first_port_scanner[host].state())
     for proto in first_port_scanner[host].all_protocols():
         print('----------')
         print('Protocol : %s' % proto)
 
         lport = first_port_scanner[host][proto].keys()
         lport.sort()
         for port in lport:
             print ('port : %s\tstate : %s' % (port, first_port_scanner[host][proto][port]['state'])
    

