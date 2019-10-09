# aspns - another simple python network scanner

import sys
import csv
import shutil
from tempfile import NamedTemporaryFile
from scapy.all import ARP, Ether, srp, sr1, IP, ICMP
from datetime import datetime
from manuf import manuf


'''Scans the network by sending ARP packets in broadcast and getting the response.'''
def scan(ip):
    print("Scanning the network...")

    arp_request = ARP(pdst=ip)

    broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")

    packet = broadcast/arp_request

    res = srp(packet, timeout=3, verbose=False)[0]

    clients = []
    for elem in res:
        client_dict = {"ip": elem[1].psrc, "mac": elem[1].hwsrc}
        clients.append(client_dict)

    return clients

'''Gets manufacturer based on a MAC address.'''
def getVendor(mac, parser):
    try:
        vendor = parser.get_manuf(mac)
        if vendor is None:
            return "Not found"
        return parser.get_manuf(mac)
    except:
        return "Could not retrieve manufacturer"

'''Reads and updates clients.csv.'''
def updateClientsFile(f, tempfile, clients):
    print("Updating clients.csv...")

    fields = ['IP', 'COUNT', 'STATUS', 'MAC', 'VENDOR', 'TIMESTAMP']
    reader = csv.DictReader(f, fieldnames=fields)
    writer = csv.DictWriter(tempfile, fieldnames=fields)
    header = next(reader) # = fields
    writer.writerow(header)

    row_list = list(reader)
    ip_mac_list = []
    for row in row_list:
        info = {'ip': row['IP'], 'mac': row['MAC']}
        ip_mac_list.append(info)

    updated_rows = []
    parser = manuf.MacParser(update=False)

    for client in clients:
        # New clients.
        if client not in ip_mac_list:
            row = {'IP': client['ip'],
                   'COUNT': 1,
                   'STATUS': "ACTIVE",
                   'MAC': client['mac'],
                   'VENDOR': getVendor(client['mac'], parser),
                   'TIMESTAMP': str(datetime.now())[:16]}
            updated_rows.append(row)
        # Updates old clients (COUNT++).
        else:
            idx = ip_mac_list.index(client)
            old_count = int(row_list[idx]['COUNT'])
            row_list[idx]['COUNT'] = old_count + 1

    # Old but inactive clients.
    for idx, old_client in enumerate(ip_mac_list):
        if not any(client == old_client for client in clients):
            row_list[idx]['STATUS'] = "INACTIVE"
        else:
            row_list[idx]['STATUS'] = "ACTIVE"

    updated_rows += row_list

    for row in updated_rows:
        writer.writerow(row)

'''Prints the updated content from clients.csv.'''
def print_clients(filename):
    print("-"*80)
    # Could've just returned the updated rows from updateClientsFile, but lazy.
    with open(filename, 'r') as f:
        active_devices = 0
        inactive_devices = 0
        new_devices = 0
        reader = csv.reader(f)
        # 0 - IP
        # 1 - COUNT
        # 2 - STATUS
        # 3 - MAC
        # 4 - VENDOR
        # 5 - TIMESTAMP
        for row in reader:
            if (row[2] == "ACTIVE"):
                active_devices += 1
            elif (row[2] == "INACTIVE"):
                inactive_devices += 1
            if (row[2] == "ACTIVE" and row[1] == "1"):
                new_devices += 1
            print('{:<15} {:<6} {:<9} {:<18} {:<10} {:<16}'.format(*row))

    print("-"*80)
    print("> Total devices:\t", active_devices + inactive_devices)
    print("> Active devices:\t", active_devices)
    print("> Inactive devices:\t", inactive_devices)
    print("> New devices:\t\t", new_devices)

def main(argv):
    own_ip = argv
    router_ip = sr1(IP(dst="www.google.com", ttl = 0)/ICMP()/"XXXXXXXXXXX", verbose=False).src
    print("> Your IP:\t\t", own_ip)
    print("> Default gateway:\t", router_ip)
    scan_res = scan(own_ip)

    filename = "clients.csv"
    tempfile = NamedTemporaryFile(mode='w', delete=False)

    with open(filename, "r") as f, tempfile:
        updateClientsFile(f, tempfile, scan_res)
    shutil.move(tempfile.name, filename)

    print_clients(filename)

if __name__ == "__main__":
    if len(sys.argv)==1:
        sys.exit("Error: run like 'sudo python aspns.py 172.21.x.xxx/yy'")
    main(sys.argv[1])
