import ipaddress
import json
import os
import socket
import subprocess
import time
from queue import Queue
from threading import Thread

import fuckit
import psutil
import requests


def getLocalIP():
    hostname = socket.gethostname()
    IPAddr = socket.gethostbyname(hostname)
    return IPAddr


def findVendor(macAddress):
    MAC_URL = 'http://macvendors.co/api/%s'
    r = requests.get(MAC_URL % macAddress)
    rJSON = r.json()

    return rJSON


def checkIfValidIP(IP):
    try:
        socket.inet_aton(IP)
        # UtilitiesLogger.debug("IP Address format is valid")
        return True
    except Exception as e:
        return False


def getAllNetworkDevicesIPAndMAC(IP=None):
    listOfIPs = []
    listOfIP_MACTuples = []
    arpA = subprocess.Popen(('arp -a'), stdout=subprocess.PIPE)
    if IP is not None:
        arpA = subprocess.Popen(('arp -a ' + IP), stdout=subprocess.PIPE)
    ipout = arpA.communicate()[0]
    ipout = (ipout.decode('utf-8'))
    for line in ipout.split("\r\n"):
        ip = line[0:18].strip()
        if checkIfValidIP(ip):
            listOfIPs.append(ip)
            macAddress = line[18:43].strip()
            listOfIP_MACTuples.append((ip, macAddress))
    listOfIP_MACTuples = list(set(listOfIP_MACTuples))
    # print("Found " + str(listOfIP_MACTuples.__len__()) + " IPs via ARP command")
    return listOfIP_MACTuples


threadQueue = Queue()


def pingHosts(net_addr):
    ip_net = ipaddress.ip_network(net_addr)
    all_hosts = list(ip_net.hosts())
    # Configure subprocess to hide the console window
    info = subprocess.STARTUPINFO()
    info.dwFlags |= subprocess.STARTF_USESHOWWINDOW
    info.wShowWindow = subprocess.SW_HIDE
    iterations = len(all_hosts)
    foundCounter = 0
    print("Starting ping sweep for " + str(iterations) + " IP addresses above " + str(all_hosts[0]))
    for i in range(iterations):
        ip = str(all_hosts[i])
        # print("Pinging " + ip)
        output = subprocess.Popen(['ping', '-n', '1', '-w', '400', ip], stdout=subprocess.PIPE,
                                  startupinfo=info).communicate()[0].decode("utf-8")
        if "Received = 1" in output and "unreachable" not in output:
            # print(ip, "is Online!!")
            # print(output)
            foundCounter += 1
            try:
                macAddress = getAllNetworkDevicesIPAndMAC(ip)[0]
                foundIP = macAddress[0]
                foundMAC = macAddress[1]
                vendorData = findVendor(foundMAC)['result']
                with open("foundIPs.txt", "a+") as foundIPs:
                    vendorJSON = json.dumps(vendorData, indent=4)
                    IPandVendorData = '{:14}'.format(foundMAC) + " @ " + foundIP + ":" + "\n" + str(
                        vendorJSON)
                    print(IPandVendorData)
                    foundIPs.write(IPandVendorData + "\n----------------------------\n")
            except Exception as e:
                print("MAC not found for " + ip)
                print(e)
    else:
        print("Scan for " + net_addr + " complete. " + str(foundCounter) + " IPs responded")
        threadQueue.task_done()


myIP = getLocalIP()
localIP_CIDR = getLocalIP()
with fuckit:
    os.remove("foundIPs.txt")
startTime = time.clock()
thirdOctet = 0
while thirdOctet < 255:
    cpu = int(psutil.cpu_percent(interval=0.5))
    print("CPU: " + str(cpu) + "%")
    if cpu < 70 and cpu > 0:
        splitIP = localIP_CIDR.split(".")
        localIP_CIDR = splitIP[0] + "." + splitIP[1] + "." + str(thirdOctet) + ".0/24"
        pingThread = Thread(target=pingHosts, args=(localIP_CIDR,))
        pingThread.start()
        thirdOctet += 1
        threadQueue.put(pingThread)

threadQueue.join()
endTime = time.clock()
duration = endTime - startTime
m, s = divmod(duration, 60)
print("Ping sweep complete in " + str(m) + "minutes, " + str(s) + " seconds")
