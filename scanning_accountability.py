#! /usr/bin/python

# New script to replace bash script
from struct import *
class pyOperationsAccountability(object):
    def __init__(self):
        import sys
        self.config = {}
        self.config.update(main(sys.argv,self.config))
        self.firewall = False
        self.tcpdump = False
        self.interfaces = {}
        self.logging = False
        self.terminal = False
        self.upload = False
        self.localpath = ""
        self.uploadpath = ""
    def main(self,args,config):
        import signal, sys
        from datetime import datetime
        # thanks to Jorge E Cardona from Stack Overflow for this signal capture
        for i in [x for x in dir(signal) if x.startswith("SIG")]:
            try:
                signum = getattr(signal, i)
                signal.signal(signum, recover)
            except RuntimeError, m:
                print "Skipping %s" % i
        try:
            #default config file, TODO make os independent
            configfile = "/etc/accountability/accountability.config"
            # get initial config from config file and user overrides
            config = get_config(args,configfile)
            # get the time
            config['now'] = datetime.utcnow().strftime("%m%d%Y-%H%M%S")
            # Get os family name
            sysos = sys.platform
            if "win" in sysos:
                config['os'] = "windows"
            elif "linux" in sysos:
                config['os'] = "linux"
            elif "darwin" in sysos:
                config['os'] = "osx"
            else:
                sys.exit("main: critical: Unsupported OS detected!")
            # Next, get the tuple version of the OS version information
            if config['os'] == "linux":
                from platform import linux_distribution as dist
                config['osversion'] = dist()
            elif config['os'] == "windows":
                config['osversion'] = sys.getwindowsversion()
            # Update global variable
            self.interfaces[config['primarydevice']] = {"status":set_interface(config['primarydevice'], config['os'],'down')}
            self.interfaces[config['secondarydevice']] = {"status":set_interface(config['secondarydevice'], config['os'],'up')}
            self.localpath = config['localpath']
            self.uploadpath = config['uploadpath']
            # Enable firewall to spec
            self.firewall = set_firewall(config)
            # If the firewall isnt setup correctly, recover the system
            self.network = set_network(config)
            self.tcpdump = set_tcpdump("start", config)
            self.terminal = exec_terminal(config)
            self.logging = exec_logging(config['os'])
            self.recovered = exec_recover(config)
            self.upload = exec_upload(config)           
        except Exception as err:
            print("main: error: %s" % err)
        return config
    def get_config(self,args,configfile):
        # Imports
        import ConfigParser
        from getopt import getopt
        # Read in config
        try:
            config = ConfigParser.read(configfile)
        except Exception as err:
            print("gather_user_data: error: %s" % err)
        # Override with options
        try:
            opts, args = getopt(args, "hc:u:i:p:I:s:S:P:t:T:g:G:d:D:o:O:f:U:",
                                ["help", "config=", "user=", "ip=", "IP=", "subnet=", "SUBNET=", "prefix=", "PREFIX=",
                                 "team=", "Tracking=", "gateway=", "GATEWAY=", "device=", "DEVICE=", "output=", "Output=",
                                 "firewall=","Upload="])
            for opt, arg in opts:
                if opt in ("-h", "--help"):
                    print("Usage")
                    print("       i ip: Primary operations interface ip")
                    print("       I IP: Secondary operations interface ip")
                    print("       p prefix: Primary interface prefix (subnet in CIDR notation without /)")
                    print("       P PREFIX: Secondary interface prefix (subnet in CIDR notation without /)")
                    print("       s subnet: Primary operations interface subnet mask (not needed if prefix set)")
                    print("       S SUBNET: Secondary operations interface subnet mask (not needed if prefix set)")
                    print("       g gateway: Primary operations interface gateway")
                    print("       G GATEWAY: Secondary operations interface gateway")
                    print("       d device: Define name of primary operations interface")
                    print("       D DEVICE: Define name of secondary operations interface")
                    print("       t team: Name of the team running the operations")
                    print("       T Tracking: Ticket number, task number, etc.")
                    print("       o output: Path to where to output logs")
                    print("       u user: name of the user in operation")
                    print("       c config: alternate config file other than default")
                    print("       f firewall: iptables restore file full path")
                    print("       U Upload: upload path")
                elif opt in ("-c", "--config"):
                    config.update(ConfigParser.read(arg))
                elif opt in ("-i", "--ip"):
                    config['primaryip'] = arg
                elif opt in ("-I", "--IP"):
                    config['secondaryip'] = arg
                elif opt in ("-s", "--subnet"):
                    config['primarysubnet'] = arg
                elif opt in ("-S", "--SUBNET"):
                    config['secondarysubnet'] = arg
                elif opt in ("-g", "--gateway"):
                    config['primarygateway'] = arg
                elif opt in ('-G', "--GATEWAY"):
                    config['secondarygateway'] = arg
                elif opt in ("-d", "--device"):
                    config['primarydevice'] = arg
                elif opt in ("-D", "--DEVICE"):
                    config['secondarydevice'] = arg
                elif opt in ("-t", "--team"):
                    config['team'] = arg
                elif opt in ("-T", "--Tracking"):
                    config['tracking'] = arg
                elif opt in ('-o', "--output"):
                    config['localpath'] = arg
                elif opt in ('-u', '--user'):
                    config['user'] = arg
                elif opt in ('-O', "--Output"):
                    config['secondarypath'] = arg
                elif opt in ('-f','--firewall'):
                    config['firewallrestore'] = arg
                elif opt in "-U":
                    config['uploadpath'] = arg
                elif opt in ("-p","--prefix"):
                    config['primaryprefix'] = arg
                elif opt in ('-P','--PREFIX'):
                    config['secondaryprefix'] = arg
                else:
                    print("get_config: Invalid option: %s" % opt)
        except Exception as err:
            print("gather_user_data: error: %s" % err)
        return config
    def set_firewall(self, config):
        from subprocess import call
        if osname == "linux":
            try:
                call(['sudo','chkconfig','iptables','on'])
                call(['sudo','iptables-restore','<', config['firewallrestore']])
                call(['sudo', 'iptables', '-I', 'INPUT', '1', '-j', '--log-prefix', ' Operations Accountability Inbound ', '--log-level', '6'])
                call(['sudo', 'iptables', '-I', 'OUTPUT', '1', '-j', '--log-prefix', ' Operations Accountability Outbound ', '--log-level', '6'])
                call(['sudo','iptables','-I','OUTPUT','-4','-s','127.0.0.0/8','-d','127.0.0.0/8','-j','ACCEPT'])
                call(['sudo', 'iptables', '-I', 'INPUT', '-4', '-s', '127.0.0.0/8', '-d', '127.0.0.0/8', '-j', 'ACCEPT'])
                # TODO validate this is the return for RHEL, fedora, and CENTOS
                if "Redhat" in config['osversion'] or "rhel" in config['osversion']:
                    conffile = '/etc/rsylog.conf'
                elif "Ubuntu" in config['osversion'] or "ubuntu" in config['osversion'] or "debian" in config['osversion'] or "Debian" in config['osversion']:
                    conffile = '/etc/syslog.conf'
                else:
                    conffile = '/etc/syslog.conf'
                with open(conffile,'w') as logconf:
                    thefile = logconf.readlines()
                    thefile = ['kern.*        %s/%s-%s-fwaccountability.log' % (config['uploadpath'],config['now'],config['user'])] + thefile
                    logconf.writelines(thefile)
                    logconf.close()
                if "Redhat" in config['osversion'] or "rhel" in config['osversion']:
                    call(['sudo', 'service', 'rsyslog', 'restart'])
                elif "Ubuntu" in config['osversion'] or "ubuntu" in config['osversion'] or "debian" in config['osversion'] or "Debian" in config['osversion']:
                    call(['sudo', 'service', 'syslog', 'restart'])
                else:
                    call(['sudo','service','syslog','restart'])
                if config['remoteip']:
                    call(['sudo','route','add','-net', '%s/32' % config['remoteip']])
            except Exception as err:
                print("set_firewall: error: %s" % err)
        elif osname == "windows":
            #TODO by @JKauff, delete pass when updated
            pass
        else:
            print("set_firewall: warning: Unable to determine how to set up your firewall for %s %s!" % (config['os'],' '.join(config['osversion'])))
            return False
        print("set_firewall: Succesfully setup your firewall to log and match your restore file.")
        return True
    def set_tcpdump(self, action,config):
        from subprocess import call
        import socket
        if action == "start":
            if config['os'] == "linux":
                call(['sudo','-b','tcpdump','-C','1024','-s0','-l','-n','-i', config['primarydevice'],'-w','%s/%s-%s-accountbility.pcap' % (config['uploadpath'],datetime.utcnow().strftime("%m%d%Y-%H%M%S"),config['user'])])
            elif config['os'] == "windows" and config['listener'] == "tcpdump":
                call(['tcpdump', '-C', '1024', '-s0', '-l',' -n','-i','%s' % config['primarydevice'],'-w',
                      '%s/%s-%s-accountbility.pcap' % (config['output'],
                                                       datetime.utcnow().strftime("%m%d%Y-%H%M%S"), config['user'])])
            elif config['listener'] == "raw":
                # Thanks for this section to http://www.binarytides.com/python-packet-sniffer-code-linux/
                # create an INET, STREAMing socket
                try:
                    s = socket.socket(socket.AF_INET, socket.SOCK_RAW)
                except socket.error, msg:
                    print ('set_tcpdump: Error: Raw Socket Listener could not be created. Error Code : ' + str(msg[0]) + ' Message ' + msg[1])
                    print('Did you run this as root? Raw socket typically needs it.')
                    return
                # receive a packet
                with open('%s/%s-%s-accountbility.pcap' % (config['localpath'], datetime.utcnow().strftime("%m%d%Y-%H%M%S"), config['user']), 'w') as thefile:
                    while True:
                        packet = s.recvfrom(65565)
                        # packet string from tuple
                        packet = packet[0]
                        # take first 20 characters for the ip header
                        ip_header = packet[0:20]
                        # now unpack them :)
                        iph = unpack('!BBHHHBBH4s4s', ip_header)
                        version_ihl = iph[0]
                        version = version_ihl >> 4
                        ihl = version_ihl & 0xF
                        iph_length = ihl * 4
                        ttl = iph[5]
                        protocol = iph[6]
                        s_addr = socket.inet_ntoa(iph[8]);
                        d_addr = socket.inet_ntoa(iph[9]);
                        thefile.writelines('Version : ' + str(version) + ' IP Header Length : ' + str(ihl) + ' TTL : ' + str(
                            ttl) + ' Protocol : ' + str(protocol) + ' Source Address : ' + str(
                            s_addr) + ' Destination Address : ' + str(d_addr))
                        tcp_header = packet[iph_length:iph_length + 20]
                        # now unpack them :)
                        tcph = unpack('!HHLLBBHHH', tcp_header)
                        source_port = tcph[0]
                        dest_port = tcph[1]
                        sequence = tcph[2]
                        acknowledgement = tcph[3]
                        doff_reserved = tcph[4]
                        tcph_length = doff_reserved >> 4
                        thefile.writelines('Source Port : ' + str(source_port) + ' Dest Port : ' + str(
                            dest_port) + ' Sequence Number : ' + str(sequence) + ' Acknowledgement : ' + str(
                            acknowledgement) + ' header length : ' + str(tcph_length))
                        h_size = iph_length + tcph_length * 4
                        data_size = len(packet) - h_size
                        # get data from the packet
                        data = packet[h_size:]
                        thefile.writelines('Data : ' + data)
            else:
                print("set_tcpdump: Critical: Unable to determine pcap provider for your os!")
                from time import sleep
                sleep(2)
                return False
        elif action == "stop":
            if config['os'] == "linux":
                call(['sudo','pkill','-9','tcpdump'])
            elif config['os'] == "windows":
                #TODO @JKauff tasking, delete pass when done
                pass
            else:
                call(['sudo', 'pkill', '-9', 'tcpdump'])
                print("set_tcpdump: Warning: Default os type kill feature used.")
                from time import sleep
                sleep(2)
                return False
        return True
    def set_network(self, config):
        from re import match
        # Note: Need to ask users if they want to change from default configuration (for network changes)
        userinput = input("Would you like to override network defaults (yes/no): ")
        while not config['primarydevice'] or not config['primarygateway'] or not (config['primarysubnet'] or config['primaryprefix']) or match(r"^[yY]([eE][sS])?$", userinput) :
            config['primarydevice'] = input("Input the name of the primary operations device: ")
            config['primaryip'] = input("Input the primary device ip address (enter dhcp for dhcp): ")
            if not config['primaryip'] == "dhcp":
                config['primaryprefix'] = input("Input the primary device subnet prefix (leave blank to put in dot notation): ")
                if not config['primaryprefix']:
                    config['primarysubnet'] = input("Input the primary device subnet mask: ")
                config['primarygateway'] = input("Input the primary device gateway: ")
            config['secondarydevice'] = input("Input the name of the secondary operations device (blank if none): ")
            if config['secondarydevice']:
                config['secondaryip'] = input("Input the secondary device ip address (enter dhcp for dhcp): ")
                if not config['secondaryip'] == "dhcp":
                    config['secondaryprefix'] = input("Input the secondary device subnet prefix (leave blank to put in dot notation): ")
                    if not config['secondaryprefix']:
                        config['secondarysubnet'] = input("Input the secondary device subnet mask: ")
                    config['secondarygateway'] = input("Input the secondary device gateway: ")
            userinput = ""
        if config['os'] == "linux":
            if match(r"^[rR]([hHeElL]{3}|edhat).*", config['osversion'][0]):
                netconf = ["TYPE=ethernet", "NAME=%s" % config['primarydevice'], "DEVICE=%s" % config['primarydevice'], "DEFROUTE=yes", "IPV4_FAILURE_FATAL=no", "IPV6INIT=no","MTU=%s" % config['MTU'], "ONBOOT=no"]
                with open("/etc/sysconfig/network-scripts/ifcfg-%s" % config['primarydevice'], 'w') as thefile:
                    if config['primaryip'] == "dhcp":
                        netconf += ["BOOTPROTO=dhcp"]
                    else:
                        netconf += ["BOOTPROTO=none","IPADDR=%s" % config['primaryip'], "GATEWAY=%s" % config['primarygateway']]
                        if config['primaryprefix']:
                            netconf += ["PREFIX=%s" % config['primaryprefix']]
                        else:
                            netconf += ["NETMASK=%s" % config['primarysubnet']]
                    thefile.writelines(netconf)
                    thefile.close()
                netconf = ["TYPE=ethernet", "NAME=%s" % config['primarydevice'], "DEVICE=%s" % config['primarydevice'], "DEFROUTE=yes", "IPV4_FAILURE_FATAL=no", "IPV6INIT=no","MTU=%s" % config['mtu'], "ONBOOT=no"]
                if config['secondarydevice']:
                    with open("/etc/sysconfig/network-scripts/ifcfg-%s" % config['secondarydevice'], 'w') as thefile:
                        if config['secondaryip'] == "dhcp":
                            netconf += ["BOOTPROTO=dhcp"]
                        else:
                            netconf += ["BOOTPROTO=none","IPADDR=%s" % config['secondaryip'], "GATEWAY=%s" % config['secondarygateway']]
                            if config['secondaryprefix']:
                                netconf += ["PREFIX=%s" % config['secondaryprefix']]
                            else:
                                netconf += ["NETMASK=%s" % config['secondarysubnet']]
                        thefile.writelines(netconf)
                        thefile.close()
            elif match(r"^([Uu]buntu|[Dd]ebian)", config['osversion'][0]):
                with open("/etc/network/interfaces.d/%s.cfg" % config['primarydevice'], 'w') as thefile:
                    if config['primaryip'] == "dhcp":
                        netconf = ["iface %s inet dhcp"]
                    else:
                        netconf = ["iface %s inet static"]
                        if config['primaryprefix']:
                            netconf += ["address %s/%s" % (config['primaryip'],config['primaryprefix'])]
                        else:
                            netconf += ["address %s" % config['primaryip'], "netmask %s" % config['primaryprefix']]
                        netconf += ["gateway %s" % config['primarygateway'], "mtu %s" % config['mtu']]
                    thefile.writelines(netconf)
                    thefile.close()
                if config['secondarydevice']:
                    with open("/etc/network/interfaces.d/%s.cfg" % config['secondarydevice'], 'w') as thefile:
                        if config['secondaryip'] == "dhcp":
                            netconf = ["iface %s inet dhcp"]
                        else:
                            netconf = ["iface %s inet static"]
                            if config['secondaryprefix']:
                                netconf += ["address %s/%s" % (config['secondaryip'],config['secondaryprefix'])]
                            else:
                                netconf += ["address %s" % config['secondaryip'], "netmask %s" % config['secondaryprefix']]
                            netconf += ["gateway %s" % config['secondarygateway'], "mtu %s" % config['mtu']]
                        thefile.writelines(netconf)
                        thefile.close()
            else:
                print("set_network: warning: Unsupported linux os, cannot set interface.")
                return False            
        elif config['os'] == "windows":
            #TODO @JKAUFF, remove pass when done
            pass
        else:
            print("set_network: warning: Unsupported os, cannot set interface.")
            return False
        self.interfaces[config['primarydevice']] = {"status":set_interface(config['primarydevice'], config['os'],'up')}
        if config['secondarydevice']:
            self.interfaces[config['secondarydevice']] = {"status":set_interface(config['secondarydevice'], config['os'],'up')}
        return True
    def set_interface(self, interface, os , state):
        from subprocess import call
        x = input("Press enter to bring %s to state %s." % (interface, state))
        if os  == "linux":
            try:
                if state == "up":
                    call(['sudo','ifup','%s' % interface])
                elif state == "down":
                    call(['sudo','ifdown','%s' % interface])
                else:
                    print("set_interfaces: error: invalid state given.")
            except Exception as err:
                print("set_interfaces: error: ip command (ifup/ifdown) failed! Trying traditional.")
                try:
                    if state == "up":
                        call(['sudo','ifconfig','%s' % interface, 'up'])
                    elif state == "down":
                        call(['sudo','ifconfig','%s' % interface, 'down'])
                    else:
                        print("set_interfaces: error: invalid state given.")
                except Exception as err:
                    print("set_interfaces: critical: Failed to bring interface %s to state %s." % (interface,state))
                    from time import pause
                    pause(3)            
        elif os == "windows":
            # TODO @JKAUFF, remove pass when done
            pass
        else:
            print("set_interface: error: Unsupported OS passed. Unable to bring interface %s to state %s." % (interface,state))
            return False
        return True
    def set_clilogging(self,os):
        if os == "linux":
            addhistory ="export PROMPT_COMMAND='history -a'"
            with open("~/.bashrc",'a') as thefile:
                thefile.writelines([addhistory])
                thefile.close()
            return True
        elif os == "windows":
            # TODO @JKAUFF remove pass when done
            pass
        else:
            print("set_clilogging: error: Unsupported OS passed. Not doing anything.")
            return False
        return True
    def exec_terminal(self, os, osversion):
        from subprocess import call
        if os == "linux":
            call(['gnome-terminal'])
        elif os == "windows":
            #TODO @JKAUFF remove pass when done
            pass
        else:
            print("set_clilogging: error: Unsupported OS passed. Not doing anything.")
            return False
        return True
    def exec_logging(self, config):
        import os
        from datetime import datetime
        userinput = ''
        # Open CSV files for operations logging
        with open('%s%s-%s-%s-operationslog.csv' % (config['localpath'],config['now'], config['team'],config['user']), 'w') as csvfile:
            cfieldnames = ['DateTime','User','action']
            writer = csv.DictWriter(csvfile, fieldnames=cfieldnames)
            writer.writeheader()
            # Iterate through user inputs
            while userinput != "exit":
                # Clear the terminal window
                if config['os'] == "windows":
                    os.system('cls')
                else:
                    os.system('clear')
                # Print Menu of options
                print("Operations Accountability User Logging")
                print("           exit     - leave user logging")
                print("           pause    - pause accountability")
                print("           reload   - reload firewall rules")
                print("           log      - enter log entry")
                # Get user selection
                userinput = input("Enter action: ")
                # Complete actions
                if userinput == "exit":
                    csvfile.close()
                    print("actionlog: Closing User Operations Log.")
                    return
                elif userinput == "pause":
                    # This feature is because we noticed with interface bounces tcpdump will go supernova
                    writer.writerows({'DateTime':datetime.utcnow().strftime("%m%d%Y-%H%M%S"), 'User':config['user'],'action':'Warning: User has paused accountability!'})
                    self.tcpdump = set_tcpdump('stop',config)
                    self.interfaces[config['primarydevice']] = {"status":set_interface(config['primarydevice'], config['os'],'down')}
                    x = input("Press Enter To Continue Accountability.")
                    # Validate network setup
                    self.network = set_network(config)
                    # Re enable tcpdump
                    self.tcpdump = set_tcpdump('start',config)
                elif userinput == "reload":
                    # In case user needs to reload the firewall after making changes to iptables restore file
                    self.firewall = set_firewall(config)
                    print("actionlog: Firewall reload completed.")
                    # We add this pause so user can see the above output
                    from time import sleep
                    sleep(2)
                elif userinput == "log":
                    # write user input to csv file
                    writer.writerows({'DateTime': datetime.utcnow().strftime("%m%d%Y-%H%M%S"), 'User': config['user'],
                                      'action':'%s' % input("Enter log entry then hit enter: ")})
                else:
                    print("actionog: Invalid Entry")
                    from time import sleep
                    # We add this pause so user can see the above output
                    sleep(2)
        return True
    def exec_upload(self, config):
        if not config['localpath'] or not config['uploadpath']:
            return False
        from subprocess import call
        try:
            if config['os'] == "linux":
                call(['cp','-rf',config['localpath'],config['uploadpath']])
            elif config['os'] == "windows":
                #TODO @JKAUFF remove pass when done
                pass
            else:
                print("exec_upload: error: unsupported OS")
                return False
        except Exception as err:
            print("exec_upload: Upload failed due to %s." % err)
            return False
        return True
    def exec_recover():
        print("exec_recover: warning: beginning recovery steps!")
        self.interfaces[config['primarydevice']] = {"status":set_interface(config['primarydevice'], config['os'],'down')}        
        self.tcpdump = set_tcpdump("stop",config)
        print("exec_recover: Recovery completed!")
        return True
if __name__ = "main:
    import pyOperationsAccountability
    x = pyOperationsAccountability()
