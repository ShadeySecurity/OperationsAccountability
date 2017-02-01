#! /usr/bin/python

# New script to replace bash script

def main(args):
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
        # Enable firewall to spec
        firewallstatus = set_firewall(config)
        # If the firewall isnt setup correctly, recover the system
        if not firewallstatus:
            recover()
    except Exception as err:
        print("main: error: %s" % err)

def get_config(args,configfile):
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
        opts, args = getopt(args, "hc:u:i:p:I:s:S:P:t:T:g:G:d:D:o:O:f:z:",
                            ["help", "config=", "user=", "ip=", "IP=", "subnet=", "SUBNET=", "prefix=", "PREFIX=",
                             "team=", "Tracking=", "gateway=", "GATEWAY=", "device=", "DEVICE=", "output=", "Output=",
                             "firewall="])
        for opt, arg in opts:
            if opt in ("-h", "--help"):
                print("Usage")
                print("       i ip: Primary operations interface ip")
                print("       I IP: Secondary operations interface ip")
                print("       s subnet: Primary operations interface subnet mask")
                print("       S SUBNET: Secondary operations interface subnet mask")
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
                print("       z: remote secondary path ip (if off system)")
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
                config['outputpath'] = arg
            elif opt in ('-u', '--user'):
                config['user'] = arg
            elif opt in ('-O', "--Output"):
                config['secondarypath'] = arg
            elif opt in ('-f','--firewall'):
                config['firewallrestore'] = arg
            elif opt in "-z":
                config['remoteip'] = arg
            else:
                print("get_config: Invalid option: %s" % opt)
    except Exception as err:
        print("gather_user_data: error: %s" % err)
    return config

def set_firewall(config):
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
                thefile = ['kern.*        %s/%s-%s-fwaccountability.log' % (config['outputpath'],config['now'],config['user'])] + thefile
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
        #TODO by @JKauff
    else:
        print("set_firewall: warning: Unable to determine how to set up your firewall for %s %s!" % (config['os'],' '.join(config['osversion'])))
        return
    print("set_firewall: Succesfully setup your firewall to log and match your restore file.")
    pass
def set_tcpdump(action,config):
    #TODO
    pass
def upload_output(config):
    #TODO
    pass
def recover():
    #TODO
    pass
def set_network(config):
    #TODO
    # Note: Need to ask users if they want to change from default configuration (for network changes)
    pass

def set_clilogging():
    #TODO
    pass
def launch_terminal():
    from subprocess import call
    call(['gnome-terminal'])
def actionlog(config):
    import os
    userinput = ''
    thelog = ['']
    # Open CSV files for operations logging
    with open('%s%s-%s-operationslog.csv' % (config['output'],config['now'], config['user']), 'w') as csvfile:
        cfieldnames = ["DateTime','User',','action']
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
                set_tcpdump('stop',config)
                x = input("Press Enter To Continue Accountability.")
                # Validate network setup
                set_network(config)
                # Re enable tcpdump
                set_tcpdump('start',config)
            elif userinput == "reload":
                # In case user needs to reload the firewall after making changes to iptables restore file
                set_firewall(config)
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




