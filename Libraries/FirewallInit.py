class FireWallInit:

    def __init__(self):
        # Key is network, value is exceptions
        self.peer_nets= {"127.0.0.1":{"in":["127.0.0.3"], "out":["127.0.0.4"]}}
        self.target_nets= {"127.0.0.1":{"in":["127.0.0.3"], "out":["127.0.0.4"]}}
        # single list elements
        self.notouch_nets= []
        self.knownbad_nets= []
        self.os = {"Family":"unknown","Version":"unknown"}
        # Configuration TODO: Move to config file read in
        self.options = { "policy": { "INPUT":"DROP", "OUTPUT":"DROP", "FORWARD":"DROP"} }
        self.support_systems = {"ntp": ["127.0.0.1"], "dns": ["1.1.1.1"], "share":["127.0.0.1"], "dhcp":["127.0.0.1"]}

    def ResetIPTables(self):
        from subprocess import call
        try:
            # Wipe IPTABLES
            call("sudo iptables -F ")
            call("sudo iptables -X")
            # Set Policy default
            call("sudo iptables -P INPUT %s" % self.options["policy"]["INPUT"])
            call("sudo iptables -P OUTPUT %s" % self.options["policy"]["OUTPUT"])
            call("sudo iptables -P FORWARD %s" % self.options["policy"]["FORWARD"])
            # Create our in chains
            call("sudo iptables -N PeerHosts_In")
            call("sudo iptables -N SupportSystems_In")
            call("sudo iptables -N TargetNets_In")
            # Create our out chains
            call("sudo iptables -N PeerHosts_Out")
            call("sudo iptables -N SupportSystems_Out")
            call("sudo iptables -N TargetNets_Out")
            # Create our single direction chains
            call("sudo iptables -N NoTouchNets")
            call("sudo iptables -N KnownBadNets")
            # Create jumps for output
            call("sudo iptables -I OUTPUT -d 0.0.0.0 -j NoTouchNets")
            call("sudo iptables -I OUTPUT -d 0.0.0.0 -j KnownBadNets")
            call("sudo iptables -A OUTPUT -d 0.0.0.0 -j PeerHosts_Out")
            call("sudo iptables -A OUTPUT -d 0.0.0.0 -j SupportSystems_Out")
            call("sudo iptables -A OUTPUT -d 0.0.0.0 -j TargetNets_Out")
            # Create jumps for input
            call("sudo iptables -I INPUT -d 0.0.0.0 -j KnownBadNets")
            call("sudo iptables -A INPUT -d 0.0.0.0 -j PeerHosts_In")
            call("sudo iptables -A INPUT -d 0.0.0.0 -j SupportSystems_In")
            call("sudo iptables -A INPUT -d 0.0.0.0 -j TargetNets_In")
            # Create jumps for forward
            call("sudo iptables -I FORWARD -d 0.0.0.0 -j NoTouchNets")
            call("sudo iptables -I FORWARD -d 0.0.0.0 -j KnownBadNets")
        except Exception as err:
            print("Error while initializing IPTables reset: %s" % err)
            return False
        return True

    def ConfigIPTables(self):
        from subprocess import call
        try:
            # Set NoTouchNets
            for network in self.notouch_nets:
                call("sudo iptables -A NoTouchHosts -d %s -j LOG" % network)
                call("sudo iptables -A NoTouchHosts -d %s -j REJECT" % network)
        except Exception as err:
            print("Error setting no touch hosts: %s" % err)
            return False

        try:
            # Set KnownBadNets
            for network in self.knownbad_nets:
                call("sudo iptables -A KnownBadNets -s %s -j LOG" % network)
                call("sudo iptables -A KnownBadNets -s %s -j DROP" % network)
                call("sudo iptables -A KnownBadNets -d %s -j LOG" % network)
                call("sudo iptables -A KnownBadNets -d %s -j REJECT" % network)
        except Exception as err:
            print("Error setting known bad hosts: %s" % err)
            return False

        try:
            # Set Peer Hosts
            for network,exceptionnet in self.peer_nets:
                for net in exceptionnet["out"]:
                    call("sudo iptables -A PeerHosts_Out -d %s -j REJECT" % net)
                for net in exceptionnet["in"]:
                    call("sudo iptables -A PeerHosts_In -s %s -j REJECT" % net)
                call("sudo iptables -A PeerHosts_Out -d %s -j ACCEPT" % network)
                call("sudo iptables -A PeerHosts_In -s %s -j ACCEPT" % network)
        except Exception as err:
            print("Error setting peer hosts: %s" % err)
            return False

        try:
            # Set SupportSystem Hosts
            for net in self.support_systems["dns"]:
                call("sudo iptables -A SupportSystems_In -s %s -p UDP --sport 53 -j ACCEPT" % net)
                call("sudo iptables -A SupportSystems_Out -d %s -p UDP --dport 53 -j ACCEPT" % net)
            for net in self.support_systems["ntp"]:
                call("sudo iptables -A SupportSystems_In -s %s -p UDP --sport 123 -j ACCEPT" % net)
                call("sudo iptables -A SupportSystems_Out -d %s -p UDP --dport 123 -j ACCEPT" % net)
            for net in self.support_systems["share"]:
                call("sudo iptables -A SupportSystems_In -s %s -P TCP --sport 22 -j ACCEPT" % net)
                call("sudo iptables -A SupportSystems_Out -d %s -P TCP --dport 22 -j ACCEPT" % net)
                call("sudo iptables -A SupportSystems_In -s %s -p TCP --sport 139 -j ACCEPT" % net)
                call("sudo iptables -A SupportSystems_In -s %s -p TCP --sport 445 -j ACCEPT" % net)
                call("sudo iptables -A SupportSystems_Out -d %s -p TCP --dport 139 -j ACCEPT" % net)
                call("sudo iptables -A SupportSystems_Out -d %s -p TCP --dport 445 -j ACCEPT" % net)
            for net in self.support_systems["dhcp"]:
                call("sudo iptables -A SupportSystems_In -s %s -p UDP --sport 67 -j ACCEPT" % net)
                call("sudo iptables -A SupportSystems_In -s %s -p UDP --sport 68 -j ACCEPT" % net)
                call("sudo iptables -A SupportSystems_Out -d %s -p UDP --dport 67 -j ACCEPT" % net)
                call("sudo iptables -A SupportSystems_Out -d %s -p UDP --dport 68 -j ACCEPT" % net)
        except Exception as err:
            print("Error setting support system rules: %s" % err)
            return False

        try:
            #Set Target Networks
            for network , exceptionnet in self.target_nets:
                for net in exceptionnet["in"]:
                    call("sudo iptables -A TargetNets_In -s %s -j ACCEPT" % net)
                for net in exceptionnet["out"]:
                    call("sudo iptables -A TargetNets_Out -d %s -j DENY" % net)
            call("sudo iptables -A TargetNets_Out -d %s -j ACCEPT" % network)
            call("sudo iptables -A TargetNets_In -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT")
        except Exception as err:
            print("Error setting target network rules: %s" % err)
            return False
        return True

    def InitFirewall(self):
        from subprocess import call
        if self.os["Version"] == "rhel":
            call("sudo systemctl disable firewalld")
            call("sudo systemctl stop firewalld")
        elif self.os["Version"] == "ubuntu":
            call("sudo ufw disable")
        else:
            return False
        return True

    def DockerSetup(self):
        from subprocess import call
        call('sudo sed -i "s/dockerd/dockerd --iptables=false/g" /usr/lib/systemd/system/docker.service')
        call('sudo systemctl restart docker')
