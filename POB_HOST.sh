#!/bin/bash


##########################
# SECTION 0: GATHER DATA #
##########################

# Add our entry to hosts file
echo "Enter handle or name: "
read HANDLE
echo "Enter partner network ip address: "
read DIP
echo "Enter partner network prefix (CIDR notation): "
read PREFIX
if [ -z "$PREFIX" ]; then
	echo "Enter subnet mask (full dot notation): "
	read SUBNET
fi
echo "Enter partner network gateway IP address: "
read GATEWAY
echo "Enter sortie number: "
read SORTIE
echo "Enter squad: "
read SQUAD
history -c


#############
# VARIABLES #
#############
MISSIONLOCAL=""
SORTIELOCALFOLDER="$MISSIONLOCAL/sortie$SORTIE"
ACCOUNTABILITYFOLDER="$SORTIELOCALFOLDER/accountability"
OUTPUTFOLDER="$SORTIELOCALFOLDER/output"
CONFIGFOLDER=""
SORTIEDRIVE=""
SHAREDRIVEIP=""
SHAREDRIVESHARE=""
SHAREMOUNT=""
ACTION="initial"
CREWLOGFILE="$ACCOUNTABILITYFOLDER/CrewLog-$(dare+'%Y%m%d_%H%M%S')_Sortie_$SORTIE_$HANDLE.csv"
BASHFILE="$ACCOUNTABILITYFOLDER/BashHistory_$(date+'%Y%m%d_%H%M%S')_Sortie_$SORTIE_$HANDLE"
PCAP="/tmp/PCAP-$(date +'%Y%m%d_%H%M%S')_Sortie_$SORTIE_$HANDLE.pcap"
INTERFACE=""
# TODO get current user and assign to variable. Replace all <user> entries below with variable.


########################
# Function Definitions #
########################

# Trap to this cleanup function so that we reset firewall and disable interface in case of failure
function cleanup
{
	# Drop external interface
	sudo ifdown $INTERFACE
	if [ `cat /sys/class/net/$INTERFACE/operstate` == "up" ]; then
		sudo /usr/sbin/ifconfig $INTERFACE down
	fi
	echo "INFO: External interface takedown complete"
	
	# Stop the TCPDUMP
	if pgrep "tcpdump" > /dev/null 2>& 1; then
		sudo pkill tcpdump
		if pgrep "tcpdump" > /dev/null 2>& 1; then
			sudo pkill -9 tcpdump
		fi
	fi
	echo "INFO: TCPDUMP kill complete"
	
	# Reset the firewall
	sudo iptables --flush
	# Add allow rule for share drive
	sudo iptables -I OUTPUT -j ACCEPT -d $SHAREDRIVEIP
	sudo iptables -I INPUT -j ACCEPT -d $SHAREDRIVEIP
	sudo iptables -I INPUT -4 -p tcp -m conntrack --cstate RELATED,ESTABLISHED -j ACCEPT
	# Add allow rule for local host
	sudo iptables -I OUTPUT -4 -s 127.0.0.0/8 -j ACCEPT
	# Default drop
	sudo iptables -P INPUT DROP
	sudo iptables -P OUTPUT DROP
	sudo iptables -P FORWARD DROP
	echo "INFO: Firewall reset complete"

	# Restore /etc/bashrc
	sudo chown <user>:<user> /home/<user>/.bashrc*
	mv -f /home/<user>/.bashrc.bak /home/<user>/.bashrc
	echo "INFO: /home/<user>/.bashrc restored"

	echo "INFO: Cleanup complete"

	echo "DISCONNECT VM EXTERNAL INTERFACE FOR MISSION PARTNER NETWORK. Press enter to continue."
	read n
}
trap "cleanup; exit" SIGHUP SIGINT SIGTERM


#################
# PRECONNECTION #
#################

# Delete current bash history
sudo rm /home/<user>/.bash_history

# Create backup of current bashrc
sudo cp /home/<user>/.bashrc /home/<user>/.bashrc.bak

echo "CLOSE ALL OTHER TERMINAL WINDOWS TO ENSURE COMMAND HISTORY IS CAPTURED. Press enter to continue."
read n

# Add setting for interactive terminal command logging
sudo bash -c "echo \"export PROMPT_COMMAND='history -a'\" >> /home/<user>/.bashrc"
echo "INFO: Command logging enabled"

# Dump table of current rules
sudo iptables --flush
# Add allow rules for share drive
sudo iptables -I INPUT -j ACCEPT -d $SHAREDRIVEIP
sudo iptables -I OUTPUT -j ACCEPT -d $SHAREDRIVEIP
# Add logging rule for outbound sortie traffic
sudo iptables -I OUTPUT -j LOG --log-prefix "OUTBOUND SORTIE $SORTIE TRAFFIC"

# Setup local sortie folder
if [ ! -d "$ACCOUNTABILITYFOLDER" ]; then
	sudo mkdir -p "$ACCOUNTABILITYFOLDER"
fi
if [ ! -d "$OUTPUTFOLDER" ]; then
	sudo mkdir -p "$OUTPUTFOLDER"
fi
sudo chown <user>:<user> $SORTIELOCALFOLDER -R
echo "INFO: Local directory setup complete"

# Mount share
if [ ! -d "$MISSIONLOCAL/mission-share" ]; then
	sudo mkdir -p "$SHAREMOUNT"
fi
# TODO replace <share_dir> with correct directory
if [ ! -d "$MISSIONLOCAL/mission-share/<share_dir>" ]; then
	sudo mount -t cifs -o username=<user> //$SHAREDRIVEIP/$SHAREDRIVESHARE $SHAREMOUNT
fi
echo "INFO: Remote directory setup complete"

# Get host files from remote share
if [ ! -f "$SORTIEDRIVE/hosts/trusted.hosts" -o ! -f "$SORTIEDRIVE/hosts/target.hosts" ]; then
	echo "WARNING: trusted or target hosts missing from sortie folder on mission share."
	echo "Exit script now if host files are required."
	read n
fi
sudo cp -fvu $SORTIEDRIVE/hosts/trusted.hosts /etc > /dev/null
sudo cp -fvu $SORTIEDRIVE/hosts/target.hosts /etc > /dev/null
# Create blank host files if not present
if [ ! -f /etc/trusted.hosts ]; then
	echo "" | sudo tee /etc/trusted.hosts
fi
if [ ! -f /etc/target.hosts ]; then
	echo "" | sudo tee /etc/target.hosts
fi

# Add ouput allow rules for trusted and target hosts
while read host
do
	sudo iptables -I OUTPUT -4 -j ACCEPT -d $host
done < /etc/trusted.hosts
while read host
do
	sudo iptables -I OUTPUT -4 -j ACCEPT -d $host
done < /etc/target.hosts
# Add input allow rules for trusted and target hosts
sudo iptables -I INPUT -4 -p icmp -m icmp --icmp-type 0 -j ACCEPT
sudo iptables -I INPUT -4 -p icmp -m icmp --icmp-type 8 -j ACCEPT
sudo iptables -I INPUT -p tcp -m conntrack --cstate RELATED,ESTABLISHED -j ACCEPT
while read host
do
	sudo iptables -I INPUT -4 -p udp -j ACCEPT -s $host
done < /etc/trusted.hosts
while read host
do
	sudo iptables -I INPUT -4 -p udp -j ACCEPT -s $host
done < /etc/target.hosts
sudo iptables -I OUTPUT -4 -s 127.0.0.0/8 -d 127.0.0.0/8 -j ACCEPT
# Default drop
sudo iptables -P INPUT DROP
sudo iptables -P OUTPUT DROP
sudo iptables -P FORWARD DROP

echo "INFO: Firewall setup complete"


######################
# CYA AND CONNECTION #
######################

# Add IP to config
cp -fv $CONFIGFOLDER/ifcfg-* /tmp > /dev/null
echo "IPADDR=$DIP" >> /tmp/ifcfg-$INTERFACE
if [ -n "$SUBNET" ]; then
	echo "NETMASK=$SUBNET" >> /tmp/ifcfg-$INTERFACE
fi
if [ -n "$PREFIX" ]; then
	echo "PREFIX=$PREFIX" >> /tmp/ifcfg-$INTERFACE
fi
echo "GATEWAY=$GATEWAY" >> /tmp/ifcfg-$INTERFACE
sudo cp -fv /tmp/ifcfg-$INTERFACE /etc/sysconfig/network-scripts > /dev/null

# Update SSH config
sudo cp -fu $CONFIGFOLDER/sshd_config /etc/ssh > /dev/null

# Bring interface up so we can start pcap. VM interface should still be disconnected.
echo "VERIFY THAT VM INTERFACE FOR MISSION PARTNER NETWORK IS DISCONNECTED"
ECHO "Interface will be brought up in OS in order to start pcap. Press enter to continue."
read n
sudo ifup $INTERFACE > /dev/null
echo "INFO: Interface setup complete"

# Start tcpdump
sudo -b tcpdump -l -n -i $INTERFACE -w $PCAP
sleep 5
# Validate that tcpdump is running and that our ip address was successfully changed.
PCAPPROC=$(ps -elfnope | grep -i tcpdump | grep -i cvah)
if [ ! -f "$PCAP" -a -n "$PCAPPROC" ]; then
	echo "TCPDUMP not started. Exiting."
	cleanup
	exit
else
	echo "INFO: TCPDUMP running"
fi
if [ -n "$PREFIX" ]; then
	# TODO check with Bowen, is $IPADDR supposed to be $DIP?
	CURRENTIP=$(ip addr show $INTERFACE | grep -i "$IPADDR/$PREFIX")
else
	CURRENTIP=$(ifconfig $INTERFACE | grep -i "inet $IPADDR netmask $SUBNET")
fi
if [ -z "$CURRENTIP" ]; then
	echo "IP change failed. Exiting."
	cleanup
	exit
fi

echo "REVIEW IPTABLES RULES. Press enter to continue."
read n
sudo iptables -nvL | less
echo "EXIT SCRIPT IF RULES ARE NOT AS EXPECTED. Press enter to continue."
read n

echo "CONNECT VM INTERFACE FOR MISSION PARTNER NETWORK. Press enter to continue."
read n

# For reasons unknown, bringing interface up takes over default gw and kills mission share connectivity
# Add static route back in
# TODO add mission share subnet and interface name back in
sudo route add -net <mission-share-subnet> <interface>


##########
# SORTIE #
##########

echo "OPENING NEW TERMINAL RUNNING TO RUN COMMANDS"
gnome-terminal

echo "Date,Hand or Name,Action" >> $CREWLOGFILE
while [ ! "$ACTION" = "exit" ]
do
	echo "Action Taken (type exit to finish sortie): "
	read ACTION
	if [ "$ACTION" = ]; then
		break
	fi
	echo "$(date -u),$HANDLE,$ACTION" >> $CREWLOGFILE
done


###############
# POST SORTIE #
###############

sudo chown <user>:<user> "$SORTIELOCALFOLDER" -R

# Cleanup function disables mission partner network interface, stops tcpdump, and resets firewall rules
cleanup

# Move pcaps to local sortie folder
mv $PCAP $ACCOUNTABILITYFOLDER > /dev/null

# Copy command history to sortie folder
cp -fu /home/<user>/.bash_history $BASHFILE > /dev/null

# Upload all files to mission share
echo "INFO: Beginning upload to mission share"
cp -rfv $SORTIELOCALFOLDER/* $SORTIEDRIVE > /dev/null
echo "INFO: File upload complete"

echo "INFO: Script complete"