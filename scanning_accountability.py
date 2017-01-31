#! /usr/bin/python

# New script to replace bash script

#Imports
from getopt import getopt
import sys
import ConfigParser

def main(args):
  configfile = "/etc/accountability/accountability.config"
  config = get_config(args,configfile)
  
def get_config(args,configfile):
  # Read in config
  try:
    config = ConfigParser.read(configfile)
  except Exception as err:
    print("gather_user_data: error: %s" % err)
  # Override with options
  try:
    opts, args = getopt(args, "hc:u:i:p:I:s:S:P:t:T:g:G:d:D:o:O:", ["help", "config=", "user=", "ip=", "IP=", "subnet=", "SUBNET=", "prefix=", "PREFIX=", "team=", "Tracking=","gateway=", "GATEWAY=", "device=", "DEVICE=", "output=", "Output="])
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
      elif opt in ("-c", "--config"):
        config.udate(ConfigParser.read(arg))
      elif opt in ("-i", "--ip"):
        config['primaryip'] = arg
      elif opt in ("-I", "--IP");
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
      else:
        print("get_config: Invalid option: %s" % opt)        
  except Exception as err:
    print("gather_user_data: error: %s" % err)
  return config

def set_firewall():
  #TODO

def activate_tcpdump(switch,output):
  #TODO
  
def upload_output
