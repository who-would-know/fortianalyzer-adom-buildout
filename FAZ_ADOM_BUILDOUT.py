#!/usr/bin/python

import os
import os.path
import sys
import time
import requests
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
requests.packages.urllib3.disable_warnings()
import json
import getpass
import transcript

### Remove previous log files and create a new files
######
if os.path.isfile('mainLOG.txt'):
	os.remove('mainLOG.txt')
if os.path.isfile('ERRORlog.txt'):
        os.remove('ERRORlog.txt')
transcript.start('mainLOG.txt')
ERRORlog = open("ERRORlog.txt", "a")
print ('>> Start logging script output to mainLOG.txt <<')

### Start stopwatch for script timing
######
stopwatchSTART = time.time()

### Get variables from user input
######
print ('--> Prompting for variables to use \n\
--> Please provide values or except defaults')
print

## FMG Info
print
print ('====================FMG=========')
print('FortiManager IP address? (default: 192.168.1.1): ')
hostIP = input()
if hostIP == '':
	hostIP = '192.168.1.1'
print ('    Using: %s' % hostIP)

print('FortiManager API admin (Read Only min. requirement)? (default: script_user): ')
hostADMIN = input()
if hostADMIN == '':
	hostADMIN = 'script_user'
print ('    Using: %s' % hostADMIN)

hostPASSWD = getpass.getpass('FortiManager API password? (default: ---): ')
if hostPASSWD == '':
	hostPASSWD = ''
hostPASSWDlength = (len(hostPASSWD))
secret = '*' * hostPASSWDlength
print ('    Using: %s' % secret)

print('FortiGate device name as seen in FMG device mgr tab? (default: FGT-70): ')
fgtDEVname = input()
if fgtDEVname == '':
        fgtDEVname = 'FGT-70'
print ('    Using: %s' % fgtDEVname)

###

## FAZ Info
print
print ('====================FAZ=========')
print('FortiAnalyzer IP address? (default: 10.101.101.1): ')
newhostIP = input()
if newhostIP == '':
        newhostIP = '10.101.101.1'
print ('    Using: %s' % newhostIP)

print('FortiAnalyzer API admin (Read-Write required)? (default: apifaz): ')
newhostADMIN = input()
if newhostADMIN == '':
        newhostADMIN = 'apifaz'
print ('    Using: %s' % newhostADMIN)

newhostPASSWD = getpass.getpass('FortiAnalyzer API password? (default: ---): ')
if newhostPASSWD == '':
        newhostPASSWD = ''
newhostPASSWDlength = (len(newhostPASSWD))
newsecret = '*' * newhostPASSWDlength
print ('    Using: %s' % newsecret)
##

print('FortiGate device name as seen in FAZ device mgr tab? (default: FGT-70): ')
newfgtDEVname = input()
if newfgtDEVname == '':
	newfgtDEVname = 'FGT-70'
print ('    Using: %s' % newfgtDEVname)

print
print ('-=-' * 20)
while True:
	try:
		print('--> Continue script with current variables? (y or n): ')
		goNOgo = input()
	except ValueError:
		print ('    Input not understood, please input y or n.')
		continue
	if goNOgo == 'y':
		print ('    Variables accepted, continuing script.')
		print
		print ('-=-' * 20)
		print
		goNOgo = ''
		break
	elif goNOgo == 'n':
		print ('    Variables NOT accepted, exiting script!')
		print
		exit()
	else:
		print ('    Input not understood, please input y or n!')
		print
		continue

### Define additional global variables
######
url = 'https://' + hostIP + '/jsonrpc'

session = ''
state = 0
adomRAW = ''
fgtLIST = []
adomLIST = []
taskID = ''

### Define classes and functions
######
def get_adom():
        #global adomRAW
        global adomLIST
        json_url = "dvmdb/adom"
        body = {
                "id": 1,
                "method": "get",
                "params": [{
                        "expand member": [
                            {
                                "fields": [
                                    "name",
                                ],
                                "filter": [
                                    "name", "==", fgtDEVname
                                ],
                                "url": "/device"
                            }
                        ],
                       "fields": [
                            "name",
                       ],
                       "url": json_url
                }],
                "session": session,
                #"verbose": 1
        }
        r = requests.post(url, json=body, verify=False)
        json_resp = json.loads(r.text)
        #print(json.dumps(json_resp, indent=2))
        for entry in json_resp['result'][0]['data']:
            #print(entry);
            if "expand member" in entry:
                adomLIST.append(entry['name'])
                #print(entry)


def list_fgt():
	global fgtLIST
	fgtLIST = []
	json_url = "dvmdb/adom/" + adomRAW + "/device"
	body = {
		"id": 1,
		"method": "get",
		"params": [{
			"url": json_url
		}],
		"session": session
	}
	r = requests.post(url, json=body, verify=False)
	json_resp = json.loads(r.text)
	json_mesg = json_resp['result'][0]['status']['message']
	print ('<-- Hcode: %d Jmesg: %s' % (r.status_code, json_resp['result'][0]['status']['message']))
	print
	if json_resp['result'][0]['data'] is None:
		pass
	else:
		for entry in json_resp['result'][0]['data']:
	        	fgtLIST.append(entry['name'])

def list_vdom(fgtDEVICE, adomRAW):
	global vdomLIST
	vdomLIST = []
	json_url = "dvmdb/adom/" + adomRAW + "/device/" + fgtDEVICE + "/vdom"
	print(json_url)
	body = {
        "id": 1,
        "method": "get",
        "params": [{
            "url": json_url
         }],
        "session": session
    }
	r = requests.post(url, json=body, verify=False)
	json_resp = json.loads(r.text)
	json_mesg = json_resp['result'][0]['status']['message']
	print ('<-- Hcode: %d Jmesg: %s' % (r.status_code, json_resp['result'][0]['status']['message']))
	print
	if json_resp['result'][0]['data'] is None:
		pass
	else:
		for entry in json_resp['result'][0]['data']:
			vdomLIST.append(entry['name'])	


def list_filtered_adom_vdom():
	global vdom2adomLIST
	get_adom()    
	vdom2adomLIST = []
	for adomRAW  in adomLIST:
		list_vdom(fgtDEVname, adomRAW)
		for vdom in vdomLIST:
			vdom2adomLIST.append(vdom + ":" + adomRAW)		 
			print ('>> Match found VDOM  %s to ADOM %s <<' % (vdom, adomRAW) ) 
		time.sleep( 0.3 )

	print
	print ('--> Getting a list of all ADOMs containing FGT %s' % fgtDEVname)
	print
	print ('    Current number of all ADOMs found: %s' % len(adomLIST))
	print ('    Current number of matching ADOMs found: %s' % len(adomLIST))
	print
	print('\n')
	print ('--> Current list of matching VDOM to ADOM found:')
	print ('\n'.join(vdom2adomLIST))
	print 
	print('\n')
	print ('--> Current list of matching ADOMs found:')
	print ('\n'.join(adomLIST))
	print
	print ('-=-' * 20)
	print
	while True:
		try:
			print ('--> Continue script with current list of ADOMs? (y or n): ')
			goNOgo = input()
		except ValueError:
			print ('    Input not understood, please input y or n.')
			continue
		if goNOgo == 'y':
			print ('    ADOM list accepted, continuing script. Creating ADOMs on FMG %s' %  newhostIP )
			print
			print ('-=-' * 20)
			print
			goNOgo = ''
			break
		elif goNOgo == 'n':
			print ('    ADOM list NOT accepted, exiting script!')
			print
			fmg_logout()
			exit()
		else:
			print ('    Input not understood, please input y or n!')
			print
			continue

# Modify for FAZ 09/05/2023
def create_adom(createADOM):
	json_url = "dvmdb/adom/"
	body = {
		"id": 1,
		"method": "add",
		"params": [{
			"url": json_url,
			"data": {
				"name": createADOM,
				"mr" : "0", 
				"os_ver": "7.0",
				"flags": ["no_vpn_console"] #, "per_device_wtp"]
			}
		}],
		"session": session
	}
	r = requests.post(url, json=body, verify=False)
	json_resp = json.loads(r.text)
	#taskID = json_resp['result'][0]['data']['task']
	print
	print ('--> Created ADOM %s' % createADOM)
	print ('<-- Hcode: %d Jmesg: %s' % (r.status_code, json_resp['result'][0]['status']['message']))
	print
	time.sleep( 0.3 )

# Modify for FAZ 09/05/2023
def move_vdom(mvVDOM, mvADOM):
	#global taskID
	#json_url = "dvmdb/adom/" + mvADOM + "/device/" + mvVDOM + "/vdom"  #"/object member" 
	json_url = "dvmdb/adom/" + mvADOM + "/object member" 
	body = {
	"id": 1,
		"method": "add",
		"params": [{
       			"url": json_url,
              		"data": {
                		"name": newfgtDEVname,
                       		"vdom": mvVDOM
						#"name": mvVDOM 
               		}
              	}],
              	"session": session
 	}
	r = requests.post(url, json=body, verify=False)
	json_resp = json.loads(r.text)
       	#taskID = json_resp['result'][0]['data']['task']
	print
	print ('--> Moved VDOM %s to  ADOM %s' % (mvVDOM, mvADOM))
	print ('<-- Hcode: %d Jmesg: %s' % (r.status_code, json_resp['result'][0]['status']['message']))
	print
	time.sleep( 0.3 )	
	#poll_taskid()


def errorexit():
	print ('-=-' * 20)
	stopwatchTOTAL = time.time()-stopwatchSTART
	print ('>>>>>> %s ran for %d seconds <<<<<<' % (sys.argv[0], stopwatchTOTAL))
	print ('-=-' * 20)

	print ('>> Stop logging script output to mainLOG.txt <<')
	ERRORlog.close();
	transcript.stop()
	print ('-=-' * 20)
	print ('Script existing due to error, for Log files please view "mainLOG.txt", "skipADOMlist.txt", and "ERRORlog.txt".\n')
	print ('Closing console 5..4..3..2..1.')
	time.sleep( 5 )

# FMG Login
def fmg_login(hostAPIUSER, hostPASSWD, hostIP):
    '''FortiManager Login & Create Session
    Arguments:
    hostAPIUSER - API User Account Name
    hostPASSWD - API User Passwd
    hostIP - IP addres of FortiManager. Note, if not on default HTTPS(443) port can input: 1.1.1.1:8080
    '''
    #Global Save Session ID
    global session
    #Create HTTPS URL
    global url
    url = 'https://' + hostIP + '/jsonrpc'
    #JSON Body to sent to API request
    body = {
    "id": 1,
            "method": "exec",
            "params": [{
                    "url": "sys/login/user",
                    "data": [{
                            "user": hostAPIUSER,
                            "passwd": hostPASSWD
                    }]
            }],
            "session": 1
    }
    #Test HTTPS connection to host then Capture and output any errors
    print ('--> Logging into FortiManager: %s' % hostIP)
    try:
        r = requests.post(url, json=body, verify=False)
    except requests.exceptions.RequestException as e: 
        print (SystemError(e))
        print ('<--Connection was not Successful, please try again, exiting...')
        errorexit()
        #Exit Program, Connection was not Successful
        sys.exit(1)
    #Save JSON response from FortiManager
    json_resp = json.loads(r.text)
    #Check if User & Passwd was valid, no code -11 means invalid
    if json_resp['result'][0]['status']['code'] != -11:
        session = json_resp['session']
        #print ('--> Logging into FortiManager: %s' % hostIP)
        #HTTP & JSON code & message
        print ('<-- HTTPcode: %d JSONmesg: %s' % (r.status_code, json_resp['result'][0]['status']['message']))
        print
    else:
        print ('<--Username or password is not valid, please try again, exiting...')
        #HTTP & JSON code & message
        print ('<-- HTTPcode: %d JSONmesg: %s' % (r.status_code, json_resp['result'][0]['status']['message']))
        print
        errorexit()
        #Exit Program, Username or Password is not valided or internal FortiManager error review Hcode & Jmesg
        sys.exit(1)

def fmg_logout(hostIP):
    '''FortiManager logout
    Arguments:
    hostIP - IP addres of FortiManager. Note, if not on default HTTPS(443) port can input: 1.1.1.1:8080
    '''
    body = {
       "id": 1,
        "method": "exec",
        "params": [{
                "url": "sys/logout"
        }],
        "session": session
    }
    #Test HTTPS connection to host then Capture and output any errors
    try:
        r = requests.post(url, json=body, verify=False)
    except requests.exceptions.RequestException as e:
        print (SystemError(e))
        #Exit Program, Connection was not Successful
        sys.exit(1)
    #Save JSON response from FortiManager    
    json_resp = json.loads(r.text)
    #Check if any API Errors returned
    if json_resp['result'][0]['status']['code'] != -11:    
        print ('--> Logging out of FMG: %s' % hostIP)
        #HTTP & JSON code & message
        print ('<-- HTTPcode: %d JSONmesg: %s' % (r.status_code, json_resp['result'][0]['status']['message']))
        print
    else:
        print ('<--Error Occured, check Hcode & Jmesg')
        #Exit Program, internal FortiManager error review Hcode & Jmesg
        print ('<-- HTTPcode: %d JSONmesg: %s' % (r.status_code, json_resp['result'][0]['status']['message']))
        print
        errorexit()
        sys.exit(1)   

# Add FAZ Login & Logout 09/05/2023
def faz_login(hostAPIUSER, hostPASSWD, hostIP):
    '''FortiAnalyzer Login & Create Session
    Arguments:
    hostAPIUSER - API User Account Name
    hostPASSWD - API User Passwd
    hostIP - IP addres of FortiManager. Note, if not on default HTTPS(443) port can input: 1.1.1.1:8080
    '''
    #Global Save Session ID
    global session
    #Create HTTPS URL
    global url
    url = 'https://' + hostIP + '/jsonrpc'
    #JSON Body to sent to API request
    body = {
    "id": 1,
            "method": "exec",
            "params": [{
                    "url": "sys/login/user",
                    "data": [{
                            "user": hostAPIUSER,
                            "passwd": hostPASSWD
                    }]
            }],
            "session": 1
    }
    #Test HTTPS connection to host then Capture and output any errors
    print ('--> Logging into FortiAnalyzer: %s' % hostIP)
    try:
        r = requests.post(url, json=body, verify=False)
    except requests.exceptions.RequestException as e: 
        print (SystemError(e))
        print ('<--Connection was not Successful, please try again, exiting...')
        errorexit()
        #Exit Program, Connection was not Successful
        sys.exit(1)
    #Save JSON response from FortiManager
    json_resp = json.loads(r.text)
    #Check if User & Passwd was valid, no code -11 means invalid
    if json_resp['result'][0]['status']['code'] != -11:
        session = json_resp['session']
        #print ('--> Logging into FortiAnalyzer: %s' % hostIP)
        #HTTP & JSON code & message
        print ('<-- HTTPcode: %d JSONmesg: %s' % (r.status_code, json_resp['result'][0]['status']['message']))
        print
    else:
        print ('<--Username or password is not valid, please try again, exiting...')
        #HTTP & JSON code & message
        print ('<-- HTTPcode: %d JSONmesg: %s' % (r.status_code, json_resp['result'][0]['status']['message']))
        print
        errorexit()
        #Exit Program, Username or Password is not valided or internal FortiManager error review Hcode & Jmesg
        sys.exit(1)

def faz_logout(hostIP):
    '''FortiManager logout
    Arguments:
    hostIP - IP addres of FortiAnalyzer. Note, if not on default HTTPS(443) port can input: 1.1.1.1:8080
    '''
    body = {
       "id": 1,
        "method": "exec",
        "params": [{
                "url": "sys/logout"
        }],
        "session": session
    }
    #Test HTTPS connection to host then Capture and output any errors
    try:
        r = requests.post(url, json=body, verify=False)
    except requests.exceptions.RequestException as e:
        print (SystemError(e))
        #Exit Program, Connection was not Successful
        sys.exit(1)
    #Save JSON response from FortiManager    
    json_resp = json.loads(r.text)
    #Check if any API Errors returned
    if json_resp['result'][0]['status']['code'] != -11:    
        print ('--> Logging out of FortiAnalyzer: %s' % hostIP)
        #HTTP & JSON code & message
        print ('<-- HTTPcode: %d JSONmesg: %s' % (r.status_code, json_resp['result'][0]['status']['message']))
        print
    else:
        print ('<--Error Occured, check Hcode & Jmesg')
        #Exit Program, internal FortiManager error review Hcode & Jmesg
        print ('<-- HTTPcode: %d JSONmesg: %s' % (r.status_code, json_resp['result'][0]['status']['message']))
        print
        errorexit()
        sys.exit(1)   

def workspace_lock(lADOM):
	json_url = "pm/config/adom/" + lADOM + "/_workspace/lock"
	body = {
		"id": 1,
		"method": "exec",
		"params": [{
			"url": json_url
		}],
		"session": session
	}
	r = requests.post(url, json=body, verify=False)
	json_resp = json.loads(r.text)
	print ('--> Locking ADOM %s' % lADOM)
	print ('<-- Hcode: %d Jmesg: %s' % (r.status_code, json_resp['result'][0]['status']['message']))
	print

def workspace_commit(cADOM):
	json_url = "pm/config/adom/" + cADOM + "/_workspace/commit"
	body = {
		"id": 1,
		"method": "exec",
		"params": [{
			"url": json_url
		}],
		"session": session
	}
	r = requests.post(url, json=body, verify=False)
	json_resp = json.loads(r.text)
	print ('--> Saving changes for ADOM %s' % cADOM)
	print ('<-- Hcode: %d Jmesg: %s' % (r.status_code, json_resp['result'][0]['status']['message']))
	print

def workspace_unlock(uADOM):
	json_url = "pm/config/adom/" + uADOM + "/_workspace/unlock"
	body = {
		"id": 1,
		"method": "exec",
		"params": [{
			"url": json_url
		}],
		"session": session
	}
	r = requests.post(url, json=body, verify=False)
	json_resp = json.loads(r.text)
	print ('--> Unlocking ADOM %s' % uADOM)
	print ('<-- Hcode: %d Jmesg: %s' % (r.status_code, json_resp['result'][0]['status']['message']))
	print

def status_taskid():
	global state
	json_url = "/task/task/" + str(taskID)
	body = {
		"id": 1,
		"method": "get",
		"params": [{
			"url": json_url
		}],
		"session": session
	}
	r = requests.post(url, json=body, verify=False)
	json_resp = json.loads(r.text)
	print ('<-- Hcode: %d Jmesg: %s' % (r.status_code, json_resp['result'][0]['status']['message']))
	print
	#print json_resp['result']['data']['state']
	state = json_resp['result'][0]['data']['state']
	totalPercent = json_resp['result'][0]['data']['tot_percent']
	if state == 0:
		print ('    Current task state (%d): pending' % state)
	if state == 1:
		print ('    Current task state (%d): running' % state)
	if state == 2:
		print ('    Current task state (%d): cancelling' % state)
	if state == 3:
		print ('    Current task state (%d): cancelled' % state)
	if state == 4:
		print ('    Current task state (%d): done' % state)
	if state == 5:
		print ('    Current task state (%d): error' % state)
	if state == 6:
		print ('    Current task state (%d): aborting' % state)
	if state == 7:
		print ('    Current task state (%d): aborted' % state)
	if state == 8:
		print ('    Current task state (%d): warning' % state)
	if state == 9:
		print ('    Current task state (%d): to_continue' % state)
	if state == 10:
		print ('    Current task state (%d): unknown' % state)
	if json_resp['result'][0]['status']['message'] == 'OK':
		print ('    Current task percentage: (%d)' % totalPercent)
		print

def poll_taskid ():
	global state
	state = 0
	while state not in [3,4,5,7]:
		print ('--> Polling task: %s' % taskID)
		time.sleep( 3 )
		status_taskid()
	if state == 4:
		print ('--> Task %s is done!' % taskID)
		print
	else:
		print ('--> Task %s is DIRTY, check FMG task manager for details!' % taskID)
		print ('    Adding this ADOM to the error log %s !' % ERRORlog.name)
		ERRORlog.write("%s %s %s\n" % (fmgADOM, taskID, state))
		print

def create_adomrev():
	json_url = "dvmdb/adom/" + fmgADOM + "/revision"
	body = {
	    "id": 1,
	    "method": "add",
	    "params": [{
	        "url": json_url,
	        "data": {
	            "locked": 0,
	            "desc": "Created via JSON API",
	            "name": "Post ADOM DB upgrade",
	            "created_by": hostADMIN
	        }
	    }],
	    "session": session
	}
	r = requests.post(url, json=body, verify=False)
	json_resp = json.loads(r.text)
	print ('--> Creating ADOM revision')
	print ('<-- Hcode: %d Jmesg: %s' % (r.status_code, json_resp['result'][0]['status']['message']))
	print
	time.sleep( 2 )

def find_vdom_exist(mVDOM):
        #global adomRAW
        #global adomLIST
        json_url = "dvmdb/device/" + newfgtDEVname + "/vdom/" + mVDOM
        body = {
                "id": 1,
                "method": "get",
                "params": [{
                       "url": json_url
                }],
                "session": session,
                #"verbose": 1
        }
        r = requests.post(url, json=body, verify=False)
        json_resp = json.loads(r.text)
        #print(json.dumps(json_resp, indent=2))
        #print(json_resp['result'][0]['status']['code'])
        if json_resp['result'][0]['status']['code'] == 0:
                return 1
        else:
                return 0

###

###END OF FUNC

########################################
### Execute funcitons and main loops ###
########################################

url = 'https://' + hostIP + '/jsonrpc'

###
# Logging into FMG and pull ADOM/VDOM info
print
fmg_login(hostADMIN, hostPASSWD, hostIP)
list_filtered_adom_vdom()
fmg_logout(hostIP)

###
## Logging into FAZ
print
print ('-=-' * 20)
print ('Logging into FAZ %s' % newhostIP)
print ('-=-' * 20)
print

url = 'https://' + newhostIP + '/jsonrpc'

faz_login(newhostADMIN, newhostPASSWD, newhostIP)

#"""
#Create new ADOM
for fmgADOM in adomLIST:
	print
	print ('--> In progress creating ADOM  %s ...' % fmgADOM)
	print
	create_adom(fmgADOM)

time.sleep( 0.3 )

## Move VDOM to ADOM
for vdom2adom in vdom2adomLIST:
	splitv2a = []
	splitv2a = vdom2adom.split(':')
	vdom2 = ""
	adom2 = ""
	vdom2 = splitv2a[0]
	adom2 = splitv2a[1]
	if find_vdom_exist(vdom2) == 1 and vdom2 != "root":
		print ('---------------ADOM %s VDOM %s DEVICE %s' % (adom2, vdom2, newfgtDEVname))
		print
		print ('--> In progress moving VDOM %s to ADOM %s ...' % (vdom2, adom2))
		print
		workspace_lock(adom2)
		move_vdom(vdom2, adom2)
		workspace_commit(adom2)
		workspace_unlock(adom2)
	else:
		print ('======***VDOM %s not found in Cluster. Adding  this to error log file error log %s !' % (vdom2, ERRORlog.name))
		ERRORlog.write("VDOM %s not found in Cluster\n" % vdom2)
#"""

faz_logout(hostIP)

print ('-=-' * 20)
stopwatchTOTAL = time.time()-stopwatchSTART
print ('>>>>>> %s ran for %d seconds <<<<<<' % (sys.argv[0], stopwatchTOTAL))
print ('-=-' * 20)

print ('>> Stop logging script output to mainLOG.txt <<')
ERRORlog.close();
transcript.stop()
print ('-=-' * 20)
print ('Completed Script, for Log files please view "mainLOG.txt", "skipADOMlist.txt", and "upgradeERRORlist.txt".\n')
print ('Closing console 5..4..3..2..1.')
time.sleep( 5 )

######
### EOF
######
