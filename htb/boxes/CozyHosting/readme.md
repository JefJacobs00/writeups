# CozyHosting (Easy)

![image](https://github.com/JefJacobs00/writeups/assets/43653885/0e4dc31a-ab63-448c-b7bf-6eafc355715d)

## Recon
### Nmap portscan

![image](https://github.com/JefJacobs00/writeups/assets/43653885/3ad04db2-ff2f-46d5-8e71-67a838d5c909)

The box has an open http and ssh service. We see that the http service redirects to "cozyhosting.htb". To access the site we need to add this to the /etc/hosts file with the corresponding ipaddress.

### Webserivce recon

The next step is to search trough the webapplication for vulnerabilities. We can use gobuster to search for available endpoints during the gobuster scan we can also checkout the site itself.

Gobuster finds a login and admin page. 

===============================================================
Gobuster v3.5
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://cozyhosting.htb/
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/wordlists/dirb/common.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.5
[+] Timeout:                 10s
===============================================================
2023/10/11 11:23:44 Starting gobuster in directory enumeration mode
===============================================================
/admin                (Status: 401) [Size: 97]
/error                (Status: 500) [Size: 73]
/index                (Status: 200) [Size: 12706]
/login                (Status: 200) [Size: 4431]
/logout               (Status: 204) [Size: 0]
Progress: 4554 / 4618 (98.61%)
===============================================================
2023/10/11 11:24:04 Finished
===============================================================

When we try to access the admin page we get a 401 (unathorised) and we get redirected to the login page. 


