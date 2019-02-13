# DefinitelyNotSLIN

# Chapter 0

## Hostname

- `hostnamectl set-hostname <hostname>` to change hostname

## User account and group

- `useradd <name>` to add user
- `passwd <name>` to set password for user
- `groupadd <group name>` to create a new group
- `usermod -aG <groupname> <user>` to add user to group
- `chgrp <groupname> <file>` to change group owner of the file
- 







# Chapter 1

## SSH

### Changing default port number for sshd

1. `netstate -tunap | grep sshd` to check which port the service is running on
2. `vi /etc/ssh/sshd_config` and change the port number
3. Need to change the SELinux policy to allow changing of port number `semanage port –a –t ssh_port_t –p tcp <port number>`
4. `systemctl restart sshd`
5. `ssh –p <port number> <ip address>`

### Secure Copy (SCP) and Secure FTP (SFTP)

`scp <serverIP>:<filename> .` The dot at the back is to represent the current directory

`sftp <username>@<ip address>`

### Network Configuration

##### Network Manager’s Command Line

- `nmcli device` or `nmcli d` to view the network devices

- `nmcli d show <device number>` to view more details about the network interface

- `route` will show the current gateway IP

- `cat /etc/resolv.conf` to view the current DNS Server

- `nmcli connection modify <device number> ipv4.addresses  "<Current IP and subnet mask> <current gateway>" ipv4.dns <current DNS Server>` for Centos release == 7.0

- ``nmcli connection modify <device number> ipv4.addresses <Current IP and subnet mask> ipv4.gateway <current gateway>" ipv4.dns <current DNS Server>` for Centos release > 7.0

- `nmcli connection modify eno16777736 ipv4.method manual` to specify using static IP address for network interface

- `nmcli device disconnect <device number>`

- `nmcli device connect <device number>`

- `/etc/sysconfig/network-scripts/ifcfg-<device number> ` to view the network settings you just made

- DNS setting for the network card in `/etc/sysconfig/network-scripts/ifcfg-<device number> ` will override the settings in global `/etc/resolv.conf`

- Changes made using ip or ifconfig will be lost upon next reboot. Permanent change will have to modify config files `/etc/sysconfig/network-scripts/ifcfg-eno1677736` or `/etc/sysconfig/network`

- Bring up and down a network interface

  ```
  nmcli c down eno1677736
  nmcli c up eno16777736
  ```

### Kernel parameters

- `sysctl -a` to view the list of available kernel parameters and their current values
- `sysctl -w net.ipv4.icmp_echo_ignore_all=1` to set kernel parameters to ignore ping packets
- `vi /etc/sysctl.conf` to set the kernel parameter back and also make changes in the kernel parameters persistent across reboots
- `sysctl -p` to load the settings from `/etc/systctl.conf`

### Prevent root login

- as Root, `visudo` and add `student ALL=ALL` to the end of the file. This will allow user student to run the `sudo` command
- Edit `/etc/passwd` to ` root:x:0:0:root:/root:/sbin/nologin` to change to non-interactive shell

### Anonymous access to vsftpd service

- `systemctl is-enabled vsftpd` to check if the service will be automatically started on bootup
- `systemctl enable vsftpd` to set the service to be automatically started on every bootup
- `systemctl start vsftpd` to start the service
- `vi /etc/vsftpd/vsftpd.conf` and edit `anonymous_enable=YES` to allow anonymous access

### Chrooting vsftpd users to their home directories

- ` setsebool -P ftp_home_dir on` to configure SELinux to allow users to access their home directories
- Edit `/etc/vsftpd/vsftpd.conf` and edit `chroot_list_enable=YES`,`chroot_list_file=/etc/vsftpd/chroot_list` and add `allow_writeable_chroot=YES`, `passwd_chroot_enable=YES`
- create the file `/etc/vsftpd/chroot_list` and add in the users to chroot

### xinetd

- `systemctl start xinetd`
- `vi /etc/xinetd.d/<service name>` and edit `disable=no` to enable tftp

### SELinux

- `getenforce` to check which SELinux mode the system is in
- `setenforce 0` to set to Permissive mode
- `setenforce 1` to set to Enforcing mode
- `getsebool -a | less` to view the SELinux booleans
- edit `/etc/selinux/config` to set the SELinux mode upon bootup
- `ls -lZ <directory>` to view SELinux file contexts of the directory
- `chcon -t <reference filename> <file to change> ` to change file context
- `restorecon <filename>` to reset back the correct file context of the file
- `chcon -t public_content_rw_ <filename>`  to change the file context to be publicly writeable
- `setsebool –P ftpd_anon_write on` to set SELinux boolean to allow anonymous FTP write. The `-P` options is to make the modification persist across reboot
- SELinux violations are logged to `/var/log/audit/audit.log`

### SED

- `sed s/<word to change>/<change with>/ /<filename>` to change the first occurrence
- `sed s/<word to change>/<change with>/g /<filename>` to change the all occurrences
- sed only print out the modified content, does not change the file content.
- use `-i` option to apply modification to the file
- need to escape special characters with `\`
- Chpt 1, page 36

### AWK

- `awk -F “\t” ‘$3 ~/A/ {print $1, $2, $3}’ <file> | sort` to print the first 3 columns if the third column contains the letter “A” and sort alphabetically.
- `-F` option is to specify the column separator



# Chpt 2

`chmod g+s` will set the group ID of the directory. All new files and subdirectories created within the current directory inherit the group ID of the directory, rather than the primary group ID of the user who created the file.

## Apache

- `yum install httpd`
- `systemctl start httpd`
- `systemctl disable/enable httpd`

## Apache Configuration

- Main config file is located at `/etc/httpd/conf/httpd.conf`

- manual can be installed using `yum install httpd-manual` and browse to `http://localhost/manual`

- Log files are found at `/var/log/httpd/access_log` and `/var/log/httpd/error_log`

- If the directory does not contain the file specified in DirectoryIndex in the main config file, then a listing of files in the directory will be displayed

- Directory listing can be disabled by  either appending the following to the end of the main config file `/etc/httpd/conf/httpd.conf` or creating a new file `/etc/httpd/httpd.conf/books.conf`

  ```
  <Directory /var/www/html/books>
  
  	Options -Indexes
  
  </Directory>
  ```

- Always remember to reload or restart the htttpd service after changing the config file

- ```
  /etc/httpd/conf/httpd.conf
  Global Section : configuration to the web server (including virtual servers) as a whole
  Main Section : configuration to the main server
  Virtual Servers : configuration for specific virtual server
   /etc/httpd/conf.d/*.conf
  Normally holds virtual server config files
  ```

  ServerRoot specifies the directory where config files are stored

- DocumentRoot specified the directory where web pages are stored

- DirectoryIndex is the default documents to search for is no page is specified in the URL

- Apache Modules (Page 12 of Chpt 2)

- 4 Types of containers (Page 14)

  - Directory
  - Location
  - Files
  - Virtual Hosts

### Access Control

- Specify in the main config file or the individual config file.

  ```
  <Directory /var/www/html/books>
      Options –Indexes
      Require all denied
      Require ip your_client_ip  your_server_ip
  </Directory>
  ```

### SSL

- `yum install mod_ssl`
- Default pair of private key and certificate will be generated `Private key : /etc/pki/tls/private/localhost.key` and `Certificate :  /etc/pki/tls/certs/localhost.crt`
- Configuration file can be found under `/etc/httpd/conf.d/ssl.conf`

### Name Based Virtual Host

- Resolve hostname to IP by adding to `/etc/hosts`

  - `server_ip	www.flowers.com`

- Create a directory `/var/www/flowers

- Create `index.html`

- Create a new file `flowers.conf` under `/etc/httpd/conf.d/`

  ```
  <VirtualHost your_server_ip:80>
      ServerName www.flowers.com
      DocumentRoot /var/www/flowers
      ErrorLog /var/log/httpd/flowers-error_log
      CustomLog /var/log/httpd/flowers-access_log combined
  </VirtualHost>
  
  ```

### CGI SCRIPTS

- Install Python3.6 (page 4)

- `mkdir /var/www/fruits-cgi-bin` to store the CGI scripts

- Set SELinux file context for the directory

  - `chcon -t httpd_sys_script_exec_t  /var/www/fruits-cgi-bin`

- create python script in the directory

  ```
  #!/usr/bin/env python3
  print("Content-type: text/html\n\n")
  print("Hello World")
  ```

- make the file world-executable `chmod +x`

- Add ScriptAlias line to the VirtualHost container for `www.fruits.com`

  ```
  <VirtualHost your_server_ip:80>
      ServerName www.fruits.com
      DocumentRoot /var/www/fruits
      ErrorLog /var/log/httpd/fruits-error_log
      CustomLog /var/log/httpd/fruits-access_log combined
      ScriptAlias /cgi-bin/ /var/www/fruits-cgi-bin/
  </VirtualHost>
  ```

- Browse to `http://www.fruits.com/cgi-bin/hello.py`

### User Authentication (Web site access control)

- Use htpasswd command to create apache users ( the -c option is used when adding first user)

  - `htpasswd -cm /etc/httpd/conf/flowers-users bob`
  - `htpasswd -m /etc/httpd/conf/flowers-users bob`

- Create the file `/var/www/flowers/.htaccess` in the DocumentRoot

  ```
  AuthType basic
  AuthName "Flowers Website"
  AuthUserFile /etc/httpd/conf/flowers-users
  require user bob
  ```

- Edit the `/etc/httpd/conf.d/flowers.conf` and add

  ```
  <Directory /var/www/flowers>
      AllowOverride AuthConfig
  </Directory>
  ```

- Changes make to `.htaccess` do not require the server to be restarted.

## Curl

- `curl -u username:password <website>`

## Squid

- `yum install squid`
- Edit `/etc/squid/squid.conf`
  - Create Access Control List (acl) for own subnet `acl my_net src 192.168.136.0/24`
  - Create the http_access `http_access allow my_net`
  - Set the parameter visible_hostname to our hostname `visible_hostname server.example.com`
- Squid run on port 3128 by default
- Check for error messages `/var/log/messages`
- View Squid access log `tail /var/log/squid/access.log`
- Block website `/etc/squid/squid.conf`
  - `acl bad_sites dstdomain .yahoo.com`
  - `http_access deny bad_sites`

## Tomcat Server

- `yum install tomcat`
- `tomcat version`
- Tomcat web pages are stored in `/var/lib/tomcat/webapps`
- Make root dir `mkdir ROOT`
- Create default page `/var/lib/tomcat/webapps/ROOT/index.jsp`
- Default server config file `/etc/tomcat/server.xml`
- To shutdown the server
  - `telnet 127.0.0.1 8005` and type `SHUTDOWN`
- To deploy a war file, copy the file to `/var/lib/tomcat/webapps`

## Nginx Web Server

- `yum install gcc`
- `yum install pcre pcre-devel`
- `yum install zlib zlib-devel`
- Download latest stable version of nginx from `www.nginx.org`
  - move the file to `/usr/src`
  - Extract the file `tar -xvf nginx-1.7.7.tar.gz`
  - `cd nginx-1.7.7`
  - `./configure`
  - `make`
  - `make install`
- The nginx config file is stored in `/usr/local/nginx/conf/nginx.conf`
- Start nginx using `/usr/local/nginx/sbin/nginx`
- Check nginx is running `netstat -tunap | grep nginx`
- Make the worker process run as user `nginx`
  - `useradd -s /sbin/nologin -d /usr/local/nginx nginx`
  - Edit the config file `user nginx nginx; worker_processes 2;`
  - restart nginx `/usr/local/nginx/sbin/nginx –s stop` and `/usr/local/nginx/sbin/nginx`

### Configuring nginx as a service

- Create a text file `/usr/lib/systemd/system/nginx.service`

  ```
  [Unit]
  Description=The NGINX HTTP server
  After=syslog.target network.target remote-fs.target nss-lookup.target
  
  [Service]
  Type=forking
  PIDFile=/usr/local/nginx/logs/nginx.pid
  ExecStartPre=/usr/local/nginx/sbin/nginx -t
  ExecStart=/usr/local/nginx/sbin/nginx
  ExecReload=/bin/kill -s HUP $MAINPID
  ExecStop=/bin/kill -s QUIT $MAINPID
  PrivateTmp=true
  
  [Install]
  WantedBy=multi-user.target
  
  ```

- Try to start and stop nginx

  ```
  systemctl status nginx
  systemctl stop nginx
  systemctl start nginx
  ```

# Chapter 3 File Systems and Network File Service (NFS)

## Setting up XFS filesystem

- `fdisk -l` to view all known disks
- `fdisk /dev/sda`
- `m` to view available options
- `p` to list existing partitions on the hard disk
- `n` to create new partition
  - `p` to create primary partition
  - `+100M` to create a 100MB partition
  - `p` to list partition info
  - `w` to write changes to disk and exit fdisk

## Format partition with XFS filesystem

- Format XFS filesystem`mkfs -t xfs /dev/sda3` sda3 is the newly created partition

- Create mount point `mkdir /filesys1`

- Find UUID of the new filesystem `blkid /dev/sda3`

- Edit `/etc/fstab` so filesystem will automatically mount on bootup

  ```
  UUID=”a11f1b0-2f5b-49e8-ba43-13de7990d3b9”	/filesys1	xfs defaults 0 0
  ```

- `mount /filesys1`

- `df` to view current storage usage

## Exporting directories on NFS server

- `yum list nfs-utils` to check if nfs packages is installed

- `systemctl status nfs-server` 

- Create a directory and make it world writeable

  - `mkdir -p /exports/data`
  - `chmod 777 /exports/data`

- Edit `/etc/exports/`

  - `/exports/data <clientIP>(ro,sync)`

- `exportfs -r` to re-export all the entries in `/etc/exports`

- `exportfs -v` to check the exports

- NFSd run on TCP port 2049

- rpcbind runs on TCP and UDP port 111, also uses loopback interface

- ```
  The following 2 lines in /etc/exports have different meanings
  /data    192.168.1.0/24(rw)
  /data    192.168.1.0/24 (rw)
  The first config line means /data will be exported to clients in the subnet 192.168.1.0/24 with read-write options
  The second config line means /data will be exported to clients in the subnet 192.168.1.0/24 with default options (read-only) and exported to all other systems with read-write option
  ```

- If userA on server with UID 505 have rwx permission. Then userB with UID 505 on client will also have rwx permission

## Mounting exported directories on NFS Client

- `yum list nfs-utils`
- Create mount point `mkdir -p /mount/data`
- `mount serverIP:/exports/data /mount/data -o rw`
- unmount using `umount /mount/data`
- Files created by root over the NFS share are owned by nfsnobody. Directories are exported with the root_squash option, which will map user root to user nfsnobody when accessing the exported directory
- Mount on bootup using `/etc/fstab`
  - `serverIP:/exports/data      /mount/data    nfs   defaults  0 0`
  - `mount /mount/data`
- The root of all exported file systems on the NFS server is known as the pseudo-root
- If the client mounts the pseudo-root, all exported file systems are mounted on the client

# Network and Service Access Controls (Firewalld and TCP wrappers)

## Zones and predefined services of firewalld

- Firewalld GUI

- `firewall-config`

- `firewall-cmd --get-zones`

- `firewall-cmd --list-all-zones`

- `firewall-cmd --get-default-zone`

- `firewall-cmd –list-services`

- `firewall-cmd --reload`

- Permanent configuration will be saved to a file `/etc/firewalld/zones/public.xml` and applied the next time the firewall is started

- Remove service in permanent `firewall-cmd --permanent --zone=public --remove-service=telnet`

- Predefined configurations of each zone are specified in `/usr/lib/firewalld/zones`. NOTE: Do not modified them

- User-modified zone configuration are stored in `/etc/firewalld/zones`

- Predefined services are specified in `/usr/lib/firewalld/services`

- User-created or modified services will be listed in `/etc/firewalld/services`

- Adding port using command line

  ```
  firewall-cmd –-zone=public –-add-port=8080/tcp
  firewall-cmd --permanent --zone=public       ---add-port=8091-8095/tcp
  ```

- `man firewalld.zone / firewalld.service / firewalld.icmptype`

## Rich Rules

- Rules are stored in zone config files `/etc/firewalld/zones`
- First rule that matches the packet will be applied
- Parsing of rules
  1. Log rules
  2. Drop rules
  3. Accept rules
- Only you to specify destination, source, ports and actions, loggings and etc.
- `firewall-cmd --permanent --zone=public –add-rich-rule='rule family=ipv4 service name=ftp source address=192.168.136.0/24 accept'`
- Logged packet are found at `/var/log/messages`
- `man firewalld.richlanguage`

## Network Address Translation (NAT)

- Enable IP Masquerade zone which means all outgoing packet will be modified to have the same source IP as the client network interface card
- On the Port forwarding port, forward all incoming packets going to Port 80 on the client to Port 80 on the server.
- Verify that the source address changed by `cat /var/log/httpd/access_log` on the server

## Using direct interface (page 18 of chpt 4)

- To create rules to control the outgoing traffic.

- Rules with priority 1 will be matched first.

- List all current rules for direct interface `firewall-cmd --direct --get-all-rules`

- To block all outgoing traffic `firewall-cmd --direct --add-rule ipv4 filter OUTPUT 99 -j DROP`

- Allow outgoing traffic `firewall-cmd --direct --add-rule ipv4 filter OUTPUT 2 -p tcp --dport 80 -j ACCEPT` and`firewall-cmd --direct --add-rule ipv4 filter OUTPUT 3 -p udp    --dport 53 -j ACCEPT`

- Allow outgoing packets that belong to a connection that is already established `firewall-cmd --direct --add-rule ipv4 filter OUTPUT 1 -m state --state ESTABLISHED,RELATED -j ACCEPT`

- `firwall-cmd --direct --get-all-rules` will list all rules through direct interface, while `firewall-cmd -list-all` will not list

- To make the rules permanent, need the `--permanent` option.

- Permanent direct interface rules are stored in `/etc/firewalld/direct.xml`

- To remove direct interface rules

  - ```
    firewall-cmd --direct --remove-rule ipv4 filter OUTPUT 1       –m state --state ESTABLISHED,RELATED -j ACCEPT
    firewall-cmd --direct --remove-rule ipv4 filter OUTPUT 2 -p tcp    --dport 80 -j ACCEPT
    firewall-cmd --direct --remove-rule ipv4 filter OUTPUT 3 -p udp    --dport 53 -j ACCEPT
    firewall-cmd --direct --remove-rule ipv4 filter OUTPUT 99      -j DROP
    ```

  - Using Firewall GUI

## TCP Wrappers

- Many network services are linked to libwrap.so library. Access to these network services can be controlled by `/etc/hosts.allow` and `/etc/hosts.deny`

- Find the full path to the vsftpd program `which vsftfpd`

- Run `ldd /usr/sbin/vsftpd | grep ‘libwrap.so’`. If libwrap.so is among the list of libraries, then the service can be controlled using `/etc/hosts.deny` and `/etc/hosts.allow`

- `ldd` may not detect the libwrap.so library. Need to use `strings usr/sbin/vsftpd | grep hosts`_access

- ```
  sshd: clientIP
  vsftpd: ALL EXCEPT clientIP
  ALL : ALL
  ```

  Rules in `/etc/hosts.allow` are applied first

- If no match in either `/etc/hosts.allow` or `/etc/hosts.deny`, then allow connection

# Chapter 5 Samba

## Creating Samba Share

1. yum install samba

2. yum install samba-client

3. systemctl start smb

4. systemctl enable smb

5. Create share directory, change group owner and give full permission to group owner

   - mkdir /samba_share
   - chgrp chipmunk /samba_share
   - chmod 775 /samba_share

6. Edit /etc/samba/smb.conf

   - ```
     [myshare]  
        comment = My Samba Share for chipmunks
        path = /samba_share
        guest ok = yes
        browsable = no
     ```

7. Add samba user (smbpasswd -a alvin)

8. Adjust firewall to allow connection

9. Edit /etc/hosts

   - ```
     127.0.0.1 server.example.com
     ```

## Browsing Samba Share from Client

1. yum install samba-client

2. `smblient -L <serverIP>`to list the samba shares on the server

3. `smbclient //<serverIP>/myshare`

   - ```
     •	Type 'lcd /tmp' to change your current folder to /tmp at the client.
     •	Type '!pwd' to check your current folder at the client.
     •	Type 'pwd' to check your current folder at the server.
     •	Type “get sambafile1” to download the shared file.
     •	Type “quit” to exit from the Samba client.
     
     ```

4. `smbclient //<serverIP> /myshare –U alvin`

## Error

1. `chcon –Rt samba_share_t /samba_share`

## Uploading Files to Samba Share

1. Allow user to modify file (/etc/samba/smb.conf) (use + for group name)

   - ```
     [myshare]
     path = /samba_share
     browsable = no
     write list = alvin
     invalid users = hacker
     valid users = alvin
     hosts allow = .example.com 192.168.0.
     hosts deny = ALL
     
     
     ```

## Mounting Samba Share Automatically upon bootup

1. yum install cifs-utils

2. mkdir /sambadata (mount point)

3. Edit /etc/fstab `//serverIP/myshare	/sambadata	cifs	credentials=/etc/sambauser	0	0`

4. vi /etc/sambauser

   - ```
     user=alvin
     pass=<alvinpassword>
     ```

5. chmod 600 /etc/sambauser

6. mount /sambadata

7. ls -l /sambadata

8. umount /sambadata

## Accessing Home Directories through Samba

1. vi /etc/samba/smb.conf

   - ```
     [homes]
        comment = Home Directories
        valid users = %S, %D%w%S
        browseable = No
        read only = No
        inherit acls = Yes
     
     ```

2. `setsebool -P samba_enable_home_dirs on`

# Chapter 6 Securing Data

## Random Number Generation

1. `hexdump /dev/random` (mouse and keyboard)
2. `hexdump /dev/urandom` (no interaction) (Not truly random)
3. `openssl rand -base64 8` generate 8 random bytes in base64 encoding to get printable characters
4. `openssl rand 8` 8 random bytes not necessarily printable
5. `md5sum <file>`
6. `<sha1sum <file>`
7. `<sha256sum <file>`

## Symmetric Encryption

1. `openssl des3 -base64 -in /tmp/<input file> -out /tmp/encrypted`
2. `openssl des3 -d -base64 -in /tmp/encrypted` to decrypt the file

## Asymmetric Encryption

1. `gpg --gen-key`

2. `gpg --list-keys`

3. `gpg --list-secret-keys`

4. `gpg -a --export AliceLim > /tmp/alice_pubkey` (As user Alice export public key to a file)

5. `gpg --import /tmp/alice_pubkey` (As user Bob import Alice public key)

6. `gpg –-recipient AliceLim -a -o /tmp/ciphertext -e /tmp/plaintext` (Encrypt file using Alice Public Key)

7. `gpg -o alicetext -a -d /tmp/ciphertext` (As Alice, decrypt the file)

8. `gpg --recipient BobTan –a --sign –o /tmp/signcipher –e alice_reply` (As user Alice, encrypt and sign)

9. `gpg -o bobtext -a -d /tmp/signcipher` (As User Bob, verify and decrypt signcipher)

10. ```
    To generate public/private keys
    		gpg --gen-key
    To list keys
    		gpg --list-keys
    		gpg --list-secret-keys
    To export a public key to a file
    		gpg -a --export > alice.publickey
    To import a public key to Public Keyring
    		gpg --import < /tmp/alice.publickey
    
    
    To create a detached signature
    Encrypted hash will be stored with extension “.sig” or “.asc”
    		gpg --detach-sign –a filename
    To verify the received hash with the original file 
    Original file must be filename and in the same directory as hash
    		gpg --verify filename.sig
    
    ```

11. 

## Creating Self-Signed certificate for Apache Web Server

1. cd /etc/pki/tls/certs

2. `make httpd.key` to generate private key for Apache Web Server

3. `ls -l httpd.key` ensure the file is only readable by root

4. `make httpd.crt` to generate self-signed certificate

5. `mv /etc/pki/tls/certs/httpd.key /etc/pki/tls/private`

6. yum install mod_ssl

7. vi /etc/httpd/conf.d/ssl.conf

   - ```
     SSLCertificateFile /etc/pki/tls/certs/httpd.crt 
     SSLCertificateKeyFile /etc/pki/tls/private/httpd.key
     ```

8. systemctl restart httpd

### No passphrase key

1. cd /etc/pki/tls/private

2. `openssl rsa httpd.key -out httpd_nopass.key`

3. vi /etc/httpd/conf.d/ssl.conf

   - ```
     SSLCertificateFile /etc/pki/tls/certs/httpd.crt 
     SSLCertificateKeyFile /etc/pki/tls/private/httpd_nopass.key
     
     ```

## Setting up Private Certificate Authority

1. mkdir /etc/pki/CA/private

2. mkdir /etc/pki/CA/certs

3. chmod 700 /etc/pki/CA/private

4. vi /etc/pki/tls/openssl.cnf

   - ```
     dir = /etc/pki/CA
     certificate = $dir/certs/slin-ca.crt
     private_key = $dir/private/slin-ca.key
     
     ```

5. touch /etc/pki/CA/index.txt

6. echo 01 > /etc/pki/CA/serial

7. cd /etc/pki/CA

8. `openssl genrsa -des3 2048 > private/slin-ca.key` (Generate a 2048 bitprivate key for private CA)

9. chmod 600 /etc/pki/CA/private/slin-ca.key

10. `openssl req -new -x509 -days 365 -key private/slin-ca.key > certs/slin-ca.crt` to generate a self-signed certificate for private CA

11. mkdir /var/www/html/pub

12. cp /etc/pki/CA/certs/slin-ca.crt /var/www/html/pub

13. http://localhost/pub/slin-ca.crt

## Signing Apache Web Server certificate using Private CA

1. cd /etc/pki/tls

2. `openssl genrsa 1024 > private/httpd2.key` (new private key for web server that does not require passphrase)

3. chmod 600 private.httpd2.key

4. `openssl req -new -key private/httpd2.key -out certs/httpd2.csr` to generate a certificate signing request (csr)

5. `openssl ca -in certs/httpd2.csr -out certs/httpd2.crt` to use CA private key to sign the CSR

6. Configure Apache to use the new certificate and private key. `vi /etc/httpd/conf.d/ssl.conf`

   - ```
     SSLCertificateFile /etc/pki/tls/certs/httpd2.crt 
     SSLCertificateKeyFile /etc/pki/tls/private/httpd2.key
     
     ```

7. systemctl restart httpd

8. import slin-ca.crt into the Trusted Authorities

9. Access the website using proper domain name

## SSH with Key-Based Authentication

1. ssh-keygen -t rsa
2. `ls /home/student/.ssh` to view the private and public keys
3. As user student, ssh to server and create the directory /home/student/.ssh
4. chmod 700 .ssh
5. `scp /home/student/.ssh/id_rsa.pub <serverIP>:/home/student/.ssh/authorized_keys`
6. On server, as user student, chmod 600 authorized_keys
7. On Client student, ssh to server

## SSH Agent

1. `ssh-add`  as student
2. `ssh <serverIP>`, no passphrase will be asked

## Virtual Network Computing through SSH Tunnel

1. On server, yum install vnc-server
2. `cp /lib/systemd/system/vncserver@.service /etc/systemd/system/vncserver@.service` to make a copy of the vncserver config file
3. vi /etc/systemd/system/vnc@.service
   - `ExecStart=/sbin/runuser -l <USER> -c "/usr/bin/vncserver %i" PIDFile=/home/<*USER>*/.vnc/%H%i.pid`
4. As user student, set a vnc password `vncpasswd`
5. systemctl daemon-reload
6. systemctl start vncserver@:1
7. netstat -tunap to look for listening ports of Xvnc (Usually is port 5901)
8. Adjust firewall to allow connection to the VNC Server.
9. As client, yum install vnc
10. As client student, `vncviewer <serverIP:1>`

## VNC Through SSH tunnel

1. `vncviewer –via <serverIP> localhost:1`

## SSH Tunnel to do Local Port Fowarding

1. At Server, Adjust firewall to block HTTP traffic
2. On client, `ssh -L 8000:localhost:80 <serverIP>`, to open local port 8000 on client and establish SSH connection to the server. Any data sent to local port 8000 will be forwarded through the SSH tunnel to the remote port 80 on the server.
3. On client, browse to `http://localhost:8000`, you will see the server’s webpage

## Block Local Port Forwarding

1. vi /etc/ssh/sshd_config `AllowTCPForwarding no`
2. systemctl restart sshd

# Chapter 7 System Monitoring

## Network monitoring

1. netstat -tunpl
2. nmap
3. tcpdump -i eno16777736
4. tcpdump icmp -i eno16777736
5. tcpdump tcp -i eno16777736
6. wireshark

## System Logging

1. All authpriv messages are logged to /var/log/secure

2. vi /etc/rsyslog.conf (authpriv with priority warning and higher will also be logged to /var/log/securewarning)

   - ```
     authpriv.*			/var/log/secure
     authpriv.warning	/var/log/securewarning
     
     ```

3. systemctl restart rsyslog

4. Creating logged entry

   - ```
     logger -p authpriv.warning "This is a test warning"
     logger -p authpriv.alert "This is a test alert"
     logger -p authpriv.info "This is a test info msg"
     
     ```

![priority](F:\Year 2 Sem 2\SLIN\Exam\priority.JPG)



## Remote Logging

1. On server, vi /etc/rsyslog.conf (remove the comment)

   - ```
     $ModLoad imudp
     $UDPServerRun 514
     
     ```

2. systemctl restart rsyslog

3. Adjust firewall to allow incoming connections to rsyslog port

4. On Client, vi /etc/rsyslog.conf

   - ```
     authpriv.warning	@<serverIP>
     kern.*            	@@192.168.0.4:8900
     *.info;mail.none    @192.168.0.5 #All info and up but mail are logged
     
     
     ```

5. systemctl restart rsyslog

```
Key log files at /var/log/

messages		default location for messages
secure		login messages
maillog		mail messages
boot.log		messages at startup and shutdown
httpd/*		Apache webserver messages
cups/*		print messages
samba/*		Samba server messages

```



## Resolving IP addresses in Apache Logs

1. On server, ls /var/log/httpd
2. `logresolve < /var/log/httpd/<site_access_log> >/tmp/apachelog`

## Webalizer for Apache

1. yum install GeoIP
2. yum install webalizer
3. cat /etc/webalizer.conf
4. `webalizer` (run the program)
5. ls /var/www/usage
6. browse to `http://localhost/usage`

## Swatchdog for real-time Log Monitoring

1. ```
   yum install perl-ExtUtils-MakeMaker
   yum install perl-Time-HiRes
   yum install perl-Date-Calc
   yum install perl-Date-Manip
   yum install perl-TimeDate
   
   ```

2. yum install perl-File-Tail

3. download swatchdog from `sourceforge.net/projects/swatch/files/swatchdog` or blackboard

4. tar -xvf swatchdog-3.2.4.tar.gz

5. cd swatchdog-3.2.4

6. ```
   perl Makefile.PL
   make
   make test
   make install
   make realclean
   
   ```

7. vi /etc/swatchdog.conf

   - ```
     watchfor /ssh/
     	echo bold
     
     ```

8. Run Swatchdog using `swatchdog -c /etc/swatchdog.conf -t /var/log/secure`

9. Email when alerted

   - ```
     watchfor /ssh.*(F|f)ailed/
         echo bold red
         mail addresses=root,subject=”SSH failed connection”
     
     ```

10. Brute force

    - ```
      watchfor /ssh.*[F|f]ailed/
          echo bold red
          mail addresses=root,subject=”Possible SSH Brute Force Attack”
          threshold track_by=$1, type=threshold, count=6, seconds=20
      
      ```

11. Background swatchdog `nohup swatchdog –c /etc/swatchdog.conf –t /var/log/secure 2>&1  > /dev/null &`

## Finding Files based on specific criteria

1. ```
   -rw-r--r--    a     (chmod 644 a)
   -rw-rw-r--    b     (chmod 664 b)
   -rw-rw-rw-    c     (chmod 666 c)
   -rw-r--rw-    d     (chmod 646 d)
   -rwxrwxrw-    e     (chmod 776 e)
   
   find . –perm 644	(Ans : a)
   find . –perm -644	(Ans : a,b,c,d,e)
   find . –perm 022	(Ans : none)
   find . –perm -022	(Ans : c,e)
   find . –perm /022	(Ans : b,c,d,e)
   
   
   ```

2. `find / -nouser`

3. `find / -mtime -1` modified in the last day

4. `find / -mmin -60` modified in the last hour

## Listing open files (lsof)

1. `lsof +D /tmp` list opened files in the /tmp directory

2. `lsof -n -i`list files opened by network-related processes

3. `lsof -n -i 4` list files opened by ipv4 network related processes

4. ```
   HTTPD_PID=`ps -ef | grep httpd | head -1 | awk '{print $2}'`lsof –p $HTTPD_PID
   
   ```

## AIDE (Advanced Intrusion Detection Environment)

1. yum install aide
2. cat /etc/aide.conf
3. `aide –-init -–config /etc/aide.conf` to create initial baseline database
4. `mv /var/lib/aide/aide.db.new.gz /var/lib/aide/aide.db.gz` rename the database to use it
5. `aide –-check –-config /etc/aide.conf` to run a check and compare with the baseline database

## Getting usage statistics

1. `df -T` or `df -Th` to view disk space utilization
2. `du -sh /home/*` to see how big each user’s home directory is
3. `iostat`, `iostat -N` or `iostat -m` to  view CPU and disk utilization 
   - -N to view logical volume disk utilization
   - -m to view in megabytes instead of kilobytes
4. `free -m`, `vmstat` or `vmstat -s` to see virtual memory statistics
5. `sar` to view summary of CPU activity
   1. `sar -f /var/log/sa/<filename> | less` to view available reports and see a report of CPU activity of a previous dat
   2. `sar -n DEV` to view network statistics on each network interface

## Settings process limits

1. vi /etc/security/limits.conf `alvin	hard	maxlogins	1`, to limit user Alvin to only 1 login

2. `ps –u alvin` to view how many processes started by the user

3. vi /etc/security/limits.conf (restrict user alvin to 10 soft and 20 hard processes)

   - ```
     alvin	soft	nproc		10
     alvin	hard	nproc		20
     @chipmunks hard nproc		20
     
     ```

4. `ulimit -a` to view the max user processes the user can run

5. `ulimit -u 16` to change the ulimit to 16, but not more than 20

## Process Accounting

1. yum install psacct
2. systemctl start psacct
3. `ac -dp` to check the daily connect times for each user
4. `lastcomm alvin` to view information about the recent commands run by User Alvin

# Domain Name System (DNS)

## Setting up basic caching only DNS Server with bind

1. yum install bind bind-utils

2. `ls -l /etc/named.conf` ensure the group owner is “named”

3. `cat /etc/resolv.conf` to find the original local DNS Server

4. ```
   listen-on port 53 { any; };
   allow-query { localhost; 192.168.137.0/24; };
   forwarders { 192.168.137.2; };
   
   ```

5. The above will allow client subnet to make queries.

6. ```
   dnssec-enable no;
   dnssec-validation	  no;
   
   ```

7. systemctl start named

8. cat /etc/log/messages to check if there are any errors with named service

9. `vi /etc/resolv.conf`, comment all lines and add `nameserver <serverIP>`

10. To make permanent update to /etc/resolv.conf, `vi /etc/NetworkManager/NetworkManager.conf`

    - ```
      [main]
      plugins=ifcfg-rh
      dns=none
      
      ```

      

11. systemctl restart NetworkManager

## Setting up Forward Lookup Zone

1. Make your DNS Server responsible for the zone “example.com”

2. ```
   vi /etc/named.conf
   
   zone "." IN {
       type hint;
       file "named.ca";
   };
   
   zone "example.com" IN {
       type master;
       file "example.com.zone";
   };
   
   ```

3. Zone files are stored in /var/named

4. vi /var/named/example.com.zone (the server below refers to the server hostname)

   - ```
     $TTL 86400
     example.com.       IN SOA server root (
                               42   ; serial
                               3H   ; refresh
                               15M  ; retry
                               1W   ; expiry
                               1D ) ; minimum
     example.com.     	IN NS server
     example.com.		IN MX 10 server
     
     server			IN A 172.16.10.13
     client			IN A 172.16.10.33
     testpc          IN A 172.16.199
     
     ```

5. `chgrp named /var/named/example.com.zone`

6. systemctl restart named

## Setting up Reverse Lookup Zone

1. ```
   vi /etc/named.conf
   
   zone "." IN {
       type hint;
       file "named.ca";
   };
   
   zone "example.com" IN {
       type master;
       file "example.com.zone";
   };
   
   zone "10.16.172.in-addr.arpa" IN {
    type master;
    file "172.16.10.zone";
   };
   
   ```

2. Create a new reverse zone file

3. vi /var/named/172.16.10.zone

   - ```
     $TTL	86400
     @	IN SOA server.example.com. root.server.example.com. (
     			42	; serial
     			28800	; refresh
     			14400	; retry
     			3600000	; expiry
     			86400 )	; minimum
     	IN NS	server.example.com.
     
     33	IN PTR	client.example.com.
     13	IN PTR	server.example.com.
     199	IN PTR	testpc.example.com.
     
     ```

4. `chgrp named /var/named/172.16.10.zone`

5. `systemctl restart named`

## Connecting to DNS Server from the client

1. On Client, vi /etc/resolv.conf, comment all lines and add `nameserver <serverIP>`
2. Make persistent in `/etc/NetworkManager/NetworkManager.conf`
3. Check firewall, port 53

## Perform a Zone transfer

1. dig -t axfr example.com

2. On server, restrict zone transfer to specific IP

3. vi /etc/named.conf

   - ```
     allow-query { localhost; 192.168.0.0/16; };
     allow-transfer { 172.16.10.199; };
     
     ```

4. systemctl restart dns

# Chapter 9 E-Mail

## configuring PostFix to listen to external network interfaces

1. systemctl status postfix

2. postfix service starts the master process. `netstat –tunap | grep master`

3. By default, postfix is listening only on the loopback interface 127.0.0.1 on Port 25

4. vi /etc/postfix/main.cf

   - ```
     inet_interfaces = all  
     # and comment out 
     #inet_interfaces = localhost
     
     ```

5. systemctl restart postfix

## Mutt 

1. Mutt is an example of Mail User Agent (MUA)
2. yum install mutt
3. client type `mutt` to try out

## Mail aliases

1. vi /etc/aliases

   - ```
     query: student
     # mail query will be sent to student
     
     ```

## Sending emails between system

1. On server, do a dig to see if the hostname can be resolved to its IP address

2. `cat /var/log/maillog` constantly to check for any error

3. On Client, adjust the firewall rules to allow incoming emails.

   - ```
     port 110 (pop3)
     port 995 (pop3s)
     port 143 (imap)
     port 993 (imaps)
     port 25 (smtp)
     
     ```

4. systemctl restart postfix

5. `mail student@client.example.com`

6. `mailq` to check if the mail has been sent

## Configuring SMTP Server to relay mails for internal network

1. `vi /etc/postfix/main.cf`

   - ```
     mynetworks = 172.16.10.0/24
     # This will relay emails from 172.16.10.0/24 subnet to external networks
     
     ```

2. systemctl restart postfix

## Configuring SMTP Server to receive mails for the local domain

1. `vi /etc/postfix/main.cf`

   - ```
     mydestination = $myhostname, localhost.$mydomain, localhost, example.com
     # adding example.com will accept emails coming for the example.com domain
     
     ```

2. systemctl restart postfix

## Configure Postfix to send mail using Gmail

1. https://www.linode.com/docs/email/postfix/configure-postfix-to-send-mail-using-gmail-and-google-apps-on-debian-or-ubuntu/

# Chapter 10 User Authentication

## Pam_permit to allow access without passwords

1. vi /etc/pam.d/login

   - ```
     auth sufficient	pam_permit.so
     # add to the TOP
     
     ```

## Pam_listfile to control access to vsftpd service

1. `vi /etc/pam.d/vsftpd` and locate the following line

   - ```
     auth required pam_listfile.so item=user sense=deny file=/etc/vsftpd/ftpusers onerr=succeed
     
     ```

2. Add a user to /etc/vsftpd/ftpusers

3. The user can no longer ftp to the server

## Pam_tally to track login attempts

1. man pam_tally2

2. cat /etc/pam.d/login and ensure it includes the file `system-auth`

3. `vi /etc/pam.d/system-auth`

   - ```
     auth required pam_env.so
     auth required pam_tally2.so deny=3 unlock_time=100
     
     account required pam_unix.so
     account required pam_tally2.so
     
     ```

4. `pam_tally2` to view failed attempts

5. `pam_tally2 --user >username> --reset`



## Using pam_time to restrict access to services based on time

1. man pam_time

2. config file is /etc/security/time.conf

3. man time.conf

4. vi /etc/pam.d/vsftpd

   - ```
     auth       required    pam_shells.so
     auth       include     password-auth
     account    required    pam_time.so # add this line to use the pam_time module
     account    include     password-auth
     
     
     ```

5. vi /etc/security/time.conf

   - ```
     vsftpd;*;alvin;!Mo0000-2400
     
     ```

## nsswitch.conf

1. cat /etc/nsswitc.conf

   - ```
     passwd:	files
     shadow:	files
     group:	files
     hosts:	files dns
     
     Currently user accounts, shadow passwords and groups are read from the local files only. So all users and groups who can login to the system are local. Hostnames are resolved by looking at the local file (/etc/hosts) and then by checking the DNS Server.
     
     
     ```

## Allocating admin tasks to normal users with sudo

1. As root, visudo
2. `simon  ALL=/usr/bin/systemctl * httpd` allow simon to start and stop httpd
3. `simon ALL=/usr/bin/systemctl * httpd, /bin/vi /etc/httpd/*` allow simon to vi
4. Logs sudo tasks in`/var/log/secure`
