# SLIN Cheatsheet

## Topic 0 (Linux Basics)

### Check hostname
`hostnamectl`  
`hostnamectl set-hostname <your hostname>`  

### Users
`useradd <username>`  
`passwd <username>`  

### Groups
`groupadd <groupname>`  
`usermod -aG <groupname> <username>` -aG = append to group  
`chgrp <groupname> <filename>` To change group owner of file  

## Topic 1 (Using Cent0S)

### SSH Configurations
`netstat -tunap | grep <service name>` Use netstat to check which port a service is running on  
SSH service file `/etc/ssh/sshd_config`  
`semanage port -a -t ssh_port_t -p tcp 8222` Allow SSH to listen on port 8222  

### SCP and SFTP
`scp <serverIP>:<file> <destination>`
`get <file> <save as>` Using SFTP to download a file

### Network Configuration
`nmcli` Stands for Network Manager's Command Line Interface  
`nmcli device` View network devices  
`nmcli connection modify eno16777736 ipv4.addresses “192.168.137.30/24 192.168.137.2” ipv4.dns 192.168.137.2` Setting a static IP address  
`nmcli connection modify eno16777736 ipv4.method manual` Specify using a IP address  
`nmcli device disconnect/connect eno16777736` Disconnect and connect for changes to take effect  
`/etc/sysconfig/network-scripts/ifcfg-<name of network interface>` Network settings file  

### Kernal Parameters
`sysctl -a` View list of available kernal parameters  
`sysctl -w net.ipv4.icmp_echo_ignore_all=1` Set kernal to ignore ping packets  
`sysctl -p` Load settings from /etc/sysctl.conf  

### Prevent Root Login
`visudo` To modify sudoer file  
`<username> ALL=ALL` To enable root previleges  
`root:x:0:0:root:/root:/sbin/nologin` Add '/sbin/nologin' in /etc/passwd to enable non-interactive shell  
`/bin/bash` For interactive shell  

### Chroot
`setsebool -P ftp_home_dir on` To allow users to access their home directories  
Editing `/etc/vsftp.conf`  
`chroot_list_enable=YES`  
`chroot_list_file=/etc/vsftpd/chroot_list`  
`allow_writeable_chroot=YES`  

### SELinux
`getenforce`  
`setenforce 0` Permissive mode  
`setenforce 1` Enforcing mode  
`getsebool -a | less` View SELinux booleans  
Edit `/etc/selinux/config` to set mode on bootup  
`ls -lZ <filename>` View SELinux file contexts  
`chcon -t shadow_t <filename>` To screw up file context  
`restorecon <filename>` To reset file context  

### VSFTPD & SELinux
`mkdir /var/ftp/incoming`  
`chgrp ftp /var/ftp/incoming`  
`chmod 730 /var/ftp/incoming`  
Uncomment `anon_upload_enable=YES` to allow anonymous uploads  

## Topic 2 (Web Servers)

### Apache Configuration
`/etc/httpd/conf/httpd.conf` Apache Config file  
`<Directory /var/www/html/books>
    Options -Indexes
 </Directory>  
`
Turning off Indexes  

### Virtual Hosts
`<VirtualHost your_server_ip:80>
    ServerName www.flowers.com
    DocumentRoot /var/www/flowers
    ErrorLog /var/log/httpd/flowers-error_log
    CustomLog /var/log/httpd/flowers-access_log combined
 </VirtualHost>`    

### CGI Scripts
`chcon –t httpd_sys_script_exec_t /var/www/fruits-cgi-bin` Setting file context  
`#!/usr/bin/perl
print “Content-type: text/html\n\n”;
print “Hello World”;
`  
`chmod 755 /var/www/fruits-cgi-bin/test.pl`  

### User Authentication (Section 8)
`htpasswd –cm /etc/httpd/conf/flowers-users bob`  
`htpasswd –m /etc/httpd/conf/flowers-users alice` -c option not used, only first entry requires it  

### Tomcat (Section 12)
`/var/lib/tomcat/webapps` Tomcat directory  

### nginx (Section 14)
Create the text file /usr/lib/systemd/system/nginx.service and enter the following contents.  
`[Unit]
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
WantedBy=multi-user.target`  

`/usr/local/nginx/sbin/nginx –s stop` Before you use the systemctl commands to start nginx, make sure nginx is not running already from the last exercise.  

## Topic 3 (File Systems)
`fdisk -l` View existing partitions  
To create a new partition on the hard disk, type "fdisk /dev/sda".  
* In fdisk, type 'm' to view the available options.  
* Type “p” to list the existing partitions on the hard disk.  
* To create a new partition, type 'n'.  
* Type 'p' to create a third primary partition. (as you already have 2 partitions)  
* Type “3” for Partition number 3.  
* Press enter to accept the default starting sector.  
* Type “+100M” to create a 100MB partition.  
* Type 'p' to list the partition info. Note your third partition and its device name (/dev/sda3). Also note its ID, which is 83 for Linux.  Type 'w' to write changes to disk and exit fdisk  
