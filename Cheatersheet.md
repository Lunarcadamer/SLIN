# SLIN Cheatsheet

## Topic 0

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

