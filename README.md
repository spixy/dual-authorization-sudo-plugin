Dual-authorization plugin for Sudo, allows to run commands (as root user) only after authorization by 2 different users.


## Usage:

**sudo** PROGRAM [ PARAMETERS ]

**sudo auth [ -s | -e | -r ] [ -l | -f ]**

### Options:

If command (parameters are optional) is supplied, command is stored in queue.

If **auth** parameter is used, plugin allows to run selected commands or remove them from queue.

###### OPTIONAL PARAMETERS:

  **-s**    prints all commands inc queue
  
  **-e**    executes all commands in queue
  
  **-r**    removes all commands from queue
  
  **-l**    shows commands in brief list
  
  **-f**    shows full commands information

[Configuration file example](examples/sudo_security_plugin.conf)


## Setup:
Installation:
run **make install** as root

Uninstallation:
run **make uninstall** as root

### Requirements:
Sudo 1.8 and newer


## Screenshot:
![Screenshot](https://cloud.githubusercontent.com/assets/4542110/8735206/625d436c-2c0f-11e5-89a4-614dfce98598.png)
