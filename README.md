Dual-authorization plugin for sudo, allows to run commands (as root user) only after authorization by 2 different users.


##Usage:

**sudo auth [ -s | -e | -r ] [ -l | -f ]**

  **-s**    prints all commands
  
  **-e**    executes all commands
  
  **-r**    removes all commands
  
  **-l**    shows commands in list
  
  **-f**    shows full commands information

[Configuration file example](examples/sudo_security_plugin.conf)

##Requirements:
Sudo 1.8 and newer


##Setup:
Installation:
run **make install** as root

Uninstallation:
run **make uninstall** as root


##Screenshot:
![Screenshot](https://cloud.githubusercontent.com/assets/4542110/8735206/625d436c-2c0f-11e5-89a4-614dfce98598.png)
