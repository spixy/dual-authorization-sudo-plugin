Dual-authorization plugin for sudo, allows to run commands (as root user) only after authorization by 2 different users.


##Usage:

sudo auth [ -l | -e | -r ] [-v]

  -l    shows all commands
  
  -e    executes all commands
  
  -r    removes all commands
  
  -v    shows all commands information

[Configuration file example](examples/sudo_security_plugin.conf)

##Requirements:
Sudo 1.8 and newer


##Setup:
Installation:
run "make install" as root

Uninstallation:
run "make uninstall" as root


![Screenshot](examples/sudo_example.png)
