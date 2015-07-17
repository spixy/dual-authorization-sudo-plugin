#ifndef IO_H_INCLUDED
#define IO_H_INCLUDED

#define PLUGIN_CONF_FILE                "/etc/sudo_dual_authorization.conf"
#define PLUGIN_COMMANDS_FILE            "/var/lib/sudo_dual_authorization/commands"
#define PLUGIN_COMMANDS_TEMP_FILE       "/var/lib/sudo_dual_authorization/commands-XXXXXX"

#include "command.h"

#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/sendfile.h>

/*
Save int to binary file
*/
bool save_int(size_t value, int bytes, int fd);

/*
Save string to binary file
*/
bool save_string(char * str, int fd);

/*
Save string array to binary file
*/
bool save_string_array(char ** str_array, int fd);

/*
Load string from binary file and save to str
*/
bool load_string(int fd, char ** str);

/*
Load string array terminated by NULL from file
*/
bool load_string_array(int fd, char *** str_array);

/*
Copy file (or create file)
-1 = source file does not exist
 0 = error
 1 = success
*/
int copy_file(char * from, int target_fd);

/*
Compare files
*/
bool cmp_files(char * oldFile, char * newFile);

/*
Load all commands from file
*/
command_data ** load(int fd);

/*
Load next command from file
*/
command_data * load_command(int fd);

/*
Save all commands to file
*/
bool save(command_data ** commands);

/*
Save command to binary file
*/
bool save_command(command_data * command, int fd);

#endif // IO_H_INCLUDED
