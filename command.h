#ifndef COMMAND_H_INCLUDED
#define COMMAND_H_INCLUDED

#include "utils.h"

typedef struct _command_data
{
    char * file;
    char ** argv;
    char sudoedit;
    char * runas_user;
    char * runas_group;
    char ** envp;
    char ** exec_by_users;
    char ** rem_by_users;
} command_data;

/*
Initialize empty command
*/
command_data * make_command();

/*
Return array size
*/
size_t commands_array_len(command_data ** array);


/*
Free command
*/
void free_command(command_data * command);

/*
Add command to commands array
*/
command_data ** add_command(command_data ** array, command_data * command);

/*
Remove command from commands array
*/
command_data ** remove_command(command_data ** array, command_data * cmd);

/*
Free commands array
*/
void free_commands_null(command_data ** array);


#endif // COMMAND_H_INCLUDED
