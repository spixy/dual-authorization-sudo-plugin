#include "command.h"

command_data * make_command()
{
    command_data * command;

    if ( (command = malloc( sizeof(command_data) )) == NULL )
    {
        return NULL;
    }

    command->file = NULL;
    command->argv = NULL;
    command->sudoedit = false;
    command->runas_user = NULL;
    command->runas_group = NULL;
    command->envp = NULL;
    command->exec_by_users = NULL;
    command->rem_by_users = NULL;

    return command;
}

size_t commands_array_len(command_data ** array)
{
    if (!array)
    {
        return 0;
    }

    size_t len = 0;

    command_data ** cmd = array;

    while (*cmd)
    {
        cmd++;
        len++;
    }

    return len;
}

command_data ** add_command(command_data ** array, command_data * command)
{
    if (!command)
    {
        return NULL;
    }

    size_t count = commands_array_len(array);
    command_data ** cmds;

    if ((cmds = realloc(array, (count+2) * sizeof(command_data*))) == NULL)
    {
        return NULL;
    }

    cmds[count] = command;
    cmds[count+1] = NULL;

    return cmds;
}

command_data ** remove_command(command_data ** array, command_data * cmd)
{
    if (!array || !cmd)
    {
        return NULL;
    }

    size_t i = 0;
    size_t index = 0;

    while (array[i])
    {
        if (array[i] != cmd)
        {
            array[index] = array[i];
            index++;
        }
        else
        {
            free_command(cmd);
        }
        i++;
    }

    array[index] = NULL;

    return array;
}

void free_command(command_data * command)
{
    if (!command)
    {
        return;
    }

    free(command->file);
    free(command->runas_user);
    free(command->runas_group);

    free_2d_null(command->argv);
    free_2d_null(command->envp);
    free_2d_null(command->exec_by_users);
    free_2d_null(command->rem_by_users);

    free(command);
}

void free_commands_null(command_data ** array)
{
    if (!array)
    {
        return;
    }

    command_data ** command = array;

    while (*command)
    {
        free_command(*command);
        command++;
    }

    free(array);
}
