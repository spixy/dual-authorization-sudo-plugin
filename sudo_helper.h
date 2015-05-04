#ifndef SUDO_HELPER_INCLUDED
#define SUDO_HELPER_INCLUDED

#define PLUGIN_NAME                     "Sudo Security Plugin"
#define PLUGIN_CONF_FILE                "/etc/sudo_security_plugin.conf"
#define PLUGIN_DATA_DIR                 "/etc/sudo_security_plugin/"
#define PLUGIN_COMMANDS_FILE            "/etc/sudo_security_plugin/commands"
#define PLUGIN_COMMANDS_TEMP_FILE       "/tmp/sudo_security_plugin_XXXXXX"
#define BOTH_USERS_AUTHENTICATED        " "
#define AUTH_USERS                      (2)

#define QUOTE(name) #name
#define STR(macro) QUOTE(macro)

struct plugin_state
{
    char ** envp;
    char * const * settings;
    char * const * user_info;
};

typedef struct _command_data
{
    char ** argv;
    char * runas_user;
    char * runas_group;
    char * user;
    char * home;
    char * path;
    char * pwd;
    char * auth_by_user;
    char * rem_by_user;
} command_data;


/*
Check if strings starts with substring
*/
static bool str_starts(const char * a, const char * b)
{
    return (strncmp(a, b, strlen(b)) == 0);
}

static bool str_case_starts(const char * a, const char * b)
{
    return (strncasecmp(a, b, strlen(b)) == 0);
}

/*
Removes whitespaces from string
*/
static char * str_no_whitespace(char * str)
{
    if (!str)
        return NULL;

    char * c = str;

    while (isspace(*c))
        ++c;

    return c;
}

/*
Get array length
*/
static unsigned int str_array_len(char ** array)
{
    unsigned int len = 0;

    char ** str;
    str = array;

    while (*str != NULL)
    {
        str++;
        len++;
    }

    return len;
}

/*
Save string to binary file <length:4bytes><string>
*/
static int save_string(char * str, int fd)
{
    if (str)
    {
        unsigned int len = strlen(str) + 1;

        return (write(fd, &len, 4) == 4 &&
                write(fd, str, len) == (int)len);
    }
    else
    {
        unsigned int zero = 0;
        return (write(fd, &zero, 4) == 4);
    }
}

/*
Array size
*/
static unsigned int commands_array_len(command_data ** array)
{
    unsigned int len = 0;

    command_data ** cmd;
    cmd = array;

    while (*cmd)
    {
        cmd++;
        len++;
    }

    return len;
}

/*
Frees 2D array
*/
static void free_2d(char ** array, size_t count)
{
    if (!array)
        return;

    for (size_t i = 0; i < count; ++i)
    {
        free(array[i]);
    }

    free(array);

    array = NULL;
}

/*
Frees 2D array
*/
static void free_2d_null(char ** array)
{
    if (!array)
        return;

    char ** str;
    str = array;

    while (*str)
    {
        free(*str);
        str++;
    }

    free(array);

    array = NULL;
}

/*
Initialize empty command
*/
static command_data * make_command()
{
    command_data * command;

    if ( (command = malloc( sizeof(command_data) )) == NULL )
    {
        return NULL;
    }

    command->argv = NULL;
    command->runas_user = NULL;
    command->runas_group = NULL;
    command->user = NULL;
    command->home = NULL;
    command->path = NULL;
    command->pwd = NULL;
    command->auth_by_user = NULL;
    command->rem_by_user = NULL;

    return command;
}

static void free_command(command_data * command)
{
    if (!command)
        return;

    free(command->runas_user);
    free(command->runas_group);
    free(command->user);
    free(command->home);
    free(command->path);
    free(command->pwd);
    free(command->auth_by_user);
    free(command->rem_by_user);

    free_2d_null(command->argv);

    free(command);

    command = NULL;
}

/*
Free commands array
*/
static void free_commands_null(command_data ** commands)
{
    if (!commands)
        return;

    unsigned int i = 0;
    while (commands[i] != NULL)
    {
        free_command(commands[i]);
        i++;
    }
    commands = NULL;
}

/*
Remove command from commands array
*/
static command_data ** remove_command(command_data ** array, command_data * cmd)
{
    if (!array || !cmd)
        return NULL;

    unsigned int count = commands_array_len(array);
    unsigned int index = 0;

    for (unsigned int i = 0; i < count; i++)
    {
        if (array[i] != cmd)
        {
            array[index] = array[i];
            index++;
        }
    }

    array[index] = NULL;

    return array;
}

/*
Add command to commands array
*/
static command_data ** add_command(command_data ** array, command_data * command)
{
    if (!array || !command)
        return NULL;

    unsigned int count = commands_array_len(array) + 2;

    command_data ** cmds;

    if ( (cmds = realloc(array, count * sizeof(command_data*) )) == NULL )
    {
        return NULL;
    }

    cmds[count-2] = command;
    cmds[count-1] = NULL;

    return cmds;
}

/*
Check if array contains string
*/
static bool array_contains(const char * str, char ** array, size_t count)
{
    if (!array || !str)
        return false;

    for (size_t i = 0; i < count; ++i)
    {
        if (strcmp(array[i], str) == 0)
            return true;
    }
    return false;
}

/*
Search for file in a PATH variable
*/
static char * find_in_path(char * command, char ** envp)
{
    struct stat sb;
    char * path = NULL, *cp_path, **ep;
    char * cmd = NULL;

     /* Already a path */
    if (strchr(command, '/') != NULL)
        return strdup(command);

    for (ep = envp; *ep != NULL; ep++)
    {
        /* Search for PATH in environment vars */
        if (str_starts(*ep,"PATH="))
        {
            path = * ep + 5;
            break;
        }
    }

    cp_path = strdup(path);

    /* Curent path */
    if ( asprintf(&cmd, "./%s",command) < 0 )
    {
        free(cp_path);
        return NULL;
    }

    if (stat(cmd, &sb) == 0)
    {
        /* Check if file exist in path & have permission to execute */
        if (S_ISREG(sb.st_mode) && (sb.st_mode & 0000111))
        {
            return cmd;
        }
    }

    free(cmd);

    if (cp_path != NULL)
    {
        char * token;

        /* First path */
        token = strtok(cp_path, ":");

        while ( token != NULL )
        {
            if ( asprintf(&cmd, "%s/%s", token, command) < 0 )
            {
                free(cp_path);
                return NULL;
            }

            if (stat(cmd, &sb) == 0)
            {
                /* Check if file exist in path & have permission to execute */
                if (S_ISREG(sb.st_mode) && (sb.st_mode & 0000111))
                {
                    free(cp_path);
                    return cmd;
                }
            }
            free(cmd);

            /* Next path */
            token = strtok(NULL, ":");
        };
    }

    free(cp_path);
    return NULL;
}

/*
Find editor for sudoedit
*/
static char * find_editor(char ** envp)
{
    char ** ep;
    char * editor = NULL;

    for (ep = envp; *ep != NULL; ep++)
    {
        if (str_starts(*ep, "SUDO_EDITOR"))
        {
            editor = *ep + 12;
            break;
        }
    }

    if (editor == NULL)
    for (ep = envp; *ep != NULL; ep++)
    {
        if (str_starts(*ep, "VISUAL"))
        {
            editor = *ep + 7;
            break;
        }
    }

    if (editor == NULL)
    for (ep = envp; *ep != NULL; ep++)
    {
        if (str_starts(*ep, "EDITOR"))
        {
            editor = *ep + 7;
            break;
        }
    }

    /* Try to search for VI editor */
    if (editor == NULL)
    {
        return find_in_path("vi", envp);
    }

    return strdup(editor);
}

#endif // SUDO_HELPER_INCLUDED
