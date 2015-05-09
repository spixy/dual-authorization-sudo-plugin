#ifndef SUDO_HELPER_INCLUDED
#define SUDO_HELPER_INCLUDED

#include <limits.h>


#define PLUGIN_NAME                     "Sudo Dual Authorization Security Plugin"
#define PLUGIN_CONF_FILE                "/etc/sudo_security_plugin.conf"
#define PLUGIN_DATA_DIR                 "/etc/sudo_security_plugin/"
#define PLUGIN_COMMANDS_FILE            "/etc/sudo_security_plugin/commands"
#define PLUGIN_COMMANDS_TEMP_FILE       "/etc/sudo_security_plugin/commands-XXXXXX"
#define BOTH_USERS_AUTHENTICATED        "BOTH_USERS"
#define NO_USER                         "N/A"
#define MIN_AUTH_USERS                   (2)
#define MAX_2_BYTES                      65535
#define PACKAGE_VERSION                  0.1

#define QUOTE(name) #name
#define STR(macro) QUOTE(macro)

typedef struct _command_data
{
    char * file;
    char ** argv;
    char sudoedit;
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

char * concat(char ** array)
{
    if (!array)
        return NULL;

    char * str = NULL;
    size_t total_length = 1;

    char ** current;
    current = array;

    while (*current != NULL)
    {
        total_length += strlen(*current);
        current++;
    }

    if ((str = malloc(total_length)) == NULL)
        return NULL;

    str[0] = '\0';

    current = array;

    while (*current != NULL)
    {
        strcat(str, *current);
        current++;
    }

  return str;
}

/*
Removes whitespaces from string
*/
static char * rem_whitespace(char * str)
{
    if (!str)
        return NULL;

    char * c = str;

    while (isspace(*c))
    {
        ++c;
    }

    return c;
}

/*
Get array length
*/
static size_t str_array_len(char ** array)
{
    size_t len = 0;

    char ** str;
    str = array;

    while (*str != NULL)
    {
        str++;
        len++;
    }

    return len;
}

static bool is_little_endian()
{
    int n = 1;
    return (*(char *)&n == 1);
}

static size_t convert_from_bytes(unsigned char * array, size_t size)
{
    if (!array)
        return 0;

    switch (size)
    {
        case 1:
            return array[0];
        case 2:
            if (is_little_endian())
            {
                return array[0] + (array[1] << 8);
            }
            else
            {
                return (array[0] << 8) + array[1];
            }
        case 4:
            if (is_little_endian())
            {
                return array[0] + (array[1] << 8) + (array[2] << 16) + (array[3] << 24);
            }
            else
            {
                return (array[0] << 24) + (array[1] << 16) + (array[2] << 8) + array[3];
            }
    }
    return 0;
}

/*
Save string to binary file <length:4bytes><string>
*/
static int save_string(char * str, int fd)
{
    if (str)
    {
        size_t len = strlen(str) + 1;

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
Load string from file
*/
static int load_string(int fd, char ** str)
{
    unsigned char int_buffer[4];
    char * string;

    if (read(fd, int_buffer, 4) != 4)
    {
        return false;
    }

    size_t len = convert_from_bytes(int_buffer, 4);

    if (len == 0)
    {
        *str = NULL;
        return true;
    }

    if ((string = malloc(sizeof(char) * len)) == NULL)
    {
        return false;
    }

    if (read(fd, string, sizeof(char) * len) != (ssize_t)len)
    {
        free(string);
        return false;
    }

    /* Checking length */
    if (string[len-1] != '\0' || strlen(string)+1 != len)
    {
        free(string);
        return false;
    }

    *str = string;

    return true;
}

/*
Array size
*/
static size_t commands_array_len(command_data ** array)
{
    size_t len = 0;

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

    command->file = NULL;
    command->argv = NULL;
    command->sudoedit = false;
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

    free(command->file);
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
}

/*
Free commands array
*/
static void free_commands_null(command_data ** commands)
{
    if (!commands)
        return;

    size_t i = 0;
    while (commands[i] != NULL)
    {
        free_command(commands[i]);
        i++;
    }
}

/*
Add command to commands array
*/
static command_data ** add_command(command_data ** array, command_data * command)
{
    if (!array || !command)
        return NULL;

    size_t count = commands_array_len(array);

    command_data ** cmds;

    if ( (cmds = realloc(array, (count+2) * sizeof(command_data*) )) == NULL )
    {
        return NULL;
    }

    cmds[count] = command;
    cmds[count+1] = NULL;

    return cmds;
}

/*
Check if array contains string
*/
static bool array_null_contains(char ** array, const char * str)
{
    if (!array || !str)
        return false;

    char ** item;
    item = array;

    while (*item)
    {
        if (strcmp(*item, str) == 0)
        {
            return true;
        }

        item++;
    }

    return false;
}

/*
Check if array contains string
*/
static bool array_contains(char ** array, const char * str, size_t count)
{
    if (!array || !str)
        return false;

    for (size_t i = 0; i < count; ++i)
    {
        if (strcmp(array[i], str) == 0)
        {
            return true;
        }
    }
    return false;
}

/*
Search for file in a PATH variable
*/
static char * find_in_path(char * command, char ** envp)
{
    struct stat sb;
    char * path = NULL, *cp_path;
    char * cmd = NULL;

     /* Already a path */
    if (strchr(command, '/') != NULL)
    {
        return strdup(command);
    }

    for (char ** ep = envp; *ep != NULL; ep++)
    {
        /* Search for PATH in environment vars */
        if (str_starts(*ep,"PATH="))
        {
            path = * ep + 5;
            break;
        }
    }

    if (!path)
    {
        return NULL;
    }

    /* Curent path */
    if ( asprintf(&cmd, "./%s",command) < 0 )
    {
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
    cp_path = strdup(path);

    if (cp_path)
    {
        char * token;

        /* First path */
        token = strtok(cp_path, ":");

        while (token)
        {
            if (asprintf(&cmd, "%s/%s", token, command) < 0)
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
        if (str_starts(*ep, "SUDO_EDITOR="))
        {
            editor = *ep + 13;
            break;
        }
    }

    if (editor == NULL)
    for (ep = envp; *ep != NULL; ep++)
    {
        if (str_starts(*ep, "VISUAL="))
        {
            editor = *ep + 8;
            break;
        }
    }

    if (editor == NULL)
    for (ep = envp; *ep != NULL; ep++)
    {
        if (str_starts(*ep, "EDITOR="))
        {
            editor = *ep + 8;
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
