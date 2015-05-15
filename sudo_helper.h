#ifndef SUDO_HELPER_INCLUDED
#define SUDO_HELPER_INCLUDED

#include <stdint.h>
#include <limits.h>

#define PLUGIN_NAME                     "Sudo Dual Authorization Security Plugin"
#define PLUGIN_CONF_FILE                "/etc/sudo_security_plugin.conf"
#define PLUGIN_COMMANDS_FILE            "/var/lib/sudo_security_plugin/commands"
#define PLUGIN_COMMANDS_TEMP_FILE       "/var/lib/sudo_security_plugin/commands-XXXXXX"
#define NO_USER                         "N/A"
#define MIN_AUTH_USERS                   2
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
    char ** exec_by_users;
    char ** rem_by_users;
} command_data;

/*
Check if strings starts with substring
*/
static bool str_starts(const char * a, const char * b)
{
    return (strncmp(a, b, strlen(b)) == 0);
}

/*
Check if strings starts with substring, not case sensitive
*/
static bool str_case_starts(const char * a, const char * b)
{
    return (strncasecmp(a, b, strlen(b)) == 0);
}

/*
Concaterate string arrays to one string, with separators
*/
static char * concat(char ** array, char * separator)
{
    if (!array)
    {
        return NULL;
    }

    char * str = NULL;
    size_t total_length = 0;
    size_t separator_length = (separator) ? strlen(separator) : 1;  // 1 for '0'

    char ** current = array;

    while (*current != NULL)
    {
        total_length += strlen(*current) + separator_length;
        current++;
    }

    if (total_length == 0 || (str = malloc(total_length)) == NULL)
    {
        return NULL;
    }

    str[0] = '\0';
    current = array;

    while (*current != NULL)
    {
        strcat(str, *current);

        if (*(++current) && separator)
        {
            strcat(str, separator);
        }
    }

  return str;
}

/*
Removes whitespaces from string
*/
static char * rem_whitespace(char * str)
{
    if (!str)
    {
        return NULL;
    }

    char * c = str;

    while (*c != '\0' && !isspace((unsigned char)*c))
    {
        ++c;
    }

    if (*c != '\0')
    {
        c = '\0';
    }

    return str;
}

/*
Return array length
*/
static size_t str_array_len(char ** array)
{
    if (!array)
    {
        return 0;
    }

    size_t len = 0;

    char ** str = array;

    while (*str != NULL)
    {
        str++;
        len++;
    }

    return len;
}

/*
Copy file (or create file)
*/
static bool copy_file(char * from, int target_fd)
{
    int source_fd;
    struct stat s;
    off_t offset = 0;

    /* Source file does not exist, do not need to copy */
    if ((source_fd = open(from, O_RDONLY)) == -1)
    {
        return true;
    }

    if (fstat(source_fd, &s) < 0)
    {
        close(source_fd);
        return false;
    }

    bool result = (s.st_size > 0) ? (sendfile(target_fd, source_fd, &offset, s.st_size) == s.st_size) : true;

    close(source_fd);
    return result;
}

/*
Compares files
-1 = error
 0 = not same
 1 = same
*/
static int cmp_files(char * oldFile, char * newFile)
{
    int ch1, ch2, result = 1;

    FILE * fp1 = fopen(oldFile, "r");
    FILE * fp2 = fopen(newFile, "r");

    if (!fp1 || !fp2)
    {
        return -1;
    }

    do
    {
        ch1 = fgetc(fp1);
        ch2 = fgetc(fp2);

        if (ch1 != ch2)
        {
            result = 0;
            break;
        }
    } while (ch1 != EOF);

    fclose(fp1);
    fclose(fp2);

    return result;
}

/*
Return array size
*/
static size_t commands_array_len(command_data ** array)
{
    size_t len = 0;

    command_data ** cmd = array;

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
    {
        return;
    }

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
    {
        return;
    }

    char ** str = array;

    while (*str)
    {
        free(*str);
        str++;
    }

    free(array);
}

/*
Convert bytes to inteteger variable
*/
static size_t convert_from_bytes(unsigned char * array, size_t bytes)
{
    if (!array)
    {
        return -1;
    }

    switch (bytes)
    {
        case 1:
            return array[0];
        case 2:
            return array[0] + (array[1] << 8);
        case 4:
            return array[0] + (array[1] << 8) + (array[2] << 16) + (array[3] << 24);
        default:
            return -1;
    }
}

/*
Save int to binary file
*/
static bool save_int(size_t value, int bytes, int fd)
{
    char val1, val2, val3, val4;

    switch (bytes)
    {
        case 1:
            return (write(fd, &value, 1) == 1);
        case 2:
            val1 =  value        & 0xFF;
            val2 = (value >> 8)  & 0xFF;
            return (write(fd, &val1, 1) == 1) && (write(fd, &val2, 1) == 1);
        case 4:
            val1 =  value        & 0xFF;
            val2 = (value >> 8)  & 0xFF;
            val3 = (value >> 16) & 0xFF;
            val4 = (value >> 24) & 0xFF;
            return (write(fd, &val1, 1) == 1) && (write(fd, &val2, 1) == 1) && (write(fd, &val3, 1) == 1) && (write(fd, &val4, 1) == 1);
        default:
            return -1;
    }
}

/*
Save string to binary file
*/
static bool save_string(char * str, int fd)
{
    if (str)
    {
        // <length:4bytes><string>
        size_t length = strlen(str) + 1;

        return (length <= UINT32_MAX &&
                save_int(length, 4, fd) &&
                write(fd, str, length) == (ssize_t)length);
    }
    else
    {
        // 0000 (4 bytes)
        return save_int(0, 4, fd);
    }
}

/*
Load string from binary file and save to str
*/
static bool load_string(int fd, char ** str)
{
    unsigned char int_buffer[4];
    char * string;

    if (read(fd, int_buffer, 4) != 4)
    {
        return false;
    }

    size_t len = convert_from_bytes(int_buffer, 4);

    // Empty string
    if (len == 0)
    {
        *str = NULL;
        return true;
    }

    // Load string
    // <length:4bytes><string>

    if ((string = malloc(sizeof(char) * len)) == NULL)
    {
        return false;
    }

    if (len > SSIZE_MAX || read(fd, string, sizeof(char) * len) != (ssize_t)len)
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
Load from file string array terminated by NULL
*/
static bool load_string_array(int fd, char *** str_array)
{
    unsigned char int_buffer[2];
    char ** array;

    /* Arguments count */
    if (read(fd, int_buffer, 2) != 2)
    {
        return false;
    }

    size_t len = convert_from_bytes(int_buffer, 2);

    if (len == 0)
    {
        *str_array = NULL;
        return true;
    }

    if ( (array = malloc((len+1)*sizeof(char*))) == NULL )
    {
        return false;
    }

    for (size_t i = 0; i < len; i++)
    {
        char * str = NULL;

        if (!load_string(fd, &str))
        {
            array[i] = NULL;
            free_2d_null(array);
            return false;
        }

        array[i] = str;
    }

    array[len] = NULL;

    *str_array = array;

    return true;
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
    command->exec_by_users = NULL;
    command->rem_by_users = NULL;

    return command;
}

static void free_command(command_data * command)
{
    if (!command)
    {
        return;
    }

    free(command->file);
    free(command->runas_user);
    free(command->runas_group);
    free(command->user);
    free(command->home);
    free(command->path);
    free(command->pwd);

    free_2d_null(command->argv);
    free_2d_null(command->exec_by_users);
    free_2d_null(command->rem_by_users);

    free(command);
}

/*
Free commands array
*/
static void free_commands_null(command_data ** array)
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

/*
Add command to commands array
*/
static char ** add_string(char ** array, char * str)
{
    if (!str)
    {
        return NULL;
    }

    size_t count = str_array_len(array);

    char ** strings;

    if ( (strings = realloc(array, (count+2) * sizeof(char*) )) == NULL )
    {
        return NULL;
    }

    strings[count] = str;
    strings[count+1] = NULL;

    return strings;
}

/*
Add command to commands array
*/
static command_data ** add_command(command_data ** array, command_data * command)
{
    if (!array || !command)
    {
        return NULL;
    }

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
    {
        return false;
    }

    char ** item = array;

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
Search for file in a PWD or PATH
*/
static char * find_in_path(char * command, char ** envp, int mode)
{
    if (!command)
    {
        return NULL;
    }

    char * path = NULL, * cp_path = NULL, * cmd = NULL;

     /* Already a path */
    if (command[0] == '/')
    {
        if (access(command, mode) == 0)
        {
            return strdup(command);
        }
    }

    for (char ** ep = envp; *ep != NULL; ep++)
    {
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

    if ((cp_path = strdup(path)) != NULL)
    {
        char * token;

        /* First path */
        token = strtok(cp_path, ":");

        while (token)
        {
            if (strcmp(token,".") == 0)
            {
                char * cwd = get_current_dir_name();
                if (!cwd)
                {
                    return NULL;
                }
                if (asprintf(&cmd, "%s/%s", cwd, command) < 0)
                {
                    free(cwd);
                    return NULL;
                }
                free(cwd);
            }
            else
            {
                if (asprintf(&cmd, "%s/%s", token, command) < 0)
                {
                    free(cp_path);
                    return NULL;
                }
            }

            if (access(cmd, mode) == 0)
            {
                free(cp_path);
                return cmd;
            }
            free(cmd);

            /* Next path */
            token = strtok(NULL, ":");
        };
    }
    free(cp_path);

    for (char ** ep = envp; *ep != NULL; ep++)
    {
        if (str_starts(*ep,"PATH="))
        {
            path = * ep + 5;
            break;
        }
    }

    return NULL;
}

/*
Getenv from envp array
*/
static char * getenv_from_envp(char * name, char ** envp)
{
    char * key;
    if (asprintf(&key, "%s=", name) < 0)
    {
        return NULL;
    }

    for (char ** ep = envp; *ep != NULL; ep++)
    {
        if (str_starts(*ep, key))
        {
            size_t len = strlen(key);
            free(key);
            return *ep + len + 1;
        }
    }

    free(key);
    return NULL;
}

/*
Find editor for sudoedit
*/
static char * find_editor(char ** envp)
{
    char * editor;

    if ((editor = getenv_from_envp("SUDO_EDITOR", envp)))
    {
        return strdup(editor);
    }

    if ((editor = getenv_from_envp("VISUAL", envp)))
    {
        return strdup(editor);
    }

    if ((editor = getenv_from_envp("EDITOR", envp)))
    {
        return strdup(editor);
    }

    /* Try to search for VIM editor */
    if (access("/usr/bin/vi", X_OK) == 0)
    {
        return strdup("/usr/bin/vi");
    }

    return NULL;
}

#endif // SUDO_HELPER_INCLUDED
