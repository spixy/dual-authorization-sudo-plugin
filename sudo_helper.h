#ifndef SUDO_HELPER_INCLUDED
#define SUDO_HELPER_INCLUDED

#define PLUGIN_NAME                     "Sudo Security Plugin"

#define PLUGIN_CONF_FILE                "/etc/sudo_security_plugin.conf"
#define PLUGIN_DATA_DIR                 "/etc/sudo_security_plugin/"
#define PLUGIN_COMMANDS_FILE            "/etc/sudo_security_plugin/commands"
#define PLUGIN_COMMANDS_TEMP_FILE       "/tmp/sudo_security_plugin_XXXXXX"
#define BOTH_USERS_AUTHENTICATED        " "

#define MAX_USER_LENGTH        32
#define MAX_NUM_LENGTH          8
#define AUTH_USERS              2


/*#ifdef __TANDEM
# define ROOT_UID       65535
#else
# define ROOT_UID       0
#endif*/

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
    char * file;
    char ** argv;
    char * runas_uid;
    char * runas_gid;
    char * user;
    char * home;
    char * path;
    char * pwd;
    char * auth_by_user;
    char * rem_by_user;
    int sudoedit;
} command_data;


/*static int get_uid(const char * name)
{
    struct passwd *pw;

    if ((pw = getpwnam(name)) != NULL)
    {
        return pw->pw_uid;
    }

    return -1;
}*/

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

static char * str_no_whitespace(char * str)
{
    char * c = str;

    while (isspace(*c))
        ++c;

    return c;
}

/*
Check if strings starts with substring
*/
/*static bool str_starts_and_ends(const char * a, const char * b)
{
    int len = strlen(a);

    return ( (len >= 2) && (a[0] == b) && (a[len-1] == b) );
}*/

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
Save string to binary file <length:2bytes><string>
*/
static int save_string(char * str, int fd)
{
    if (str != NULL)
    {
        unsigned int len = strlen(str) + 1;

        return (write(fd, &len, 2) == 2 &&
                write(fd, str, len) == (int)len);
    }
    else
    {
        unsigned int zero = 0;
        return (write(fd, &zero, 2) == 2);
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

    while (*cmd != NULL)
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
    if (array == NULL)
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
    if (array == NULL)
        return;

    char ** str;
    str = array;

    while (*str != NULL)
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
    command->file = NULL;
    command->runas_uid = NULL;
    command->runas_gid = NULL;
    command->user = NULL;
    command->home = NULL;
    command->path = NULL;
    command->pwd = NULL;
    command->auth_by_user = NULL;
    command->rem_by_user = NULL;
    command->sudoedit = false;

    return command;
}

static void free_command(command_data * command)
{
    if (command == NULL)
        return;

    free(command->file);
    free(command->runas_uid);
    free(command->runas_gid);
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
Frees commands
*/
static void free_commands_null(command_data ** commands)
{
    if (commands == NULL)
        return;

    int i = 0;
    while (commands[i] != NULL)
    {
        free_command(commands[i]);
        i++;
    }
    commands = NULL;
}

static command_data ** remove_command(command_data ** array, command_data * cmd)
{
    if (array == NULL || cmd == NULL)
        return NULL;

    int count = commands_array_len(array);
    int index = 0;

    for (int i = 0; i < count; i++)
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

static command_data ** add_command(command_data ** array, command_data * command)
{
    if (array == NULL || command == NULL)
        return NULL;

    int count = commands_array_len(array) + 2;

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
    if (array == NULL || str == NULL)
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

    if (editor == NULL)
    {
        return find_in_path("vi", envp);
    }

    return strdup(editor);
}

#endif // SUDO_HELPER_INCLUDED
