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

#define FILTER_NOT_AUTH         0
#define FILTER_AUTH_ME          1
#define FILTER_AUTH_NOT_ME      2
#define FILTER_NOT_REM          3
#define FILTER_REM_ME           4
#define FILTER_REM_NOT_ME       5

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

/*
        USER=beelzebub
        PATH=/bin:/usr/bin
        PWD=/Users/jleffler/tmp/soq
        TZ=UTC0
        SHLVL=1
        HOME=/
        LOGNAME=tarzan
        _=/usr/bin/env
        */

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


/*static int get_gid(const char * name)
{
    struct group *grp;

    if ((grp = getgrnam(name)) != NULL)
    {
        return grp->gr_gid;
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

/*static void save_command_2(command_data * command, FILE * fp)
{
    char ** argv;
    argv = command->argv;

    while (*argv != NULL)
    {
        fwrite(argv, sizeof(char), strlen(*argv), fp);
        argv++;
    }

    fwrite(command->runas_uid, sizeof(char), strlen(command->runas_uid), fp);
    fwrite(command->runas_gid, sizeof(char), strlen(command->runas_gid), fp);

    fwrite(command->user, sizeof(char), strlen(command->user), fp);
    fwrite(command->home, sizeof(char), strlen(command->home), fp);
    fwrite(command->path, sizeof(char), strlen(command->path), fp);
    fwrite(command->pwd, sizeof(char), strlen(command->pwd), fp);

    fwrite(command->auth_by_user, sizeof(char), strlen(command->auth_by_user), fp);
}*/

static int save_command(command_data * command, int fd)
{
    int result;
    char ** argv;
    argv = command->argv;

    /*  Arguments count  */
    unsigned int argc = str_array_len(command->argv);
    result = (write(fd, &argc, 2) == 2);

    /*  Arguments  */
    while (*argv != NULL)
    {
        result &= save_string(*argv, fd);
        argv++;
    }

    /*  Separator  */
    unsigned int zero = 0;
    result &= (write(fd, &zero, 1) == 1);

    /*  Other data  */
    result &= save_string(command->runas_uid, fd) &&
              save_string(command->runas_gid, fd) &&
              save_string(command->user, fd) &&
              save_string(command->home, fd) &&
              save_string(command->path, fd) &&
              save_string(command->pwd, fd) &&
              save_string(command->auth_by_user, fd) &&
              save_string(command->rem_by_user, fd);

    return result;
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

#endif // SUDO_HELPER_INCLUDED
