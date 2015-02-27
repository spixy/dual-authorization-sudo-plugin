#ifndef SUDO_HELPER_INCLUDED
#define SUDO_HELPER_INCLUDED

#define PLUGIN_CONF_FILE                "/etc/sudo_security_plugin.conf"
#define PLUGIN_DATA_DIR                 "/etc/sudo_security_plugin/"
#define PLUGIN_COMMANDS_ALL             "/etc/sudo_security_plugin/commands"         // all commands
#define PLUGIN_COMMANDS_APPLY           "/etc/sudo_security_plugin/commands_apply"   // 1/2 user authenticated to apply-all
#define PLUGIN_COMMANDS_CLEAR           "/etc/sudo_security_plugin/commands_clear"   // 1/2 user authenticated to reset-all
#define PLUGIN_APPLY_AUTH_FILE          "/etc/sudo_security_plugin/apply_auth"
#define PLUGIN_CLEAR_AUTH_FILE          "/etc/sudo_security_plugin/clear_auth"
#define PLUGIN_NAME                     "Sudo Security Plugin"

#define MAX_USER_LENGTH    32
#define MAX_GROUP_LENGTH  255
#define MAX_NUM_LENGTH     15
#define MIN_USERS           2
#define MAX_USERS           2

#ifdef __TANDEM
# define ROOT_UID       65535
#else
# define ROOT_UID       0
#endif

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
} command_data;


static int get_uid(const char * name)
{
    struct passwd *pw;

    if ((pw = getpwnam(name)) != NULL)
    {
        return pw->pw_uid;
    }

    return -1;
}


static int get_gid(const char * name)
{
    struct group *grp;

    if ((grp = getgrnam(name)) != NULL)
    {
        return grp->gr_gid;
    }

    return -1;
}

/*
Check if strings starts with substring
*/
static bool str_starts(const char * a, const char * b)
{
    return (strncmp(a, b, strlen(b)) == 0);
}

/*
Check if strings starts with substring
*/
static bool str_starts_and_ends(const char * a, const char * b)
{
    int len = strlen(a);

    return ( (len >= 2) && (a[0] == b) && (a[len-1] == b) );
}

/*
Frees 2D array
*/
static void free_2d(char ** array, size_t count)
{
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
    size_t i=0;

    while (array[i] != NULL)
    {
        free(array[i]);
        i++;
    }

    free(array);

    array = NULL;
}

static char * pure_string(const char * str)
{
    size_t len = strlen(str);

    char * newstr = malloc((len-1) * sizeof(char));
    strncpy(newstr, str+1, len-2);
    newstr[len-2] = '\0';

    return newstr;
}

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

    return command;
}

/*
Compare 2 arrays
 0 = same length
>0 = length of smaller 2nd array
<0 = length of smaller 1st array
*/

static int cmp_command(command_data ** cmd1, command_data ** cmd2)
{
    int i = 0;

    while (cmd1[i] != NULL && cmd2[i] != NULL)
    {
        i++;
    }

    /* Both arrays have same length */
    if (cmd1[i] == cmd2[i])
    {
        return 0;
    }
    /* 2nd longer */
    else if (cmd1[i] == NULL)
    {
        return -i;
    }
    /* 1st longer */
    else //if (cmd2[i] == NULL)
    {
        return i;
    }
}

/*
Frees command
*/
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

/*
Check if array contains string
*/
static bool array_contains(const char * str, char ** array, size_t count)
{
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
