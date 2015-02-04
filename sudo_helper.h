#ifndef SUDO_HELPER_INCLUDED
#define SUDO_HELPER_INCLUDED

#define PLUGIN_CONF_FILE          "/etc/sudo_security_plugin.conf"
#define PLUGIN_DATA_DIR           "/etc/sudo_security_plugin/"
#define PLUGIN_COMMANDS_LIST_FILE "/etc/sudo_security_plugin/commands"
#define PLUGIN_AUTH_USERS_FILE    "/etc/sudo_security_plugin/auth_users"
#define PLUGIN_NAME               "Sudo Security Plugin"

#define QUOTE(name) #name
#define STR(macro) QUOTE(macro)

#define BUFFER_SIZE       256
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
} command_data;

/*
Check if strings starts with string
*/
bool str_starts(const char *a, const char *b)
{
    if (strncmp(a, b, strlen(b)) == 0)
        return true;
    else
        return false;
}

/*
Frees 2D array
*/
static void free_2d(char** array, size_t count)
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
static void free_2d_null(char** array)
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

/*
Frees command
*/
static void free_command(command_data * command)
{
    free(command->file);
    free(command->runas_uid);
    free(command->runas_gid);

    free_2d_null(command->argv);

    free(command);

    command = NULL;
}

/*
Check if array contains string
*/
static bool array_contains(const char* str, char** array, size_t count)
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
static char* find_in_path(char * command, char ** envp)
{
    struct stat sb;
    char *path = NULL, *cp_path, **ep;
    char * cmd = NULL;

     /* Already path */
    if (strchr(command, '/') != NULL)
        return strdup(command);

    for (ep = envp; *ep != NULL; ep++)
    {
        /* Search for PATH in environment vars */
        if (str_starts(*ep,"PATH="))
        {
            path = *ep + 5;
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
        char *token;

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
                    return cmd;
                }
            }
            free(cmd);

            /* Next path */
            token = strtok(NULL, ":");
        };
    }
    return NULL;
}

/*
* Creates a name=value string
*/
static char* formate_string(const char* name, const char* value)
{
    char *str = malloc(strlen(name) + 1 + strlen(value) + 1);

    if (str != NULL)
    {
        strcpy(str, name);
        strcat(str, "=");
        strcat(str, value);
    }
    return str;
}

#endif // SUDO_HELPER_INCLUDED
