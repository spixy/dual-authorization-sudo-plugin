#define _GNU_SOURCE // asprintf()

#include <ctype.h>
#include <fcntl.h>
#include <grp.h>
#include <memory.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
//#include <strings.h>
#include <sudo_plugin.h>
#include <pwd.h>
#include <linux/limits.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/wait.h>

#include "sudo_helper.h"

#define PACKAGE_VERSION 0.1

static struct plugin_state plugin_state;
static sudo_conv_t sudo_conv;
static sudo_printf_t sudo_log;
static uid_t runas_uid;
static gid_t runas_gid;
static int use_sudoedit = false;


static char* find_in_path(char *command, char **envp)
{
    struct stat sb;
    char *path, *path0, **ep, *cp;
    char pathbuf[PATH_MAX], *qualified = NULL;

    if (strchr(command, '/') != NULL)
        return command;

    //path = _PATH_DEFPATH;
    for (ep = plugin_state.envp; *ep != NULL; ep++)
    {
        if (strncmp(*ep, "PATH=", 5) == 0)
        {
            path = *ep + 5;
            break;
        }
    }
    path = path0 = strdup(path);
    do
    {
        if (( cp = strchr(path, ':') ))
            *cp = '\0';

        snprintf(pathbuf, sizeof(pathbuf), "%s/%s", *path ? path : ".", command);

        if (stat(pathbuf, &sb) == 0)
        {
            if (S_ISREG(sb.st_mode) && (sb.st_mode & 0000111))
            {
                qualified = pathbuf;
                break;
            }
        }
        path = cp + 1;
    } while (cp != NULL);

    free(path0);
    return qualified ? strdup(qualified) : NULL;
}

/*
Frees 2D char array
*/
static void free_2d(char** array, size_t count)
{
    for (size_t i = 0; i < count; ++i)
    {
        free(array[i]);
    }

    free(array);
}

/*
Check if array contains string
*/
static bool array_contains(char* str, char** array, size_t count)
{
    for (size_t i = 0; i < count; ++i)
    {
        if (strcmp(array[i], str) == 0)
            return true;
    }
    return false;
}

/*
Reads user names from conf file
*/
static int get_users(char **users)
{
    FILE *fp;

    if ( (fp = fopen(PLUGIN_CONF_FILE, "r")) != NULL )
    {
        char buffer[MAX_LINE];
        size_t usercount = 0;
        size_t usersize = 2;
        size_t len;
        struct passwd *pw;
        struct group *grp;

        if ( (users = malloc(usersize * sizeof(char*))) == NULL)
        {
            sudo_log(SUDO_CONV_ERROR_MSG, "Could not allocate data\n");
            return -1;
        }

        while (! feof(fp))
        {
            fgets(buffer, MAX_LINE, fp);

            len = strlen(buffer);

            // ignore empty lines and comments
            if (len > 0 && buffer[0] != '#')
            {
                if (usercount == usersize)
                {
                    usersize *= 2;

                    if ( (users = realloc(users, usersize * sizeof(char*))) == NULL)
                    {
                        sudo_log(SUDO_CONV_ERROR_MSG, "Could not allocate data\n");
                            return usercount;  /// TODO
                    }
                }

                if (strstr(buffer, "user ") == 0 && len > 5)
                {
                    char user[MAX_USER_LENGTH + 1];
                    strcpy(user, buffer+5); // strlen("user ") == 5

                    // checks if user exists
                    if (getpwnam(user) == NULL)
                    {
                        sudo_log(SUDO_CONV_ERROR_MSG, "user %s not found\n", user);
                        continue;
                    }

                    // checks if user is already loaded
                    if (array_contains(user, users, usercount))
                        continue;

                    // save user name
                    users[usercount] = malloc( strlen(user) + 1 );
                    strcpy(users[usercount], user);

                    usercount++;
                }
                else if (strstr(buffer, "uid ") == 0 && len > 4)
                {
                    // get user id
                    char uid_str[MAX_NUM_LENGTH + 1];
                    strcpy(uid_str, buffer+4); // strlen("uid ") == 4

                    // get user struct
                    uid_t id = atoi(uid_str);
                    pw = getpwuid(id);

                    if (pw == NULL)
                    {
                        sudo_log(SUDO_CONV_ERROR_MSG, "user with id %s not found\n", uid_str);
                        continue;
                    }

                    // checks if user is already loaded
                    if (array_contains(pw->pw_name, users, usercount))
                        continue;

                    // save user name
                    users[usercount] = malloc( strlen(pw->pw_name) + 1 );
                    strcpy(users[usercount], pw->pw_name);

                    usercount++;

                }
                else if (strstr(buffer, "group ") == 0 && len > 6)
                {
                    // get group name
                    char group[MAX_GROUP_LENGTH + 1];
                    strcpy(group, buffer+6); // strlen("group ") == 6

                    // get group struct
                    grp = getgrnam(group);

                    if (grp == NULL)
                    {
                        sudo_log(SUDO_CONV_ERROR_MSG, "group %s not found\n", group);
                        continue;
                    }

                    // get group members
                    for (int i = 0; ; i++)
                    {
                        if (grp->gr_mem[i] == NULL)
                            break;

                        // checks if user is already loaded
                        if (array_contains(grp->gr_mem[i], users, usercount))
                            continue;

                        // save user name
                        users[usercount] = malloc( strlen(grp->gr_mem[i]) + 1 );
                        strcpy(users[usercount], grp->gr_mem[i]);

                        usercount++;
                    }
                }
                else if (strstr(buffer, "gid ") == 0 && len > 4)
                {
                    // get group id
                    char gid_str[MAX_NUM_LENGTH + 1];
                    strcpy(gid_str, buffer+4); // strlen("gid ") == 4

                    // get group struct
                    gid_t id = atoi(gid_str);
                    grp = getgrgid(id);

                    if (grp == NULL)
                    {
                        sudo_log(SUDO_CONV_ERROR_MSG, "group with id %s not found\n", gid_str);
                        continue;
                    }

                    // get group members
                    for (int i = 0; ; i++)
                    {
                        if (grp->gr_mem[i] == NULL)
                            break;

                        // checks if user is already loaded
                        if (array_contains(grp->gr_mem[i], users, usercount))
                            continue;

                        // save user name
                        users[usercount] = malloc( strlen(grp->gr_mem[i]) + 1 );
                        strcpy(users[usercount], grp->gr_mem[i]);

                        usercount++;
                    }
                }
            }
        }

        fclose(fp);
        return usercount;
    }
    else
    {
        return -1;
    }
}


/*
Checks passwords
*/
static int check_passwd()
{
    struct sudo_conv_message msg;
    struct sudo_conv_reply repl;
    struct passwd *pw;
    char* user = NULL;
    char** users = NULL;
    char message[64];

    int count = get_users(users);

    if (count == -1)
    {
        sudo_log(SUDO_CONV_ERROR_MSG, "cannot read conf file\n");
        return false;
    }
    else if (count < MIN_USERS)
    {
        sudo_log(SUDO_CONV_ERROR_MSG, "not enough users (found %d, minimum is %d)\n", count, MIN_USERS);
        free_2d(users, count);
        return false;
    }

    unsigned short max = (count > MAX_USERS) ? MAX_USERS : count;

    for (unsigned short i = 0; i < max; ++i)
    {
        user = users[i];

        strcpy(message, user);
        strcat(message, " password:");

        memset(&msg, 0, sizeof(msg));
        msg.msg_type = SUDO_CONV_PROMPT_ECHO_OFF;
        msg.msg = message;

        memset(&repl, 0, sizeof(repl));
        sudo_conv(1, &msg, &repl);

        if (repl.reply == NULL)
        {
            sudo_log(SUDO_CONV_ERROR_MSG, "missing password\n");
            free_2d(users, count);
            return false;
        }

        pw = getpwnam(user);

        /* uz netreba kontrolovat

        if ( (pw = getpwnam(user)) == NULL)
        {
            sudo_log(SUDO_CONV_ERROR_MSG, "user not found\n");
            free_2d(users, count);
            return false;
        }*/

        if (strcmp(repl.reply, pw->pw_passwd) != 0)
        {
            sudo_log(SUDO_CONV_ERROR_MSG, "incorrect password\n");
            free_2d(users, count);
            return false;
        }
    }

    free_2d(users, count);
    return true;
}

static char** build_command_info(const char *command)
{
    static char **command_info;
    int i = 0;

    /* Setup command info. */
    command_info = calloc(32, sizeof(char *));
    if (command_info == NULL)
        return NULL;

    /*if ((command_info[i++] = fmt_string("command", command)) == NULL ||
        asprintf(&command_info[i++], "runas_euid=%ld", (long)runas_uid) == -1 ||
        asprintf(&command_info[i++], "runas_uid=%ld", (long)runas_uid) == -1)
	{
        return NULL;
    }*/

    //if (runas_gid != -1)
    //{
        if (asprintf(&command_info[i++], "runas_gid=%ld", (long)runas_gid) == -1 ||
            asprintf(&command_info[i++], "runas_egid=%ld", (long)runas_gid) == -1)
	    {
            return NULL;
        }
    //}

    if (use_sudoedit)
    {
        command_info[i] = strdup("sudoedit=true");
        if (command_info[i++] == NULL)
            return NULL;
    }

    #ifdef USE_TIMEOUT
    command_info[i++] = "timeout=30";
    #endif

    return command_info;
}

static char* find_editor(int nfiles, char * const files[], char **argv_out[])
{
    char *cp, **ep, **nargv, *editor, *editor_path;
    int ac, i, nargc, wasblank;

    /* Lookup EDITOR in user's environment. */
    //editor = _PATH_VI;
    for (ep = plugin_state.envp; *ep != NULL; ep++)
    {
        if (strncmp(*ep, "EDITOR=", 7) == 0)
        {
            editor = *ep + 7;
            break;
        }
    }
    editor = strdup(editor);
    if (editor == NULL)
    {
        sudo_log(SUDO_CONV_ERROR_MSG, "unable to allocate memory\n");
        return NULL;
    }

    /*
     * Split editor into an argument vector; editor is reused (do not free).
     * The EDITOR environment variables may contain command
     * line args so look for those and alloc space for them too.
     */
    nargc = 1;
    for (wasblank = 0, cp = editor; *cp != '\0'; cp++)
    {
        if (isblank((unsigned char) *cp))
            wasblank = 1;
        else if (wasblank)
        {
            wasblank = 0;
            nargc++;
        }
    }
    /* If we can't find the editor in the user's PATH, give up. */
    cp = strtok(editor, " \t");
    if (cp == NULL || (editor_path = find_in_path(editor, plugin_state.envp)) == NULL)
    {
        free(editor);
        return NULL;
    }
    if (editor_path != editor)
        free(editor);
    nargv = (char **) malloc((nargc + 1 + nfiles + 1) * sizeof(char *));
    if (nargv == NULL)
    {
        sudo_log(SUDO_CONV_ERROR_MSG, "unable to allocate memory\n");
        free(editor_path);
        return NULL;
    }
    for (ac = 0; cp != NULL && ac < nargc; ac++)
    {
        nargv[ac] = cp;
        cp = strtok(NULL, " \t");
    }
    nargv[ac++] = "--";
    for (i = 0; i < nfiles; )
        nargv[ac++] = files[i++];
    nargv[ac] = NULL;

    *argv_out = nargv;
    return editor_path;
}


/*
Returns 1 on success, 0 on failure, -1 if a general error occurred, or -2 if there was a usage error.
In the latter case, sudo will print a usage message before it exits.

If an error occurs, the plugin may optionally call the conversation() or plugin_printf() function with
SUDO_CONF_ERROR_MSG to present additional error information to the user.
*/
static int sudo_open (unsigned int version, sudo_conv_t conversation, sudo_printf_t sudo_printf,
                        char * const settings[], char * const user_info[], char * const user_env[], char * const options[])
{
    char * const *ui;
    struct passwd *pw;
    const char *runas_user = NULL;
    struct group *gr;
    const char *runas_group = NULL;

    if (!sudo_conv)
        sudo_conv = conversation;
    if (!sudo_log)
        sudo_log = sudo_printf;

    if (SUDO_API_VERSION_GET_MAJOR(version) != SUDO_API_VERSION_MAJOR)
    {
        sudo_log(SUDO_CONV_ERROR_MSG, "this plugin requires API version %d.x\n", SUDO_API_VERSION_MAJOR);
        return -1;
    }

    /* Only allow commands to be run as root. */
    for (ui = settings; *ui != NULL; ui++)
    {
        if (strncmp(*ui, "runas_user=", sizeof("runas_user=") - 1) == 0)
        {
            runas_user = *ui + sizeof("runas_user=") - 1;
        }
        if (strncmp(*ui, "runas_group=", sizeof("runas_group=") - 1) == 0)
        {
            runas_group = *ui + sizeof("runas_group=") - 1;
        }

        #if !defined(HAVE_GETPROGNAME) && !defined(HAVE___PROGNAME)
        /*if (strncmp(*ui, "progname=", sizeof("progname=") - 1) == 0)
        {
            setprogname(*ui + sizeof("progname=") - 1);
        }*/
        #endif

        /* Check to see if sudo was called as sudoedit or with -e flag. */
        if (strncmp(*ui, "sudoedit=", sizeof("sudoedit=") - 1) == 0)
        {
            if (strcasecmp(*ui + sizeof("sudoedit=") - 1, "true") == 0)
                use_sudoedit = true;
        }

        /* Plugin doesn't support running sudo with no arguments. */
        if (strncmp(*ui, "implied_shell=", sizeof("implied_shell=") - 1) == 0)
        {
            if (strcasecmp(*ui + sizeof("implied_shell=") - 1, "true") == 0)
                return -2; /* usage error */
        }
    }

    if (runas_user != NULL)
    {
        if ((pw = getpwnam(runas_user)) == NULL)
        {
            sudo_log(SUDO_CONV_ERROR_MSG, "unknown user %s\n", runas_user);
            return 0;
        }
        runas_uid = pw->pw_uid;
    }

    if (runas_group != NULL)
    {
        if ((gr = getgrnam(runas_group)) == NULL)
        {
            sudo_log(SUDO_CONV_ERROR_MSG, "unknown group %s\n", runas_group);
            return 0;
        }
        runas_gid = gr->gr_gid;
    }

    /* Plugin state. */
    plugin_state.envp = (char **)user_env;
    plugin_state.settings = settings;
    plugin_state.user_info = user_info;

    return 1;
}


/*
Sudo_close() is called when the command being run by sudo finishes.
*/
static void sudo_close (int exit_status, int error)
{
    /*
     * The policy might log the command exit status here.
     */
    if (error)
    {
        sudo_log(SUDO_CONV_ERROR_MSG, "Command error: %s\n", strerror(error));
    }
    else
    {
        if (WIFEXITED(exit_status))
        {
            sudo_log(SUDO_CONV_INFO_MSG, "Command exited with status %d\n",
            WEXITSTATUS(exit_status));
        }
        else if (WIFSIGNALED(exit_status))
        {
            sudo_log(SUDO_CONV_INFO_MSG, "Command killed by signal %d\n",
            WTERMSIG(exit_status));
        }
    }
}

/*
The show_version() function is called by sudo when the user specifies the -V option.
The plugin displays its version information to the user.
If the user requests detailed version information, the verbose flag will be set.
*/
static int sudo_show_version (int verbose)
{
    sudo_log(SUDO_CONV_INFO_MSG, "Policy plugin version %s\n", PACKAGE_VERSION);

    if (verbose)
    {
        sudo_log(SUDO_CONV_INFO_MSG, "Henrich Horváth <xhorvat4@fi.muni.cz>\n");
        sudo_log(SUDO_CONV_INFO_MSG, "Minimum authorized users: %d\nMaximum authorized users: %d\n", MIN_USERS, MAX_USERS);
        sudo_log(SUDO_CONV_INFO_MSG, "Conf file path: %s\n", PLUGIN_CONF_FILE);
    }

    return true;
}

/*
Function is called by sudo to determine whether the user is allowed to run the specified commands.
*/
static int sudo_check_policy (int argc, char * const argv[], char *env_add[], char **command_info[], char **argv_out[], char **user_env_out[])
{
    char *command;

    if (!argc || argv[0] == NULL)
    {
        sudo_log(SUDO_CONV_ERROR_MSG, "no command specified\n");
        return false;
    }

    if (!check_passwd(2))
        return false;

    command = find_in_path(argv[0], plugin_state.envp);
    if (command == NULL)
    {
        sudo_log(SUDO_CONV_ERROR_MSG, "%s: command not found\n", argv[0]);
        return false;
    }

    /* If "sudo vi" is run, auto-convert to sudoedit.  */
    //if (strcmp(command, _PATH_VI) == 0)
    //    use_sudoedit = true;

    if (use_sudoedit)
    {
        /* Rebuild argv using editor */
        free(command);
        command = find_editor(argc - 1, argv + 1, argv_out);
        if (command == NULL)
        {
            sudo_log(SUDO_CONV_ERROR_MSG, "unable to find valid editor\n");
            return -1;
        }
        use_sudoedit = true;
    }
    else
    {
        /* No changes needd to argv */
        *argv_out = (char **)argv;
    }

    /* No changes to envp */
    *user_env_out = plugin_state.envp;

    /* Setup command info. */
    *command_info = build_command_info(command);

    free(command);
    if (*command_info == NULL)
    {
        sudo_log(SUDO_CONV_ERROR_MSG, "out of memory\n");
        return -1;
    }

    return true;
}

/*
List available privileges for the invoking user. Returns 1 on success, 0 on failure and -1 on error.
*/
static int sudo_list (int argc, char * const argv[], int verbose, const char *list_user)
{
    //List user's capabilities.
    sudo_log(SUDO_CONV_INFO_MSG, "Validated users may run any command\n");
    return true;
}

struct policy_plugin sudo_policy = {
SUDO_POLICY_PLUGIN,
SUDO_API_VERSION,
sudo_open,
sudo_close,
sudo_show_version,
sudo_check_policy,
sudo_list,
NULL, /* validate */
NULL, /* invalidate */
NULL, /* init_session */
NULL, /* register_hooks */
NULL /* deregister_hooks */
};
