/*
* Copyright (c) 2010-2013 Todd C. Miller <Todd.Miller@courtesan.com>
*
* Permission to use, copy, modify, and distribute this software for any
* purpose with or without fee is hereby granted, provided that the above
* copyright notice and this permission notice appear in all copies.
*
* THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
* WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
* MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
* ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
* WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
* ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
* OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
*/

#define _GNU_SOURCE

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
#include <sudo_plugin.h>
#include <pwd.h>

#include <linux/limits.h>

#include <security/pam_appl.h>
#include <security/pam_misc.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

#include "sudo_helper.h"

#define PACKAGE_VERSION 0.1

static struct plugin_state plugin_state;
static sudo_conv_t sudo_conv;
static sudo_printf_t sudo_log;
static uid_t runas_uid;
static gid_t runas_gid;
static const char * runas_user = NULL;
static const char * runas_group = NULL;
static char * pwd;
static int use_sudoedit = false;

static char** get_users();
static int save_command(int argc, char * const argv[]);
static command_data * load_command(char * buffer);
static command_data * load_commands();
//static char** build_command_info(const char *command);
static int check_passwd(const char* user);
static int check_pam_result(int result);
static int execute(command_data * command);


/*
Reads user names from conf file
*/
static char** get_users()
{
    FILE *fp;
    char ** users;

    if ( (users = malloc( (MAX_USERS+1) * sizeof(char*))) == NULL)
    {
        sudo_log(SUDO_CONV_ERROR_MSG, "cannot not allocate data\n");
        return NULL;
    }
    users[MAX_USERS] = NULL;

    if ( (fp = fopen(PLUGIN_CONF_FILE, "r")) == NULL )
    {
        sudo_log(SUDO_CONV_ERROR_MSG, "%s not found\n", STR(PLUGIN_CONF_FILE));
        return NULL;
    }

    size_t usercount = 0;
    ssize_t len = 0;
    size_t buflen = 0;
    struct passwd *pw;
    //struct group *grp;
    char* buffer = NULL;

    // read new line
    while ( (len = getline(&buffer, &buflen, fp)) != -1 )
    {
            // remove new line character
            buffer[len - 1] = '\0';

            // ignore empty lines and comments
            if (len > 0 && buffer[0] != '#')
            {
                // maximum user count loaded
                if (usercount == MAX_USERS)
                {
                    fclose(fp);
                    free(buffer);
                    sudo_log(SUDO_CONV_ERROR_MSG, "too many users stored in %s (maximum is %d)\n", STR(PLUGIN_CONF_FILE), MAX_USERS);
                    free_2d(users, MAX_USERS);
                    return NULL;
                    //return users;
                }

                // parsing "user xxx"
                if (str_starts(buffer, "user ") && (size_t)len > strlen("user "))
                {
                    char user[MAX_USER_LENGTH + 1];
                    strcpy(user, buffer + strlen("user "));

                    // checks if user exists
                    if (getpwnam(user) == NULL)
                    {
                        sudo_log(SUDO_CONV_ERROR_MSG, "user %s not found\n", user);
                        continue;
                    }

                    // checks if user is already loaded
                    if (array_contains(user, users, usercount))
                    {
                        sudo_log(SUDO_CONV_ERROR_MSG, "found duplicate of user %s, skipping\n", user);
                        continue;
                    }

                    // save user name
                    users[usercount] = malloc( strlen(user) + 1 );
                    strcpy(users[usercount], user);

                    usercount++;
                }
                else if (str_starts(buffer, "uid ") && (size_t)len > strlen("uid ")) // parsing "uid 123"
                {
                    // get user id
                    char uid_str[MAX_NUM_LENGTH + 1];
                    strcpy(uid_str, buffer + strlen("uid "));

                    // get user struct
                    uid_t id = strtol(uid_str,NULL, 10);
                    pw = getpwuid(id);

                    if (pw == NULL)
                    {
                        sudo_log(SUDO_CONV_ERROR_MSG, "user with id %s not found\n", uid_str);
                        continue;
                    }

                    // checks if user is already loaded
                    if (array_contains(pw->pw_name, users, usercount))
                    {
                        sudo_log(SUDO_CONV_ERROR_MSG, "found duplicate of user %s, skipping\n", pw->pw_name);
                        continue;
                    }

                    // save user name
                    users[usercount] = malloc( strlen(pw->pw_name) + 1 );
                    strcpy(users[usercount], pw->pw_name);

                    usercount++;

                }
                /*else if (str_starts(buffer, "group ") && len > 6)
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
                        {
                            sudo_log(SUDO_CONV_ERROR_MSG, "found duplicate of user %s, skipping\n", grp->gr_mem[i]);
                            continue;
                        }

                        // save user name
                        users[usercount] = malloc( strlen(grp->gr_mem[i]) + 1 );
                        strcpy(users[usercount], grp->gr_mem[i]);

                        usercount++;
                    }
                }
                else if (str_starts(buffer, "gid ") && len > 4)
                {
                    // get group id
                    char gid_str[MAX_NUM_LENGTH + 1];
                    strcpy(gid_str, buffer+4); // strlen("gid ") == 4

                    // get group struct
                    gid_t id = strtol(gid_str, NULL, 10);
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
                        if (array_contains(grp->cs[i], users, usercount))
                        {
                            sudo_log(SUDO_CONV_ERROR_MSG, "found duplicate of user %s, skipping\n", grp->gr_mem[i]);
                            continue;
                        }

                        // save user name
                        users[usercount] = malloc( strlen(grp->gr_mem[i]) + 1 );
                        strcpy(users[usercount], grp->gr_mem[i]);

                        usercount++;
                    }
                }*/
            }
    }

    fclose(fp);
    free(buffer);

    // check if it loaded needed user count
    if (usercount < MIN_USERS)
    {
        free_2d(users, MAX_USERS);
        sudo_log(SUDO_CONV_ERROR_MSG, "not enough users set in %s (minimum is %d)\n", STR(PLUGIN_CONF_FILE) , MIN_USERS);
        return NULL;
    }
    else
    {
        return users;
    }
}

/*static char** build_command_info(const char *command)
{
    static char **command_info;
    int i = 0;

    command_info = calloc(32, sizeof(char *));

    if (command_info == NULL)
    {
        return NULL;
    }

    if ((command_info[i++] = formate_string("command", command)) == NULL ||
        asprintf(&command_info[i++], "runas_euid=%ld", (long)runas_uid) == -1 ||
        asprintf(&command_info[i++], "runas_uid=%ld", (long)runas_uid) == -1)
	{
        return NULL;
    }

    //if (runas_gid != -1)
    //{
        if (asprintf(&command_info[i++], "runas_gid=%ld", (long)runas_gid) == -1 ||
            asprintf(&command_info[i++], "runas_egid=%ld", (long)runas_gid) == -1)
	    {
            return NULL;
        }
    //}

    /*if (use_sudoedit)
    {
        command_info[i] = strdup("sudoedit=true");
        if (command_info[i++] == NULL)
            return NULL;
    }* /

    return command_info;
}*/

/*static char* find_editor(int nfiles, char * const files[], char **argv_out[])
{
    char *cp, **ep, **nargv, *editor, *editor_path;
    int ac, i, nargc, wasblank;

    // Lookup EDITOR in user's environment.
    editor = _PATH_VI;
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

    / *
     * Split editor into an argument vector; editor is reused (do not free).
     * The EDITOR environment variables may contain command
     * line args so look for those and alloc space for them too.
     *
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
    // If we can't find the editor in the user's PATH, give up.
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
}*/


/*-
Returns 1 on success, 0 on failure, -1 if a general error occurred, or -2 if there was a usage error.
In the latter case, sudo will print a usage message before it exits.
*/
static int sudo_open(unsigned int version, sudo_conv_t conversation, sudo_printf_t sudo_printf,
                        char * const settings[], char * const user_info[], char * const user_env[], char * const options[])
{
    char* const *ui;
    struct passwd *pw;
    struct group *gr;

    if (!sudo_conv)
        sudo_conv = conversation;
    if (!sudo_log)
        sudo_log = sudo_printf;

    if (SUDO_API_VERSION_GET_MAJOR(version) != SUDO_API_VERSION_MAJOR)
    {
        sudo_log(SUDO_CONV_ERROR_MSG, "this plugin requires API version %d.x\n", SUDO_API_VERSION_MAJOR);
        return -1;
    }

    /* Only allow commands to be run as root */
    for (ui = settings; *ui != NULL; ui++)
    {
        if (str_starts(*ui, "runas_user=")) //(strncmp(*ui, "runas_user=", sizeof("runas_user=") - 1) == 0)
        {
            runas_user = *ui + sizeof("runas_user=") - 1;
        }
        if (str_starts(*ui, "runas_group=")) //(strncmp(*ui, "runas_group=", sizeof("runas_group=") - 1) == 0)
        {
            runas_group = *ui + sizeof("runas_group=") - 1;
        }

        /*#if !defined(HAVE_GETPROGNAME) && !defined(HAVE___PROGNAME)
        if (strncmp(*ui, "progname=", sizeof("progname=") - 1) == 0)
        {
            setprogname(*ui + sizeof("progname=") - 1);
        }
        #endif*/

        // Check to see if sudo was called as sudoedit or with -e flag
        if (str_starts(*ui, "sudoedit="))  //(strncmp(*ui, "sudoedit=", sizeof("sudoedit=") - 1) == 0)
        {
            if (strcasecmp(*ui + sizeof("sudoedit=") - 1, "true") == 0)
                use_sudoedit = true;
        }

        /* Plugin doesn't support running sudo with no arguments. */
        if (str_starts(*ui, "implied_shell=")) //(strncmp(*ui, "implied_shell=", sizeof("implied_shell=") - 1) == 0)
        {
            if (strcasecmp(*ui + sizeof("implied_shell=") - 1, "true") == 0)
                return -2;
        }
    }

    if (runas_user != NULL)
    {
        if ((pw = getpwnam(runas_user)) == NULL)
        {
            sudo_log(SUDO_CONV_ERROR_MSG, "unknown user %s\n", runas_user);
            return -1;
        }
        runas_uid = pw->pw_uid;
    }

    if (runas_group != NULL)
    {
        if ((gr = getgrnam(runas_group)) == NULL)
        {
            sudo_log(SUDO_CONV_ERROR_MSG, "unknown group %s\n", runas_group);
            return -1;
        }
        runas_gid = gr->gr_gid;
    }

    /* Plugin state */
    plugin_state.envp = (char **)user_env;
    plugin_state.settings = settings;
    plugin_state.user_info = user_info;

    /* Create plugin directory in /etc */
    struct stat st = {0};

    if (stat(PLUGIN_DATA_DIR, &st) == -1)
    {
        mkdir(PLUGIN_DATA_DIR, 0700);
    }

    return 1;
}


/*
Sudo_close() is called when the command being run by sudo finishes.
*/
static void sudo_close (int exit_status, int error)
{
    /* The policy might log the command exit status here. */
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
    sudo_log(SUDO_CONV_INFO_MSG, PLUGIN_NAME);
    sudo_log(SUDO_CONV_INFO_MSG, "\nPackage version %s\n", STR(PACKAGE_VERSION));

    //if (verbose)
    {
        sudo_log(SUDO_CONV_INFO_MSG, "Conf file path: %s\n", STR(PLUGIN_CONF_FILE));
        sudo_log(SUDO_CONV_INFO_MSG, "Authorities:\n");

        char ** users = get_users();
        int i = 0;

        if (users == NULL)
            return true;

        while (users[i] != NULL)
        {
            sudo_log(SUDO_CONV_INFO_MSG, users[i]);
            sudo_log(SUDO_CONV_INFO_MSG, "\n");
            i++;
        }

        free_2d_null(users);
    }

    return true;
}

/*
Save sudo commands to file
*/
/*static int save_command_b(int argc, char * const argv[])
{
    FILE * fp;

    if ( (fp = fopen(PLUGIN_COMMANDS_LIST_FILE, "wb")) == NULL )
    {
        sudo_log(SUDO_CONV_ERROR_MSG, "could not open %s\n", STR(PLUGIN_COMMANDS_LIST_FILE));
        return false;
    }

    fwrite(argv, sizeof(char), (argc+1) * sizeof(argv), fp);
    fclose(fp);

    return true;
}*/

/*static char** load_commands_b()
{
    FILE * fp;
    char ** commands = NULL;
    int i, size;

    if ( (fp = fopen(PLUGIN_COMMANDS_LIST_FILE, "rb")) == NULL )
    {
        sudo_log(SUDO_CONV_ERROR_MSG, "could not open %s\n", STR(PLUGIN_COMMANDS_LIST_FILE));
        return NULL;
    }

    fseek(fp, 0, SEEK_END);
    size = ftell(fp);
    fseek(fp, 0, SEEK_SET);

    commands = (char**) malloc(size * sizeof(char*));

    fread(commands, sizeof(char*), sizeof(commands), fp);
    fclose(fp);

    return commands;
}*/

static int save_command(int argc, char * const argv[])
{
    FILE * fp;
    char * str = NULL;

    if ( (fp = fopen(PLUGIN_COMMANDS_LIST_FILE, "a")) == NULL )
    {
        sudo_log(SUDO_CONV_ERROR_MSG, "could not open %s\n", STR(PLUGIN_COMMANDS_LIST_FILE));
        return false;
    }

    for (int i = 0; i < argc; ++i)
    {
        /*char str [ strlen(argv[i])+2+1 ];
        strcpy(str, "\"");
        strcat(str, argv[i]);
        strcat(str, "\"");*/

        if ( asprintf(&str, "\"%s\" ", argv[i]) < 0 || fputs(str, fp) == EOF )
        {
            fclose(fp);
            return false;
        }

        free(str);
    }

    if (runas_user == NULL)
        runas_user = strdup("");

    if (runas_group == NULL)
        runas_group = strdup("");

    if ( asprintf(&str, "\nrunas_user=%s ", runas_user) < 0 || fputs(str, fp) == EOF ||
         asprintf(&str, "runas_group=%s\n",  runas_group) < 0 || fputs(str, fp) == EOF )
    {
        fclose(fp);
        return false;
    }

    fclose(fp);
    return true;
}

/*
Saves already authorized users
*/
/*static int save_authorization(const char user[])
{
    FILE *fp;

    if ( (fp = fopen(PLUGIN_AUTH_USERS_FILE, "a")) == NULL )
    {
        sudo_log(SUDO_CONV_ERROR_MSG, "could not open %s\n", STR(PLUGIN_COMMANDS_LIST_FILE));
        return false;
    }

    char user_str [strlen(user) + 2];

    strcpy(user_str, user);
    strcat(user_str, "\n");

    if ( fputs(user_str, fp) == EOF )
    {
        fclose(fp);
        return false;
    }

    fclose(fp);
    return true;
}*/

/*
Checks if user has not authorized sudo commands
*/
/*static int check_authorization(const char user[])
{
    FILE *fp;
    char* buffer = NULL;
    size_t buflen = 0;
    int len;

    if ( (fp = fopen(PLUGIN_AUTH_USERS_FILE, "r")) == NULL )
        return true;

    while (len = getline(&buffer, &buflen, fp) != -1)
    {
        if (strncmp(buffer, user, len-1) == 0)
        {
            fclose(fp);
            free(buffer);
            return false;
        }
    }

    fclose(fp);
    free(buffer);
    return true;
}*/

/*
Parse line and load command
*/
static command_data * load_command(char * buffer)
{
    char * first;
    char * last;
    char ** backup;
    char fst = true;
    size_t size = 2;
    command_data * command;

    if ( (command = malloc( sizeof(command_data) )) == NULL )
    {
        return NULL;
    }

    if ( (command->argv = malloc( size * sizeof(char*) )) == NULL )
    {
        free(command);
        return NULL;
    }

    /* Find file */
    if ( (first = strchr(buffer, '"')) == NULL || (last = strchr(first+1, '"')) == NULL )
    {
        free(command);
        return NULL;
    }

    first[last-first] = '\0';
    first++;

    command->file = find_in_path(first, plugin_state.envp);
    command->argv[0] = strdup(first);

    buffer = last + 1;

    /* Find arguments */
    while ( (first = strchr(buffer, '"')) != NULL && (last = strchr(first+1, '"')) != NULL )
    {
        first[last-first] = '\0';
        first++;

        /* Space between arguments */
        if (strcmp(first," ") == 0)
        {
            buffer = last + 1;
            continue;
        }

        size++;

        if ( (backup = realloc(command->argv, size * sizeof(char*) )) == NULL )
        {
            free_command(command);
            return NULL;
        }

        command->argv = backup;
        command->argv[size-2] = strdup(first);

        buffer = last + 1;
    }

    command->argv[size-1] = NULL;

    command->runas_uid = NULL;
    command->runas_gid = NULL;

    return command;
}

/*
Load stored sudo commands from file
*/
static command_data * load_commands()
{
    FILE * fp;
    command_data ** cmds;
    command_data ** more_cmds;
    size_t count = 1;
    ssize_t len = 0;
    size_t buflen = 0;
    char * buffer = NULL;
    char even = false;

    if ( (cmds = malloc( count * sizeof(command_data*) )) == NULL )
    {
        sudo_log(SUDO_CONV_ERROR_MSG, "cannot allocate data\n");
        return NULL;
    }

    if ( (fp = fopen(PLUGIN_COMMANDS_LIST_FILE, "r")) == NULL )
    {
        sudo_log(SUDO_CONV_ERROR_MSG, "cannot open %s\n", STR(PLUGIN_COMMANDS_LIST_FILE));
        return NULL;
    }

    /* Read line */
    while ( (len = getline(&buffer, &buflen, fp)) != -1 )
    {
        /* Remove new line character */
        buffer[len - 1] = '\0';
        len--;

        /* Event line, load envp */
        if (even)
        {
            char * token = strtok(buffer, " ");

            if (strlen(token) > strlen("runas_user="))
                cmds[count -2]->runas_uid = strdup(token + strlen("runas_user="));

            token = strtok(NULL, " ");

            if (strlen(token) > strlen("runas_group="))
                cmds[count -2]->runas_gid = strdup(token + strlen("runas_group="));
        }

        count++;

        /* Resize commands array */
        if ( (more_cmds = realloc(cmds, count * sizeof(command_data*))) == NULL )
        {
            sudo_log(SUDO_CONV_ERROR_MSG, "cannot allocate data\n");
            for (ssize_t j = 0; j < count - 1; ++j)
            {
                free_command(cmds[j]);
            }
            free(buffer);
            fclose(fp);
            return NULL;
        }

        cmds = more_cmds;

        cmds[count -2] = load_command(buffer);

        even = !even;
    }

    cmds[count-1] = NULL;

    free(buffer);
    fclose(fp);

    return cmds;
}

/*
Error checking for PAM
*/
static int check_pam_result(int result)
{
    switch (result)
    {
        case PAM_SUCCESS:
            return true;

        case PAM_ABORT:
            sudo_log(SUDO_CONV_ERROR_MSG, "critical error\n");
            return false;

        case PAM_ACCT_EXPIRED:
            sudo_log(SUDO_CONV_ERROR_MSG, "user account has expired\n");
            return false;

        case PAM_AUTH_ERR:
            sudo_log(SUDO_CONV_ERROR_MSG, "the user was not authenticated\n");
            return false;

        case PAM_AUTHINFO_UNAVAIL:
            sudo_log(SUDO_CONV_ERROR_MSG, "the modules were not able to access the authentication information\n");
            return false;

        case PAM_BUF_ERR:
            sudo_log(SUDO_CONV_ERROR_MSG, "memory buffer error\n");
            return false;

        case PAM_CONV_ERR:
            sudo_log(SUDO_CONV_ERROR_MSG, "conversation failure\n");
            return false;

        case PAM_CRED_INSUFFICIENT:
            sudo_log(SUDO_CONV_ERROR_MSG, "insufficient credentials to access authentication data\n");
            return false;

        case PAM_MAXTRIES:
            sudo_log(SUDO_CONV_ERROR_MSG, "one or more of the authentication modules has reached its limit of tries authenticating the user. Do not try again\n");
            return false;

        case PAM_NEW_AUTHTOK_REQD:
            sudo_log(SUDO_CONV_ERROR_MSG, "authentication token expired\n");
            return false;

        case PAM_PERM_DENIED :
            sudo_log(SUDO_CONV_ERROR_MSG, "permission denied\n");
            return false;

        case PAM_SYSTEM_ERR:
            sudo_log(SUDO_CONV_ERROR_MSG, "system error\n");
            return false;

        case PAM_USER_UNKNOWN:
            sudo_log(SUDO_CONV_ERROR_MSG, "user unknown to authentication service\n");
            return false;

        default:
            sudo_log(SUDO_CONV_ERROR_MSG, "unknown PAM error\n");
            return false;
    }
}

/*
Authorize user via PAM
*/
static int check_passwd(const char* user) // PAM zatim nefunguje (PAM_AUTH_ERR)
{                                         // https://www.redhat.com/archives/pam-list/2004-November/msg00038.html
    return true;
    /*struct sudo_conv_message msg;
    struct sudo_conv_reply repl;
    char message[MAX_USER_LENGTH + 11];

    strcpy(message, user);
    strcat(message, " password:");

    memset(&msg, 0, sizeof(msg));
    //msg.msg_type = SUDO_CONV_PROMPT_ECHO_OFF;
    msg.msg_type = SUDO_CONV_PROMPT_ECHO_ON; // testing
    msg.msg = message;

    /* Show message * /
    memset(&repl, 0, sizeof(repl));
    sudo_conv(1, &msg, &repl);*/

    struct pam_conv pamc;
    pam_handle_t * pamh = NULL;

    pamc.conv = &misc_conv;
    pamc.appdata_ptr = NULL;

    /* Initialize PAM */
    int result = pam_start("sudo-security-plugin", user, &pamc, &pamh);
    sudo_log(SUDO_CONV_ERROR_MSG, "pam_start: %d\n",result);

    if (!check_pam_result(result))
    {
        pam_end(pamh, result);
        return false;
    }

    /*pwd = repl.reply;

    if ((reply = (struct pam_response *) malloc(sizeof(struct pam_response))) == NULL)
        return false;

    reply[0].resp = strdup(pwd);
    reply[0].resp_retcode = 0;

    pam_set_item(pamh, PAM_AUTHTOK, strdup(pwd));*/

    /* Authenticate user  */
    result = pam_authenticate(pamh, 0);  // user have to be password protected
    sudo_log(SUDO_CONV_ERROR_MSG, "pam_authenticate: %d\n",result);

    if (!check_pam_result(result))
    {
        pam_end(pamh, result);
        return false;
    }

    /* Check for account validation */
    result = pam_acct_mgmt(pamh, 0);
    sudo_log(SUDO_CONV_ERROR_MSG, "pam_acct_mgmt: %d\n",result);

    if (!check_pam_result(result))
    {
        pam_end(pamh, result);
        return false;
    }

    pam_end(pamh, result);
    return true;
}

/*
Execute command
*/
static int execute(command_data * command)
{
    pid_t pid;
    int status;

    if ((pid = fork()) < 0) /* fork a child process           */
    {
        sudo_log(SUDO_CONV_ERROR_MSG, "forking child process failed\n");
        return false;
    }
    else if (pid == 0) /* for the child process:         */
    {
        if (execvp(command->file, command->argv) < 0) /* execute the command  */
        {
            sudo_log(SUDO_CONV_ERROR_MSG, "exec failed\n");
            return false;
        }
    }
    else    /* for the parent:      */
    {
        while (wait(&status) != pid);       /* wait for completion  */
    }
    return true;
}

/*
Print command with arguments
*/
static void print_command(command_data * command)
{
    int i = 0;

    while (command->argv[i] != NULL)
    {
        sudo_log(SUDO_CONV_INFO_MSG, command->argv[i]);
        sudo_log(SUDO_CONV_INFO_MSG, " ");
        i++;
    }

    sudo_log(SUDO_CONV_INFO_MSG, "\n");
}

/*
Function is called by sudo to determine whether the user is allowed to run the specified commands.
*/
static int sudo_check_policy(int argc, char * const argv[], char *env_add[], char **command_info[], char **argv_out[], char **user_env_out[])
{
    if (!argc || argv[0] == NULL)
    {
        sudo_log(SUDO_CONV_ERROR_MSG, "no command specified\n");
        return -1;
    }

    if (argc > 0 && strcmp(argv[0],"apply-all") == 0)
    {
        char ** users = get_users();
        int i = 0;

        /* No authorized users found */
        if (users == NULL)
        {
            sudo_log(SUDO_CONV_ERROR_MSG, "no users set in %s\n", STR(PLUGIN_CONF_FILE));
            return -1;
        }

        command_data ** commands = load_commands();

        /* No commands found */
        if (commands == NULL)
        {
            sudo_log(SUDO_CONV_ERROR_MSG, "no commands found\n");
            return -1;
        }

        /* Print commands */
        sudo_log(SUDO_CONV_INFO_MSG, "Commands to run:\n");
        while (commands[i] != NULL)
        {
            print_command(commands[i]);
            i++;
        }

        i = 0;

        /* Authenticate all users */
        while (users[i] != NULL)
        {
            /*if (! check_authorization(user_name))
            {
                sudo_log(SUDO_CONV_ERROR_MSG, "user %s already authorized sudo commands\n", user_name);
                return -1;
            }*/

            if (!check_passwd(users[i]))
            {
                i = 0;
                while (commands[i] != NULL)
                {
                    sudo_log(SUDO_CONV_INFO_MSG, "free:%d\n", i);
                    free_command(commands[i]);
                    i++;
                }
                free_2d_null(users);
                return -1;
            }

            i++;
        }

        i = 0;

        /* Run commands */
        while (commands[i] != NULL)
        {
            if (!execute(commands[i]))
            {
                sudo_log(SUDO_CONV_ERROR_MSG, "error\n");
                break;
            }

            i++;
        }

        remove(PLUGIN_COMMANDS_LIST_FILE);
        remove(PLUGIN_AUTH_USERS_FILE);

        i = 0;
        while (commands[i] != NULL)
        {
            free_command(commands[i]);
            i++;
        }
        free_2d_null(users);

        return 0;
    }
    else if (argc > 0 && strcmp(argv[0], "reset-all") == 0)
    {
        int i = 0;
        char ** users = get_users();

        /* No authorized users found */
        if (users == NULL)
        {
            sudo_log(SUDO_CONV_ERROR_MSG, "no users set in %s\n", STR(PLUGIN_CONF_FILE));
            return -1;
        }

        command_data ** commands = load_commands();

        /* No commands found */
        if (commands == NULL)
        {
            sudo_log(SUDO_CONV_ERROR_MSG, "no commands found\n");
            return -1;
        }

        /* Print commands */
        sudo_log(SUDO_CONV_INFO_MSG, "Commands to run:\n");
        while (commands[i] != NULL)
        {
            print_command(commands[i]);
            i++;
        }

        i = 0;

        /* Authenticate all users */
        while (users[i] != NULL)
        {
            /*if (! check_authorization(user_name))
            {
                sudo_log(SUDO_CONV_ERROR_MSG, "user %s already authorized sudo commands\n", user_name);
                return -1;
            }*/

            if (!check_passwd(users[i]))
            {
                i = 0;
                while (commands[i] != NULL)
                {
                    free_command(commands[i]);
                    i++;
                }
                free_2d_null(users);
                return -1;
            }

            i++;
        }

        remove(PLUGIN_COMMANDS_LIST_FILE);
        remove(PLUGIN_AUTH_USERS_FILE);

        i = 0;
        while (commands[i] != NULL)
        {
            free_command(commands[i]);
            i++;
        }
        free_2d_null(users);
        return 0;
    }
    else
    {
        char * path;

        if ((path = find_in_path(argv[0],plugin_state.envp)) == NULL)
        {
            free(path);
            return -2;
        }
        free(path);

        if (save_command(argc, argv))
        {
            sudo_log(SUDO_CONV_INFO_MSG, "Commands saved\nRun all saved sudo commands by: sudo apply-all\nRemove all saved sudo commands by: sudo reset-all\n");
            return 0;
        }
        else
        {
            sudo_log(SUDO_CONV_ERROR_MSG, "error while saving commands\n");
            return -1;
        }
    }
}

/*
List available privileges for the invoking user. Returns 1 on success, 0 on failure and -1 on error.
*/
static int sudo_list(int argc, char * const argv[], int verbose, const char *list_user)
{
    sudo_log(SUDO_CONV_INFO_MSG, "All commands have to be allowed by selected authorities.\n");

    /* Write authorities list */
    if (verbose)
    {
        sudo_log(SUDO_CONV_INFO_MSG, "Authorities:\n");

        char ** users = get_users();
        int i = 0;

        if (users == NULL)
            return true;

        while (users[i] != NULL)
        {
            sudo_log(SUDO_CONV_INFO_MSG, users[i]);
            sudo_log(SUDO_CONV_INFO_MSG, "\n");
            i++;
        }

        free_2d_null(users);
    }
    return true;
}

struct policy_plugin sudoers_policy = {
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
