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
static char * user;
static char * pwd;
static char * cwd;
static int use_sudoedit = false;


static void print_command(command_data * command, int full);

static char ** load_users();

static command_data * load_command_line(char * buffer);
static int load_command_environment(char * buffer, command_data * cmd);
static command_data * load_commands(const char * file);
static int save_command(command_data * command, const char * file);

static int check_authorization(const char * user, const char * file);
static int save_authorization(const char * user, const char * file);

static int check_passwd(const char* user);
static int check_pam_result(int result);

static char ** build_envp(command_data * command);
static int execute(command_data * command);

/*
Prints command with arguments
*/
static void print_command(command_data * command, int full)
{
    char ** argv;
    argv = command->argv;

    while (*argv != NULL)
    {
        sudo_log(SUDO_CONV_INFO_MSG, *argv);
        sudo_log(SUDO_CONV_INFO_MSG, " ");
        argv++;
    }

    if (full)
    {
        sudo_log(SUDO_CONV_INFO_MSG, "\nuser:%s group:%s\n", command->runas_uid, command->runas_gid);
        sudo_log(SUDO_CONV_INFO_MSG, "user:%s home:%s pwd:%s\n", command->user, command->home, command->pwd);

    }
    else
    {
        sudo_log(SUDO_CONV_INFO_MSG, "\n");
    }
}

/*
Reads user names from conf file
*/
static char ** load_users()
{
    FILE * fp;
    char ** users;

    if ( (users = malloc( (MAX_USERS+1) * sizeof(char*))) == NULL)
    {
        sudo_log(SUDO_CONV_ERROR_MSG, "cannot allocate data\n");
        return NULL;
    }
    users[MAX_USERS] = NULL;

    if ( (fp = fopen(PLUGIN_CONF_FILE, "r")) == NULL )
    {
        sudo_log(SUDO_CONV_ERROR_MSG, "%s not found\n", STR(PLUGIN_CONF_FILE));
        free(users);
        return NULL;
    }

    size_t usercount = 0;
    ssize_t len = 0;
    size_t buflen = 0;
    struct passwd *pw;
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
                    char user_name[MAX_USER_LENGTH + 1];
                    strcpy(user_name, buffer + strlen("user "));

                    // checks if user exists
                    if (getpwnam(user_name) == NULL)
                    {
                        sudo_log(SUDO_CONV_ERROR_MSG, "user %s not found\n", user);
                        continue;
                    }

                    // checks if user is already loaded
                    if (array_contains(user_name, users, usercount))
                    {
                        sudo_log(SUDO_CONV_ERROR_MSG, "found duplicate of user %s, skipping\n", user_name);
                        continue;
                    }

                    // save user name
                    users[usercount] = malloc( strlen(user_name) + 1 );
                    strcpy(users[usercount], user_name);

                    usercount++;
                }
                else if (str_starts(buffer, "uid ") && (size_t)len > strlen("uid ")) // parsing "uid 123"
                {
                    // get user id
                    char user_id[MAX_NUM_LENGTH + 1];
                    strcpy(user_id, buffer + strlen("uid "));

                    // get user struct
                    uid_t id = strtol(user_id, NULL, 10);
                    pw = getpwuid(id);

                    if (pw == NULL)
                    {
                        sudo_log(SUDO_CONV_ERROR_MSG, "user with id %s not found\n", user_id);
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

/*
Builds envp array for exec
*/
static char ** build_envp(command_data * command)
{
    static char ** envp;
    int i = 0;

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

    if ( (envp = malloc(5 * sizeof(char *))) == NULL )
    {
        return NULL;
    }

    if (asprintf(&envp[i++], "USER=%s", command->user) == -1 ||
        asprintf(&envp[i++], "HOME=%s", command->home) == -1 ||
        asprintf(&envp[i++], "PATH=%s", command->path) == -1 ||
        asprintf(&envp[i++], "PWD=%s", command->pwd ) == -1)
    {
        free_2d(envp, i-1);
        return NULL;
    }
    envp[i] = NULL;

    return envp;
}

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
            break;
        }
        if (str_starts(*ui, "runas_group=")) //(strncmp(*ui, "runas_group=", sizeof("runas_group=") - 1) == 0)
        {
            runas_group = *ui + sizeof("runas_group=") - 1;
            break;
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

    /* Only allow commands to be run as root */
    for (ui = user_info; *ui != NULL; ui++)
    {
        if (str_starts(*ui, "user="))
        {
            user = *ui + sizeof("user=") - 1;
            break;
        }
        if (str_starts(*ui, "cwd="))
        {
            cwd = *ui + sizeof("cwd=") - 1;
            break;
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

    if (verbose)
    {
        sudo_log(SUDO_CONV_INFO_MSG, "Conf file path: %s\n", STR(PLUGIN_CONF_FILE));
        sudo_log(SUDO_CONV_INFO_MSG, "Authorities:\n");

        char ** users = load_users();
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
Save command to file
*/
static int save_command(command_data * command, const char * file)
{
    FILE * fp;
    char * str = NULL;
    char ** argv;

    if ( (fp = fopen(file, "a")) == NULL )
    {
        return false;
    }

    for (argv = command->argv; *argv != NULL; argv++)
    {
        if ( asprintf(&str, "\"%s\" ", *argv) < 0 || fputs(str, fp) == EOF )
        {
            free(str);
            fclose(fp);
            return false;
        }
        free(str);
    }

    if (command->runas_uid == NULL)
        str = strdup("\n\"\" ");
    else
        asprintf(&str, "\n\"%s\" ", command->runas_uid);

    if (fputs(str, fp) == EOF)
    {
        free(str);
        fclose(fp);
        return false;
    }
    free(str);

    if (command->runas_gid == NULL)
        str = strdup("\"\" ");
    else
        asprintf(&str, "\"%s\" ", command->runas_gid);

    if (fputs(str, fp) == EOF)
    {
        free(str);
        fclose(fp);
        return false;
    }
    free(str);

    if (asprintf(&str, "\"%s\" ", command->user) < 0 || fputs(str, fp) == EOF)
    {
        free(str);
        fclose(fp);
        return false;
    }
    free(str);

    if (asprintf(&str, "\"%s\" ", command->home) < 0 || fputs(str, fp) == EOF)
    {
        free(str);
        fclose(fp);
        return false;
    }
    free(str);

    if (asprintf(&str, "\"%s\" ", command->path) < 0 || fputs(str, fp) == EOF)
    {
        free(str);
        fclose(fp);
        return false;
    }
    free(str);

    if (asprintf(&str, "\"%s\"\n", command->pwd) < 0 || fputs(str, fp) == EOF)
    {
        free(str);
        fclose(fp);
        return false;
    }
    free(str);

    fclose(fp);
    return true;
}

/*
Saves already authorized users
*/
static int save_authorization(const char * user, const char * file)
{
    FILE * fp;
    char * user_str = NULL;

    if ( (fp = fopen(file, "a")) == NULL ||
         asprintf(&user_str, "%s\n", user) < 0 ||
         fputs(user_str, fp) == EOF )
    {
        fclose(fp);
        return false;
    }

    free(user_str);
    fclose(fp);
    return true;
}

/*
Checks if user has not authorized sudo commands yet
Returns user count or -1 if current user is alreadyin file
*/
static int check_authorization(const char * user, const char * file)
{
    FILE * fp;
    char * buffer = NULL;
    size_t buflen = 0;
    ssize_t len;
    int lines = 0;

    ///TODO load_users()
    char ** users = load_users();
    if (! array_contains(user, users, MAX_USERS))
    {
        free_2d(users, MAX_USERS);
        return -2;
    }
    free_2d(users, MAX_USERS);

    if ( (fp = fopen(file, "r")) == NULL )
        return 0;

    while ( (len = getline(&buffer, &buflen, fp)) != -1 )
    {
        if (strncmp(buffer, user, len-1) == 0)
        {
            fclose(fp);
            free(buffer);
            return -1;
        }
        lines++;
    }

    fclose(fp);
    free(buffer);
    return lines;
}

/*
Parse line and load command
*/
static command_data * load_command_line(char * buffer)
{
    char * first;
    char * last;
    char ** backup;
    char fst = true;
    size_t size = 2;
    command_data * command;

    if ( (command = make_command()) == NULL )
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

    return command;
}

/*
Parse line and load command
*/
static int load_command_environment(char * buffer, command_data * cmd)
{
            char * token;

            /* runas_uid */

            if ((token = strtok(buffer, " ")) == NULL)
                return false;

            if (strcmp(token, "\"\"") != 0)
                cmd->runas_uid = pure_string(token);

            /* runas_gid */

            if ((token = strtok(NULL, " ")) == NULL)
                return false;

            if (strcmp(token, "\"\"") != 0)
                cmd->runas_gid = pure_string(token);

            /* USER */

            if ((token = strtok(NULL, " ")) == NULL)
                return false;

            cmd->user = pure_string(token);

            /* HOME */

            if ((token = strtok(NULL, " ")) == NULL)
                return false;

            cmd->home = pure_string(token);

            /* PATH */

            if ((token = strtok(NULL, " ")) == NULL)
                return false;

            cmd->path = pure_string(token);

            /* PWD */

            if ((token = strtok(NULL, " ")) == NULL)
                return false;

            cmd->pwd = pure_string(token);

            return true;
}

/*
Load stored sudo commands from file
*/
static command_data * load_commands(const char * file)
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

    cmds[0] = NULL;

    if ( (fp = fopen(file, "r")) == NULL )
    {
        return cmds;
    }

    /* Read line */
    while ( (len = getline(&buffer, &buflen, fp)) != -1 )
    {
        /* Remove new line character */
        buffer[len - 1] = '\0';
        len--;

        /* Event line, load environment */
        if (even)
        {
            if (! load_command_environment(buffer, cmds[count-2]))
            {
                free_command(cmds[count-2]);
                even = !even;
                count--;
                continue;
            }
        }
        else
        {
            count++;

            /* Resize commands array */
            if ( (more_cmds = realloc(cmds, count * sizeof(command_data*))) == NULL )
            {
                sudo_log(SUDO_CONV_ERROR_MSG, "cannot allocate data\n");
                free_commands_null(cmds);
                free(buffer);
                fclose(fp);
                return NULL;
            }

            cmds = more_cmds;
            if ((cmds[count-2] = load_command_line(buffer)) == NULL)
            {
                count--;
                continue;
            }
            cmds[count -1] = NULL;
        }

        even = !even;
    }

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

    if ((pid = fork()) < 0) /* fork a child process */
    {
        return false;
    }
    else if (pid == 0) /* for the child process: */
    {
        char ** envp = build_envp(command);
        chdir(command->pwd);

        /* execute the command  */
        if (execve(command->file, &command->argv[0], &envp[0]) < 0)
        {
            free_2d_null(envp);
            return false;
        }

        free_2d_null(envp);
        return true;
    }
    else /* for the parent  */
    {
        while (wait(&status) != pid)  /* wait for completion  */
            ;
    }
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

    if ((argc > 0) && (strcmp(argv[0],"apply-all") == 0 || strcmp(argv[0], "aa") == 0))
    {
        int i = 0, count;
        command_data ** cmds_all = load_commands(PLUGIN_COMMANDS_ALL);
        command_data ** cmds_apply = load_commands(PLUGIN_COMMANDS_APPLY);
        command_data ** cmds_run;

        /* Run commands from PLUGIN_COMMANDS_ALL or PLUGIN_COMMANDS_APPLY? */
        if (cmds_apply == NULL || cmds_apply[0] == NULL)
            cmds_run = cmds_all;
        else
            cmds_run = cmds_apply;

        /* No commands found */
        if (cmds_run == NULL || cmds_run[0] == NULL)
        {
            sudo_log(SUDO_CONV_ERROR_MSG, "no commands found\n");
            free_commands_null(cmds_all);
            free_commands_null(cmds_apply);
            return -1;
        }

        /* Print commands */
        sudo_log(SUDO_CONV_INFO_MSG, "Commands to run:\n");
        while (cmds_run[i] != NULL)
        {
            print_command(cmds_run[i], false);
            i++;
        }

        count = check_authorization(user, PLUGIN_APPLY_AUTH_FILE);

        if ( count == -1 )
        {
            sudo_log(SUDO_CONV_ERROR_MSG, "you have already authorized to run sudo commands\n");
            free_commands_null(cmds_all);
            free_commands_null(cmds_apply);
            return -1;
        }
        if ( count == -2 )
        {
            sudo_log(SUDO_CONV_ERROR_MSG, "you do not have permissions to run sudo commands\n");
            free_commands_null(cmds_all);
            free_commands_null(cmds_apply);
            return -1;
        }

        /* Authenticate user */
        if (! check_passwd(user))
        {
            free_commands_null(cmds_all);
            free_commands_null(cmds_apply);
            return -1;
        }

        sudo_log(SUDO_CONV_INFO_MSG, "\n");

        /* Run all commands */
        if (count == MAX_USERS - 1)
        {
            sudo_log(SUDO_CONV_INFO_MSG, "User %d/%d authorized.\n", count+1, MAX_USERS);

            remove(PLUGIN_COMMANDS_ALL);
            remove(PLUGIN_COMMANDS_APPLY);
            remove(PLUGIN_COMMANDS_CLEAR);

            remove(PLUGIN_APPLY_AUTH_FILE);
            remove(PLUGIN_CLEAR_AUTH_FILE);

            int offset = cmp_command(cmds_all, cmds_run);

            if (offset > 0)
            {
                while (cmds_all[offset] != NULL)
                {
                    save_command(cmds_all[offset], PLUGIN_COMMANDS_ALL);
                    offset++;
                }
            }

            i = 0;
            while (cmds_run[i] != NULL)
            {
                if (! execute(cmds_run[i]))
                {
                    /* Error in executing command, stopping execution of all commands */
                    sudo_log(SUDO_CONV_ERROR_MSG, "cannot execute command ");
                    print_command(cmds_run[i], false);

                    /* Save all commands, that havent been executed */
                    while (cmds_run[i] != NULL)
                    {
                        save_command(cmds_run[i], PLUGIN_COMMANDS_APPLY);
                        i++;
                    }
                    break;
                }
                i++;
            }
        }
        else
        {
            if (save_authorization(user, PLUGIN_APPLY_AUTH_FILE))
            {
                /* Saves all authorized commands */
                i = 0;
                while (cmds_all[i] != NULL)
                {
                    save_command(cmds_all[i], PLUGIN_COMMANDS_APPLY);  /// error handling
                    i++;
                }
                sudo_log(SUDO_CONV_INFO_MSG, "User %d/%d authorized.\n", count+1, MAX_USERS);
            }
            else
            {
                sudo_log(SUDO_CONV_ERROR_MSG, "cannot save authorization information to %s\n", STR(PLUGIN_APPLY_AUTH_FILE));
            }
        }

        free_commands_null(cmds_all);
        free_commands_null(cmds_apply);
        return 0;
    }

    else if ((argc > 0) && (strcmp(argv[0],"clear-all") == 0 || strcmp(argv[0], "ca") == 0))
    {
        int i = 0, count;
        command_data ** cmds_all = load_commands(PLUGIN_COMMANDS_ALL);
        command_data ** cmds_clear = load_commands(PLUGIN_COMMANDS_CLEAR);
        command_data ** cmds_run;

        /* Run commands from PLUGIN_COMMANDS_ALL or PLUGIN_COMMANDS_CLEAR? */
        if (cmds_clear == NULL || cmds_clear[0] == NULL)
            cmds_run = cmds_all;
        else
            cmds_run = cmds_clear;

        /* No commands found */
        if (cmds_run == NULL || cmds_run[0] == NULL)
        {
            sudo_log(SUDO_CONV_ERROR_MSG, "no commands found\n");
            free_commands_null(cmds_all);
            free_commands_null(cmds_clear);
            return -1;
        }

        /* Print commands */
        sudo_log(SUDO_CONV_INFO_MSG, "Commands to clear:\n");
        while (cmds_run[i] != NULL)
        {
            print_command(cmds_run[i], false);
            i++;
        }

        count = check_authorization(user, PLUGIN_CLEAR_AUTH_FILE);

        if ( count == -1 )
        {
            sudo_log(SUDO_CONV_ERROR_MSG, "you have already authorized to clear sudo commands\n");
            free_commands_null(cmds_all);
            free_commands_null(cmds_clear);
            return -1;
        }
        if ( count == -2 )
        {
            sudo_log(SUDO_CONV_ERROR_MSG, "you do not have permissions to clear sudo commands\n");
            free_commands_null(cmds_all);
            free_commands_null(cmds_clear);
            return -1;
        }

        /* Authenticate user */
        if (! check_passwd(user))
        {
            free_commands_null(cmds_all);
            free_commands_null(cmds_clear);
            return -1;
        }

        /* Clear all commands */
        if ( count == MAX_USERS - 1 )
        {
            remove(PLUGIN_COMMANDS_ALL);
            remove(PLUGIN_COMMANDS_APPLY);
            remove(PLUGIN_COMMANDS_CLEAR);

            remove(PLUGIN_APPLY_AUTH_FILE);
            remove(PLUGIN_CLEAR_AUTH_FILE);

            int offset = cmp_command(cmds_all, cmds_clear);

            if (offset > 0)
            {
                while (cmds_all[offset] != NULL)
                {
                    save_command(cmds_all[offset], PLUGIN_COMMANDS_ALL);
                    offset++;
                }
            }

            sudo_log(SUDO_CONV_INFO_MSG, "Commands cleared.\n");
        }
        else
        {
            if (save_authorization(user, PLUGIN_CLEAR_AUTH_FILE))
            {
                /* Saves all authórized commands */
                i = 0;
                while (cmds_all[i] != NULL)
                {
                    save_command(cmds_all[i], PLUGIN_COMMANDS_CLEAR);  /// error handling
                    i++;
                }
                sudo_log(SUDO_CONV_INFO_MSG, "User %d/%d authorized.\n", count+1, MAX_USERS);
            }
            else
            {
                sudo_log(SUDO_CONV_ERROR_MSG, "cannot save authorization information to %s\n", STR(PLUGIN_APPLY_AUTH_FILE));
            }
        }

        free_commands_null(cmds_all);
        free_commands_null(cmds_clear);
        return 0;
    }
    else
    {
        char * path;

        /* Check if its regular command */
        if ((path = find_in_path(argv[0],plugin_state.envp)) == NULL)
        {
            free(path);
            return -2;
        }
        free(path);

        command_data * command = make_command();
        command->argv = argv;
        command->user = getenv("USER");
        command->home = getenv("HOME");
        command->path = getenv("PATH");
        command->pwd = getenv("PWD");

        /* Save command to file */
        int result = save_command(command, PLUGIN_COMMANDS_ALL);
        free(command);

        if (result)
        {
            sudo_log(SUDO_CONV_INFO_MSG, "Commands saved\n");
            return 0;
        }
        else
        {
            sudo_log(SUDO_CONV_ERROR_MSG, "cannot save command\n");
            return -1;
        }
    }
}

/*
List available privileges for the invoking user. Returns 1 on success, 0 on failure and -1 on error.
*/
static int sudo_list(int argc, char * const argv[], int verbose, const char *list_user)
{
    sudo_log(SUDO_CONV_INFO_MSG, "apply-all     run all saved sudo commands\nclear-all     remove all saved sudo commands\n");

    sudo_log(SUDO_CONV_INFO_MSG, "These commands are by allowed to selected authorities only.\n");

    /* Write authorities list */
    if (verbose)
    {
        sudo_log(SUDO_CONV_INFO_MSG, "Authorities:\n");

        char ** users = load_users();
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
