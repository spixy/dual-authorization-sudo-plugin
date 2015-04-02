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
#include <errno.h>
#include <fcntl.h>
#include <grp.h>
#include <memory.h>
#include <pwd.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <sudo_plugin.h>
#include <unistd.h>

#include <linux/limits.h>

#include <security/pam_appl.h>
#include <security/pam_misc.h>
#include <security/pam_modules.h>
#include <security/_pam_macros.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/sendfile.h>
#include <sys/wait.h>

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
static char * cwd;
static int use_sudoedit = false;


static char ** load_users();

static void print_command(command_data * command, int full);
static command_data ** load();
static command_data * load_command(FILE * fp);
static command_data ** filter_commands(command_data ** commands, int filter);
static int save(command_data ** commands);
static int save_command(command_data * command, int fd);

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
        sudo_log(SUDO_CONV_INFO_MSG, "%s ", *argv);
        argv++;
    }

    if (full)
    {
        sudo_log(SUDO_CONV_INFO_MSG, "\nrunas user:%s runas group:%s", command->runas_uid, command->runas_gid);
        sudo_log(SUDO_CONV_INFO_MSG, "\nuser:%s home:%s pwd:%s", command->user, command->home, command->pwd);
        sudo_log(SUDO_CONV_INFO_MSG, "\nauth by:%s rem by:%s\n", command->auth_by_user, command->rem_by_user);
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

    if ( (users = malloc( (AUTH_USERS+1) * sizeof(char*))) == NULL)
    {
        sudo_log(SUDO_CONV_ERROR_MSG, "cannot allocate data\n");
        return NULL;
    }
    users[AUTH_USERS] = NULL;

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
                if (usercount == AUTH_USERS)
                {
                    fclose(fp);
                    free(buffer);
                    sudo_log(SUDO_CONV_ERROR_MSG, "too many users stored in %s (maximum is %d)\n", STR(PLUGIN_CONF_FILE), AUTH_USERS);
                    free_2d(users, AUTH_USERS);
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
    if (usercount == AUTH_USERS)
    {
        free_2d(users, AUTH_USERS);
        sudo_log(SUDO_CONV_ERROR_MSG, "not enough users set in %s (minimum is %d)\n", STR(PLUGIN_CONF_FILE) , AUTH_USERS);
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
Copy temp file (fd) to PLUGIN_COMMANDS_FILE
*/
static int copy_tmp(int fd)
{
    int targetfd;
    struct stat s;
    off_t offset = 0;

    if ((targetfd = open(PLUGIN_COMMANDS_FILE, O_RDWR | O_CREAT, S_IWUSR | S_IRUSR)) == -1)
    {
        return false;
    }

    fstat(fd, &s);

    if (sendfile(targetfd,fd,&offset, s.st_size) < s.st_size)
    {
        close(targetfd);
        return false;
    }

    close(targetfd);
    return true;
}

static int save(command_data ** commands)
{
    int fd;

    char fileNameArray[] = PLUGIN_COMMANDS_TEMP_FILE;

    char * fileName = mktemp(fileNameArray);

    if ( (fd = open(fileName, O_RDWR | O_CREAT | O_EXCL, S_IWUSR | S_IRUSR)) /*(fd = mkstemp(fileName))*/ == -1 )
    {
        free(fileName);
        return false;
    }

    /* Commands count */
    unsigned int count = commands_array_len(commands);

    if (write(fd, &count, 2) != 2)
    {
        close(fd);
        free(fileName);
        return false;
    }

    unsigned int i = 0;
    while (commands[i] != NULL)
    {
        if (!save_command(commands[i], fd))
        {
            close(fd);
            free(fileName);
            return false;
        }
        i++;
    }

    /* Copy fileName from /tmp/ to PLUGIN_COMMANDS_FILE */

    int result = copy_tmp(fd);  //rename(fileName, PLUGIN_COMMANDS_FILE);

    unlink(fileName);

    // free(fileName);  // free(): invalid pointer

    close(fd);

    return result;
}

static char * load_string(FILE * fp)
{
    unsigned char int_buffer[2];

    if (fread(int_buffer, 2, 1, fp) != 1)
    {
        return NULL;
    }

    unsigned int len = int_buffer[0] + int_buffer[1]*256;
    char * str;

    if (len == 0)
    {
        return NULL;
    }

    if ( (str = malloc(sizeof(char) * len)) == NULL )
    {
        return NULL;
    }

    if (fread(str, sizeof(char), len, fp) != len)
    {
        free(str);
        return NULL;
    }

    return str;
}

static command_data * load_command(FILE * fp)
{
    unsigned char int_buffer[2];
    command_data * command;

    if ( (command = make_command()) == NULL )
    {
        return NULL;
    }

    /* Arguments count */
    if (fread(int_buffer, 2, 1, fp) != 1)
    {
        free(command);
        return NULL;
    }

    unsigned int argc = int_buffer[0] + int_buffer[1]*256;

    if ( ( command->argv = malloc((argc+1)*sizeof(char*)) ) == NULL )
    {
        free_command(command);
        return NULL;
    }

    for (unsigned int i = 0; i < argc; i++)
    {
        char * str = load_string(fp);

        if (str == NULL)
        {
            free(command->argv);
            free(command);
            return NULL;
        }

        command->argv[i] = str;
    }
    command->argv[argc] = NULL;

    /* Separator */
    if ( fread(int_buffer, 1, 1, fp) != 1 || int_buffer[0] != 0 )
    {
        free_command(command);
        return NULL;
    }

    command->runas_uid = load_string(fp);
    command->runas_gid = load_string(fp);
    command->user = load_string(fp);
    command->home = load_string(fp);
    command->path = load_string(fp);
    command->pwd = load_string(fp);
    command->auth_by_user = load_string(fp);

    return command;
}

static command_data ** load()
{
    FILE * fp;
    command_data ** cmds;
    unsigned char int_buffer[2];

    if ( (fp = fopen(PLUGIN_COMMANDS_FILE, "rb")) == NULL )
    {
        return NULL;
    }

    int debug;

    /* Commands count */
    if ((debug = fread(int_buffer, 2, 1, fp)) != 1)
    {
        fclose(fp);
        return NULL;
    }

    unsigned int count = int_buffer[0] + int_buffer[1]*256;

    if ( (cmds = malloc( (count+1) * sizeof(command_data*) )) == NULL )
    {
        sudo_log(SUDO_CONV_ERROR_MSG, "cannot allocate data\n");
        fclose(fp);
        return NULL;
    }

    for (unsigned int i = 0; i < count; i++)
    {
        if ((cmds[i] = load_command(fp)) == NULL)
        {
            sudo_log(SUDO_CONV_ERROR_MSG, "cannot allocate data\n");

            cmds[i] = NULL;
            free_commands_null(cmds);
            fclose(fp);
            return NULL;
        }
    }

    cmds[count] = NULL;

    fclose(fp);
    return cmds;
}

static command_data ** filter_commands(command_data ** commands, int filter)
{
    if (commands == NULL)
        return NULL;

    command_data ** cmds;
    command_data ** more_cmds;
    unsigned int count = 1;

    if ( (cmds = malloc( count * sizeof(command_data*) )) == NULL )
    {
        sudo_log(SUDO_CONV_ERROR_MSG, "cannot allocate data\n");
        return NULL;
    }

    int i = 0;
    while (commands[i] != NULL)
    {
        if ( (filter == FILTER_NOT_AUTH && commands[i]->auth_by_user == NULL) ||
             (filter == FILTER_AUTH_ME && commands[i]->auth_by_user != NULL && strcmp(commands[i]->auth_by_user, user) == 0) ||
             (filter == FILTER_AUTH_NOT_ME && commands[i]->auth_by_user != NULL && strcmp(commands[i]->auth_by_user, user) != 0) )
        {
            cmds[count-1] = commands[i];
            count++;

            if ( (more_cmds = realloc(cmds, count * sizeof(command_data*) )) == NULL )
            {
                sudo_log(SUDO_CONV_ERROR_MSG, "cannot allocate data\n");
                free(cmds);
                return NULL;
            }

            cmds = more_cmds;
        }
        i++;
    }

    cmds[count-1] = NULL;

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

int converse( pam_handle_t *pamh,''int nargs, struct pam_message **message, struct pam_response **response )
{
    int retval;
    struct pam_conv *conv;

    // Begin speaking with PAM, flaged with the PAM_CONV argument
    retval = pam_get_item(pamh, PAM_CONV,  (const void **) &conv ) ;
    if ( retval == PAM_SUCCESS )
    {
       retval = conv->conv( nargs,
                            ( const struct pam_message ** ) message,
                            response,
                            conv->appdata_ptr );
    }
    return retval;
}


int _set_auth_tok( pam_handle_t *pamh, int flags, int argc, const char **argv )
{
   int retval;
   char *p;

   struct pam_message msg[1],*pmsg[1];
   struct pam_response *resp;

/* set up conversation call */

   pmsg[0] = &msg[0];
   msg[0].msg_style = PAM_PROMPT_ECHO_OFF;
   msg[0].msg = "Password: ";
   resp = NULL;

// Call the converse function so we know we are speaking with PAM
   if ( ( retval = converse( pamh, 1 , pmsg, &resp ) ) != PAM_SUCCESS )
       return retval;

   if ( resp )
   {
       if( ( flags & PAM_DISALLOW_NULL_AUTHTOK ) &&
            resp[0].resp == NULL )
       {
           free( resp );
           return PAM_AUTH_ERR;
       }

        p = resp[ 0 ].resp;

        resp[ 0 ].resp = NULL;
    }
   else
       return PAM_CONV_ERR;


   free( resp );
// Set our authentication arguments to retrieve username & passsword.
   pam_set_item( pamh, PAM_AUTHTOK, p );
   return PAM_SUCCESS;
}

/*
Authorize user via PAM
*/
static int check_passwd(const char* user) // PAM zatim nefunguje (PAM_AUTH_ERR)
{
    /*struct sudo_conv_message msg;
    struct sudo_conv_reply repl;
    char message[MAX_USER_LENGTH + 11];

    strcpy(message, user);
    strcat(message, " password:");

    memset(&msg, 0, sizeof(msg));
    //msg.msg_type = SUDO_CONV_PROMPT_ECHO_OFF;
    msg.msg_type = SUDO_CONV_PROMPT_ECHO_ON; // testing
    msg.msg = message;

    / * Show message * /
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
    sudo_log(SUDO_CONV_INFO_MSG, ">> ");
    print_command(command, false);

    pid_t pid;
    int status;

    if ((pid = fork()) < 0) /* fork a child process */
    {
        return false;
    }
    else if (pid == 0) /* for the child process: */
    {
        char ** envp = build_envp(command);

        if (chdir(command->pwd) == -1)
        {
            free_2d_null(envp);
            return false;
        }

        /* find executable path  */
        command->file = find_in_path(command->argv[0], envp);

        /* execute the command  */
        if (execve(command->file, &command->argv[0], &envp[0]) < 0)
        {
            return false;
        }
        exit(0);
    }
    else /* for the parent  */
    {
        while (wait(&status) != pid)
        {
            // wait
        }
        return (status == 0);
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
        int i, result, i_exec = -1;
        command_data ** cmds = load();

        /* No commands found */
        if (cmds == NULL || cmds[0] == NULL)
        {
            sudo_log(SUDO_CONV_ERROR_MSG, "no commands found.\n");
            free_commands_null(cmds);
            return -1;
        }

        command_data ** cmds_not_auth    = filter_commands(cmds, FILTER_NOT_AUTH);    // to authenticate
        command_data ** cmds_auth_me     = filter_commands(cmds, FILTER_AUTH_ME);     // nothing
        command_data ** cmds_auth_not_me = filter_commands(cmds, FILTER_AUTH_NOT_ME); // to execute

        if (cmds_not_auth == NULL || cmds_auth_me == NULL || cmds_auth_not_me == NULL)
        {
            sudo_log(SUDO_CONV_ERROR_MSG, "allocation error\n");
            free_commands_null(cmds);
            return -1;
        }

        sudo_log(SUDO_CONV_INFO_MSG, "Commands already authenticated:\n");
        i = 0;
        while (cmds_auth_me[i] != NULL)
        {
            sudo_log(SUDO_CONV_INFO_MSG, "%d: ", i+1);
            print_command(cmds_auth_me[i], false);
            i++;
        }
        sudo_log(SUDO_CONV_INFO_MSG, "\n");


        sudo_log(SUDO_CONV_INFO_MSG, "Commands to authenticate:\n");
        i = 0;
        while (cmds_not_auth[i] != NULL)
        {
            sudo_log(SUDO_CONV_INFO_MSG, "%d: ", i+1);
            print_command(cmds_not_auth[i], false);
            i++;
        }
        sudo_log(SUDO_CONV_INFO_MSG, "\n");


        sudo_log(SUDO_CONV_INFO_MSG, "Commands to execute:\n");
        i = 0;
        while (cmds_auth_not_me[i] != NULL)
        {
            sudo_log(SUDO_CONV_INFO_MSG, "%d: ", i+1);
            print_command(cmds_auth_not_me[i], false);
            i++;
        }
        sudo_log(SUDO_CONV_INFO_MSG, "\n");


        /* Authenticate user */
        if (! check_passwd(user))
        {
            free_commands_null(cmds);
            free(cmds_not_auth);
            free(cmds_auth_me);
            free(cmds_auth_not_me);
            return -1;
        }

        /* Run all commands */
        i = 0;
        while (cmds_auth_not_me[i] != NULL)
        {
            if (execute(cmds_auth_not_me[i]))
            {
                cmds = remove_command(cmds, cmds_auth_not_me[i]);
            }
            else /* Error in executing command, stopping execution of all commands */
            {
                sudo_log(SUDO_CONV_ERROR_MSG, "cannot execute command ");
                //print_command(cmds_auth_not_me[i], true);
                i_exec = i;
                break;
            }
            i++;
        }

        /* Set auth commands */
        i = 0;
        while (cmds_not_auth[i] != NULL)
        {
            cmds_not_auth[i]->auth_by_user = strdup(user);
            i++;
        }

        if (i_exec >= 0) /* Mark failed commands as authed by both users */
        {
            i = i_exec;
            while (cmds_auth_not_me[i] != NULL)
            {
                free(cmds_auth_not_me[i]->auth_by_user);
                cmds_auth_not_me[i]->auth_by_user = strdup(BOTH_USERS_AUTHENTICATED);
                i++;
            }
        }

        if (!save(cmds))
        {
            sudo_log(SUDO_CONV_ERROR_MSG, "cannot save commands");
        }
        else sudo_log(SUDO_CONV_ERROR_MSG, "OK\n");

        free(cmds_not_auth);
        free(cmds_auth_me);
        free(cmds_auth_not_me);
        free_commands_null(cmds);
        return 0;
    }

    /*else if ((argc > 0) && (strcmp(argv[0],"clear-all") == 0 || strcmp(argv[0], "ca") == 0))
    {
        int i = 0, count;
        command_data ** cmds = load();

        / * No commands found * /
        if (cmds == NULL || cmds[0] == NULL)
        {
            sudo_log(SUDO_CONV_ERROR_MSG, "no commands found\n");
            free_commands_null(cmds);
            return -1;
        }

        / * Print commands * /
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
            free_commands_null(cmds);
            return -1;
        }
        if ( count == -2 )
        {
            sudo_log(SUDO_CONV_ERROR_MSG, "you do not have permissions to clear sudo commands\n");
            free_commands_null(cmds);
            return -1;
        }

        / * Authenticate user * /
        if (! check_passwd(user))
        {
            free_commands_null(cmds);
            return -1;
        }

        / * Clear all commands * /
        if ( count == AUTH_USERS - 1 )
        {
            remove(PLUGIN_COMMANDS_ALL);
            remove(PLUGIN_COMMANDS_APPLY);
            remove(PLUGIN_COMMANDS_CLEAR);

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
                / * Saves all authórized commands * /
                i = 0;
                while (cmds_all[i] != NULL)
                {
                    save_command(cmds_all[i], PLUGIN_COMMANDS_CLEAR);  /// error handling
                    i++;
                }
                sudo_log(SUDO_CONV_INFO_MSG, "User %d/%d authorized.\n", count+1, AUTH_USERS);
            }
            else
            {
                sudo_log(SUDO_CONV_ERROR_MSG, "cannot save authorization information to %s\n", STR(PLUGIN_APPLY_AUTH_FILE));
            }
        }

        free_commands_null(cmds_all);
        free_commands_null(cmds_clear);
        return 0;
    }*/
    else
    {
        char * path;
        int result;

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
        command->pwd  = getenv("PWD");

        /* Load commands from file */
        command_data ** cmds = load();
        command_data ** cmds_save;
        sudo_log(SUDO_CONV_INFO_MSG, "load()\n");

        if (cmds != NULL)
        {
            if ((cmds_save = add_command(cmds, command)) == NULL)
            {
                sudo_log(SUDO_CONV_ERROR_MSG, "cannot allocate data\n");
                free_commands_null(cmds);
                return -1;
            }

            sudo_log(SUDO_CONV_INFO_MSG, "save(1)\n");

            /* Save commands to file */
            result = save(cmds_save);

            int count = commands_array_len(cmds_save);

            cmds_save[count-1] = NULL;

            free_commands_null(cmds_save);
        }
        else
        {
            if ( (cmds_save = malloc(2 * sizeof(command_data*))) == NULL )
            {
                sudo_log(SUDO_CONV_ERROR_MSG, "cannot allocate data\n");
                free_commands_null(cmds);
                return -1;
            }
            cmds_save[0] = command;
            cmds_save[1] = NULL;

            sudo_log(SUDO_CONV_INFO_MSG, "save(2)\n");

            /* Save commands to file */
            result = save(cmds_save);

            free(cmds_save);
        }

        if (result)
        {
            sudo_log(SUDO_CONV_INFO_MSG, "Command saved\n");
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
