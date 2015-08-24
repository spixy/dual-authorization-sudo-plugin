/*
 * Copyright 2015 Horváth Henrich
 *
 * Sudo security plugin is free software
 * released under GNU Lesser General Public License.
 *
*/

#define _GNU_SOURCE
#define PLUGIN_NAME                     "Sudo Dual Authorization Security Plugin"
#define MIN_AUTH_USERS                   2
#define PACKAGE_VERSION                  1.0

#include "utils.h"
#include "command.h"
#include "io.h"

#include <errno.h>
#include <grp.h>
#include <pwd.h>
#include <stdbool.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <syslog.h>
#include <sudo_plugin.h>
#include <security/pam_appl.h>
#include <security/pam_modules.h>
#include <security/_pam_macros.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>

typedef enum
{
    LIST,
    NORMAL,
    FULL
} print_mode;

typedef enum
{
    AUTHORIZED,
    EXECUTED,
    SKIPPED,
    ERROR
} task_result;

static sudo_conv_t sudo_conv;
static sudo_printf_t sudo_log;
static char * runas_user = NULL;
static char * runas_group = NULL;
static char ** users = NULL;
static char * user = NULL;
static char ** envp = NULL;
static unsigned int min_auth_users = MIN_AUTH_USERS;
static bool use_sudoedit = false;  // sudoedit mode
static bool always_auth = false;   // always authorise before new command is added
static int pam_auth_type = PAM_DISALLOW_NULL_AUTHTOK;
static int commands_fd = -1;

static int execute(command_data * command, bool as_root);
static int run_editor(char * arg);
static int run_diff(command_data * commmand);
static int load_config();
static void print_table_all_commands(command_data ** commands);
static void print_command(command_data * command, print_mode mode);
static task_result auth_remove(command_data ** cmds, int i);
static task_result auth_exec(command_data ** cmds, int i);
static int append_command(char * file, char ** argv, bool flag_sudoedit, char * authorised_by);
static int sudoedit(char * file);
static int try_lock(char * file);
static int check_pam();
static int check_pam_result(int result);
static void SIG_handler(int signal);
static int PAM_conv (int, const struct pam_message**, struct pam_response**, void*);

struct pam_conv PAM_converse =
{
    PAM_conv,
    NULL
};

/*
Get max length of selected table column
*/
static size_t field_size(command_data ** commands, int index, int min)
{
    command_data ** command = commands;

    size_t max = min;
    size_t len;
    char * exec_by_users;
    char * rem_by_users;

    while (*command)
    {
        switch (index)
        {
            case 0:
                if ((*command)->runas_user)
                {
                    len = strlen((*command)->runas_user);
                    if (len > max)
                        max = len;
                }
                break;

            case 1:
                if ((*command)->runas_group)
                {
                    len = strlen((*command)->runas_group);
                    if (len > max)
                        max = len;
                }
                break;

            case 2:
                exec_by_users = concat((*command)->exec_by_users, ",");
                if (exec_by_users)
                {
                    len = strlen (exec_by_users);
                    if (len > max)
                        max = len;
                    free(exec_by_users);
                }
                break;

            case 3:
                rem_by_users = concat((*command)->rem_by_users, ",");
                if (rem_by_users)
                {
                    len = strlen (rem_by_users);
                    if (len > max)
                        max = len;
                    free(rem_by_users);
                }
                break;
        }

        command++;
    }

    return max;
}

/*
Prints commands in table
*/
static void print_table_all_commands(command_data ** commands)
{
    if (!commands)
    {
        return;
    }

    char runas_user_label[] = "USER";
    char runas_group_label[] = "GROUP";
    char exec_by_users_label[] = "TO EXECUTE";
    char rem_by_users_label[] = "TO REMOVE";
    char command_label[] = "COMMAND";

    size_t columns_width[4];

    columns_width[0] = field_size(commands, 0, strlen(runas_user_label)+1);
    columns_width[1] = field_size(commands, 1, strlen(runas_group_label)+1);
    columns_width[2] = field_size(commands, 2, strlen(exec_by_users_label)+1);
    columns_width[3] = field_size(commands, 3, strlen(rem_by_users_label)+1);

    size_t total_width = 0;
    for (int i = 0; i < 4; i++)
        total_width += columns_width[i];

    sudo_log(SUDO_CONV_INFO_MSG, "%-*s%-*s%-*s%-*s %s\n",
            columns_width[0], runas_user_label,
            columns_width[1], runas_group_label,
            columns_width[2], exec_by_users_label,
            columns_width[3], rem_by_users_label,
            command_label);

    for (size_t i = 0; i < total_width; i++)
        sudo_log(SUDO_CONV_INFO_MSG, "=");

    sudo_log(SUDO_CONV_INFO_MSG, "\n");


    command_data ** command = commands;

    while (*command)
    {
        char * exec_by_users = concat((*command)->exec_by_users, ",");
        char * rem_by_users  = concat((*command)->rem_by_users, ",");
        char * cmd_line = get_command_line(*command);

        sudo_log(SUDO_CONV_INFO_MSG, "%-*s%-*s%-*s%-*s %s\n",
            columns_width[0], (*command)->runas_user,
            columns_width[1], (*command)->runas_group,
            columns_width[2], exec_by_users,
            columns_width[3], rem_by_users,
            cmd_line);

        free(exec_by_users);
        free(rem_by_users);
        free(cmd_line);

        command++;
    }
}

/*
Prints command with arguments
*/
static void print_command(command_data * command, print_mode mode)
{
    if (!command || !command->argv)
    {
        return;
    }

    /* Sudoedit */
    if (command->sudoedit)
    {
        if (mode == LIST)
        {
            sudo_log(SUDO_CONV_INFO_MSG, "sudoedit %s\n", command->argv[4]);
        }
        else
        {
            run_diff(command);

            char * exec_by_users = concat(command->exec_by_users, ",");
            char * rem_by_users = concat(command->rem_by_users, ",");

            sudo_log(SUDO_CONV_INFO_MSG,
                "Authorised to execute:%s Authorised to remove:%s\n",
                (exec_by_users ? exec_by_users : "N/A"),
                (rem_by_users ? rem_by_users : "N/A"));

            free(exec_by_users);
            free(rem_by_users);
        }

        return;
    }

    /* Other command */

    char * cmd_line = get_command_line(command);
    sudo_log(SUDO_CONV_INFO_MSG, "%s\n", cmd_line);
    free(cmd_line);

    if (mode == NORMAL || mode == FULL)
    {
        char * exec_by_users = concat(command->exec_by_users, ",");
        char * rem_by_users = concat(command->rem_by_users, ",");

        if (command->runas_user)
            sudo_log(SUDO_CONV_INFO_MSG,"Run as user:%s ",command->runas_user);
        if (command->runas_group)
            sudo_log(SUDO_CONV_INFO_MSG,"Run as group:%s ",command->runas_group);

        sudo_log(SUDO_CONV_INFO_MSG,
                "Authorised to execute:%s Authorised to remove:%s\n",
                (exec_by_users ? exec_by_users : "N/A"),
                (rem_by_users ? rem_by_users : "N/A"));

        free(exec_by_users);
        free(rem_by_users);
    }

    if (mode == FULL)
    {
        char ** local_envp = command->envp;

        while (*local_envp)
        {
            sudo_log(SUDO_CONV_INFO_MSG, "%s\n", *local_envp);
            local_envp++;
        }
    }
}

/*
Reads data (users, always_auth) from conf file
*/
static int load_config()
{
    FILE * fp;
    int error = 0;
    unsigned int user_count = 0;
    size_t user_size = MIN_AUTH_USERS + 1;
    ssize_t len = 0;
    size_t buflen = 0;
    struct passwd *pw;
    char* buffer = NULL;

    if ((users = calloc(user_size, sizeof(char*))) == NULL)
    {
        sudo_log(SUDO_CONV_ERROR_MSG, "Cannot allocate data.\n");
        return false;
    }

    if ( (fp = fopen(PLUGIN_CONF_FILE, "r")) == NULL )
    {
        sudo_log(SUDO_CONV_ERROR_MSG, "File %s not found.\n", STR(PLUGIN_CONF_FILE));
        free(users);
        return false;
    }

    // read new line
    while ( (len = getline(&buffer, &buflen, fp)) != -1 )
    {
        // ignore empty lines and comments
        if (len == 0 || buffer[0] == '#' || buffer[0] == '\n')
        {
            continue;
        }

        // set null instead of new line character
        buffer[len - 1] = '\0';

        if (str_case_starts(buffer, "always_auth ") && (size_t)len > strlen("always_auth ")) // parsing "user xxx"
        {
            char * value = rem_whitespace(buffer + strlen("always_auth "));

            if (strcasecmp(value,"true") == 0 || strcmp(value,"1") == 0)
            {
                always_auth = true;
            }
            else if (strcasecmp(value,"false") == 0 || strcmp(value,"0") == 0)
            {
                always_auth = false;
            }
        }
        else if (str_case_starts(buffer, "user ") && (size_t)len > strlen("user ")) // parsing "user xxx"
        {
            char * user_name = strdup(rem_whitespace(buffer + strlen("user ")));

            if (!user_name)
            {
                error = -1;
                break;
            }

            // check if user exists
            if (!getpwnam(user_name))
            {
                sudo_log(SUDO_CONV_ERROR_MSG, "User %s not found.\n", user_name);
                free(user_name);
                continue;
            }

            // check if user is already loaded
            if (array_null_contains(users, user_name))
            {
                sudo_log(SUDO_CONV_ERROR_MSG, "Found duplicate of user %s, skipping.\n", user_name);
                free(user_name);
                continue;
            }

            // resize array
            if (user_count+1 == user_size)
            {
                user_size += 2;
                char ** new_users;
                if ((new_users = realloc(users, user_size * sizeof(char*))) == NULL)
                {
                    error = -1;
                    break;
                }
                users = new_users;
            }

            // save user name
            users[user_count++] = user_name;
            users[user_count] = NULL;
        }
        else if (str_case_starts(buffer, "uid ") && (size_t)len > strlen("uid ")) // parsing "uid 123"
        {
            char * user_id = strdup(rem_whitespace(buffer + strlen("uid ")));

            if (!user_id)
            {
                error = -1;
                break;
            }

            // get user struct
            char *p;
            errno = 0;
            uid_t id = strtol(user_id, &p, 10);

            if (errno != 0 || *p != 0 || p == user_id)
            {
                sudo_log(SUDO_CONV_ERROR_MSG, "Invalid UID %s\n", user_id);
                free(user_id);
                error = -2;
                continue;
            }

            free(user_id);

            pw = getpwuid(id);

            // check if user with UID exists
            if (!pw)
            {
                sudo_log(SUDO_CONV_ERROR_MSG, "User with uid %s not found.\n", id);
                error = -2;
                continue;
            }

            // checks if user is already loaded
            if (array_null_contains(users, pw->pw_name))
            {
                sudo_log(SUDO_CONV_ERROR_MSG, "Found duplicate of user %s, skipping.\n", pw->pw_name);
                continue;
            }

            // resize array
            if (user_count+1 == user_size)
            {
                user_size += 2;
                char ** new_users;
                if ((new_users = realloc(users, user_size * sizeof(char*))) == NULL)
                {
                    error = -1;
                    break;
                }
                users = new_users;
            }

            char * user_name = strdup(pw->pw_name);

            if (!user_name)
            {
                error = -1;
                break;
            }

            // save user name
            users[user_count++] = user_name;
            users[user_count] = NULL;
        }
        else if (str_case_starts(buffer, "authorizations_count "))
        {
            char * min_users_str = strdup(rem_whitespace(buffer + strlen("authorizations_count ")));

            if (!min_users_str)
            {
                error = -1;
                break;
            }

            // convert to number
            char *p;
            errno = 0;
            size_t _min_auth_users = strtol(min_users_str, &p, 10);

            if (errno != 0 || *p != 0 || p == min_users_str || _min_auth_users < 1 || _min_auth_users > SIZE_MAX)
            {
                sudo_log(SUDO_CONV_ERROR_MSG, "Invalid authorization count: %s\n", min_users_str);
                free(min_users_str);
                error = -2;
                continue;
            }

            // save
            min_auth_users = _min_auth_users;
        }
    }

    fclose(fp);
    free(buffer);

    switch (error)
    {
        case -1: // allocation error
            free_2d_null(users);
            sudo_log(SUDO_CONV_ERROR_MSG, "Cannot allocate data.\n");
            return false;

        case -2: // invalid configuration error
            free_2d_null(users);
            return false;
    }

    if (user_count < min_auth_users)
    {
        free_2d_null(users);
        sudo_log(SUDO_CONV_ERROR_MSG, "Not enough users set in %s (minimum is %d).\n", STR(PLUGIN_CONF_FILE), min_auth_users);
        return false;
    }

    return true;
}

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
        sudo_log(SUDO_CONV_ERROR_MSG, "This plugin requires API version %d.x\n", SUDO_API_VERSION_MAJOR);
        return -1;
    }

    /* Load settings */
    for (ui = settings; *ui != NULL; ui++)
    {
        if (str_case_starts(*ui, "runas_user="))
        {
            runas_user = *ui + sizeof("runas_user=") - 1;
        }
        else if (str_case_starts(*ui, "runas_group="))
        {
            runas_group = *ui + sizeof("runas_group=") - 1;
        }
        else if (strcasecmp(*ui, "sudoedit=true") == 0)
        {
            use_sudoedit = true;
        }
        /* Plugin doesn't support running sudo with no arguments. */
        else if (strcasecmp(*ui, "implied_shell=true") == 0)
        {
            return -2;
        }
    }

    for (ui = user_info; *ui != NULL; ui++)
    {
        if (str_case_starts(*ui, "user="))
        {
            user = *ui + sizeof("user=") - 1;
            break;
        }
    }

    if (runas_user)
    {
        if ((pw = getpwnam(runas_user)) == NULL)
        {
            sudo_log(SUDO_CONV_ERROR_MSG, "Unknown user %s.\n", runas_user);
            return -1;
        }
    }

    if (runas_group)
    {
        if ((gr = getgrnam(runas_group)) == NULL)
        {
            sudo_log(SUDO_CONV_ERROR_MSG, "Unknown group %s.\n", runas_group);
            return -1;
        }
    }

    envp = (char **)user_env;

    openlog("sudo", LOG_PID|LOG_CONS, LOG_USER);

    if (!load_config())
    {
        return -1;
    }

    if (!try_lock(PLUGIN_COMMANDS_FILE))
    {
        return -1;
    }

    return 1;
}

/*
Sudo_close() is called when the command being run by sudo finishes.
*/
static void sudo_close (int exit_status, int error)
{
    free_2d_null(users);

    /* Unlock file with commands */
    if (commands_fd != -1)
    {
        flock(commands_fd, LOCK_UN);
        close(commands_fd);
    }

    closelog();

    if (error)
    {
        sudo_log(SUDO_CONV_ERROR_MSG, "Command error: %s.\n", strerror(error));
    }
    else
    {
        if (WIFEXITED(exit_status))
        {
            sudo_log(SUDO_CONV_INFO_MSG, "Command exited with status %d.\n",
            WEXITSTATUS(exit_status));
        }
        else if (WIFSIGNALED(exit_status))
        {
            sudo_log(SUDO_CONV_INFO_MSG, "Command killed by signal %d.\n",
            WTERMSIG(exit_status));
        }
    }
}

/*
The show_version() function is called by sudo when the user specifies the -V option.
*/
static int sudo_show_version (int verbose)
{
    sudo_log(SUDO_CONV_INFO_MSG, "%s\nPackage version %s\n", PLUGIN_NAME, STR(PACKAGE_VERSION));

    if (verbose)
    {
        sudo_log(SUDO_CONV_INFO_MSG, "Sudo API version %d.%d\n", SUDO_API_VERSION_MAJOR, SUDO_API_VERSION_MINOR);
    }

    return true;
}

/*
Tests if file lock does not exist and locks file
*/
static int try_lock(char * file)
{
    if ( (commands_fd = open(file, O_RDWR | O_CREAT, S_IRUSR | S_IWUSR)) == -1 )
    {
        sudo_log(SUDO_CONV_ERROR_MSG, "Cannot open data file.\n");
        return false;
    }

    if (flock(commands_fd, LOCK_EX | LOCK_NB) == -1)
    {
        sudo_log(SUDO_CONV_ERROR_MSG, "Instance of sudo is already running.\n");
        return false;
    }

    return true;
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

        case PAM_BAD_ITEM:
            sudo_log(SUDO_CONV_ERROR_MSG, "attempted to set an undefined or inaccessible item\n");
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
PAM conversation function
*/
static int PAM_conv(int num_msg, const struct pam_message **msg, struct pam_response **resp, void *appdata_ptr)
{
    struct pam_response * reply = NULL;
    reply = (struct pam_response *) malloc(sizeof(struct pam_response) * num_msg);

    if (!reply)
    {
        return PAM_CONV_ERR;
    }

    struct sudo_conv_message msgs[1];
    struct sudo_conv_reply replies[1];

    for (int i = 0; i < num_msg; i++)
    {
        switch (msg[i]->msg_style)
        {
            case PAM_PROMPT_ECHO_ON:
            case PAM_PROMPT_ECHO_OFF:

                if (msg[i]->msg_style == PAM_PROMPT_ECHO_ON)
                {
                    msgs[0].msg_type = SUDO_CONV_PROMPT_ECHO_ON;
                }
                else
                {
                    msgs[0].msg_type = SUDO_CONV_PROMPT_ECHO_OFF;
                }

                /* Message */
                char * message = strdup(msg[i]->msg);
                if (!message)
                {
                    return PAM_BUF_ERR;
                }
                msgs[0].msg = message;

                /* Conversation */
                if (sudo_conv(1, msgs, replies) != 0)
                {
                    free(message);
                    return PAM_CONV_ERR;
                }

                /* Response */
                reply[i].resp_retcode = 0;
                reply[i].resp = strdup(replies[0].reply);
                if (!reply[i].resp)
                {
                    free(message);
                    return PAM_BUF_ERR;
                }

                free(message);
                free(replies[0].reply);

                break;

            case PAM_TEXT_INFO:
                sudo_log(SUDO_CONV_INFO_MSG, msg[i]->msg);
                break;

            case PAM_ERROR_MSG:
                sudo_log(SUDO_CONV_ERROR_MSG, msg[i]->msg);
                break;

            default:
                return PAM_CONV_ERR;
        }
    }

    *resp = reply;

    return PAM_SUCCESS;
}

/*
Authenticate user via PAM
*/
static int check_pam()
{
    pam_handle_t * pamh = NULL;

    /* Initialize PAM */
    int result = pam_start("sudo", user, &PAM_converse, &pamh);

    if (!check_pam_result(result))
    {
        pam_end(pamh, result);
        return false;
    }

    /* Authenticate user  */
    result = pam_authenticate(pamh, pam_auth_type);

    if (!check_pam_result(result))
    {
        syslog(LOG_ERR, "User %s has not authenticated", user);
        pam_end(pamh, result);
        return false;
    }

    /* Check for account validation */
    result = pam_acct_mgmt(pamh, 0);

    if (!check_pam_result(result))
    {
        syslog(LOG_ERR, "User %s not valid", user);
        pam_end(pamh, result);
        return false;
    }

    pam_end(pamh, result);
    return true;
}

/*
Execute command
*/
static int execute(command_data * command, bool as_root)
{
    if (!command)
    {
        return false;
    }

    pid_t pid;

    if ((pid = fork()) < 0) /* Fork a child process */
    {
        return false;
    }
    else if (pid == 0) /* For the child process */
    {
        char * pwd = getenv_from_envp("PWD", command->envp);

        if (chdir(pwd) == -1)
        {
            return false;
        }

        /* Run as group */
        if (command->runas_group && !as_root)
        {
            struct group * gid;
            if ((gid = getgrnam(command->runas_group)) != NULL)
            {
                if (setgid(gid->gr_gid) == -1)
                {
                    sudo_log(SUDO_CONV_ERROR_MSG, "Cannot set gid to %d.\n", gid->gr_gid);
                    return false;
                }
            }
            else
            {
                sudo_log(SUDO_CONV_ERROR_MSG, "Group %s not found.\n", command->runas_group);
                return false;
            }
        }
        else
        {
            /* Run as root */
            if (setgid(0) == -1)
            {
                sudo_log(SUDO_CONV_ERROR_MSG, "Cannot set gid to %d.\n", 0);
                return false;
            }
        }

        /* Run as user */
        if (command->runas_user && !as_root)
        {
            struct passwd * uid;
            if ((uid = getpwnam(command->runas_user)) != NULL)
            {
                if (setuid(uid->pw_uid) == -1)
                {
                    sudo_log(SUDO_CONV_ERROR_MSG, "Cannot set uid to %d.\n", uid->pw_uid);
                    return false;
                }
            }
            else
            {
                sudo_log(SUDO_CONV_ERROR_MSG, "User %s not found.\n", command->runas_user);
                return false;
            }
        }
        else
        {
            /* Run as root */
            if (setuid(0) == -1)
            {
                sudo_log(SUDO_CONV_ERROR_MSG, "Cannot set uid to %d.\n", 0);
                return false;
            }
        }

        /* Execute the command  */
        if (execve(command->file, &command->argv[0], &/*local_envp*/command->envp[0]) < 0)
        {
            _exit(1);
        }

        _exit(0);
    }
    else /* For the parent  */
    {
        int status;
        while (wait(&status) != pid)
        {
            // wait
        }
        return (WIFEXITED(status) && WEXITSTATUS(status) == 0);
    }
}

/*
Run editor for sudoedit
*/
static int run_editor(char * arg)
{
    if (!arg)
    {
        sudo_log(SUDO_CONV_ERROR_MSG, "Invalid command.\n");
        return false;
    }

    /* Find editor in ENVP */
    char * editor = find_editor(envp);

    if (!editor)
    {
        sudo_log(SUDO_CONV_ERROR_MSG, "Cannot find editor.\n");
        return false;
    }

    char * file = strdup(arg);

    if (!file)
    {
        sudo_log(SUDO_CONV_ERROR_MSG, "Cannot allocate data.\n");
        free(editor);
        return false;
    }

    /* Create command */
    command_data * cmd = make_command();
    if (!cmd)
    {
        sudo_log(SUDO_CONV_ERROR_MSG, "Cannot allocate data.\n");
        free(editor);
        free(file);
        return false;
    }

    cmd->argv = malloc(3 * sizeof(char*));
    if (!cmd->argv)
    {
        sudo_log(SUDO_CONV_ERROR_MSG, "Cannot allocate data.\n");
        free(editor);
        free(file);
        free(cmd);
        return false;
    }

    cmd->file = editor;
    cmd->argv[0] = x_strdup(basename(editor));
    cmd->argv[1] = file;
    cmd->argv[2] = NULL;
    cmd->envp = envp;
    cmd->runas_user = strdup(user);

    if (!cmd->argv[0] || !cmd->runas_user || !cmd->envp)
    {
        sudo_log(SUDO_CONV_ERROR_MSG, "Cannot allocate data.\n");
        cmd->envp = NULL;
        free_command(cmd);
        return false;
    }

    /* Run text editor */
    int result = execute(cmd, false);

    cmd->envp = NULL;
    free_command(cmd);

    return result;
}

/*
DIFF function for sudoedit
*/
static int run_diff(command_data * commmand)
{
    if (!commmand || !commmand->argv || str_array_len(commmand->argv) < 5)
    {
        return false;
    }

    char * file1 = commmand->argv[4];
    char * file2 = commmand->argv[3];

    if (!file1 || !file2)
    {
        return false;
    }

    /* Crete command */
    command_data * cmd = make_command();
    if (!cmd)
    {
        sudo_log(SUDO_CONV_ERROR_MSG, "Cannot allocate data.\n");
        return false;
    }

    cmd->argv = malloc(5 * sizeof(char*));
    if (!cmd->argv)
    {
        sudo_log(SUDO_CONV_ERROR_MSG, "Cannot allocate data.\n");
        free(cmd);
        return false;
    }

    cmd->file = strdup("/usr/bin/diff");
    cmd->argv[0] = strdup("diff");
    cmd->argv[1] = strdup("-u");
    cmd->argv[2] = strdup(file1);
    cmd->argv[3] = strdup(file2);
    cmd->argv[4] = NULL;
    cmd->envp = commmand->envp;

    if (!cmd-> file || !cmd->argv[0] || !cmd->argv[1] || !cmd->argv[2] || !cmd->argv[3] || !cmd->envp)
    {
        sudo_log(SUDO_CONV_ERROR_MSG, "Cannot allocate data.\n");
        cmd->envp = NULL;
        free_command(cmd);
        return false;
    }

    sudo_log(SUDO_CONV_ERROR_MSG, "DIFF %s\n", file1);

    /* Run diff */
    int result = execute(cmd, true);

    cmd->envp = NULL;
    free_command(cmd);

    return result;
}

/*
Creates copy of file, open it with editor, save to list
*/
static int sudoedit(char * orig_file)
{
    if (!orig_file)
    {
        return false;
    }

    char * orig_file_basename = basename(orig_file);
    char * temp_file;

    if (!orig_file_basename || asprintf(&temp_file, "/var/tmp/%s-XXXXXX", orig_file_basename) < 0)
    {
        sudo_log(SUDO_CONV_ERROR_MSG, "Cannot allocate data.\n");
        return false;
    }

    /* Generate temporary file */
    int fd = mkstemp(temp_file);
    if (fd < 0)
    {
        sudo_log(SUDO_CONV_ERROR_MSG, "Cannot create file\n");
        free(temp_file);
        return false;
    }

    /* Copy file */
    int result = copy_file(orig_file, fd);
    close(fd);

    switch (result)
    {
        case -1:
            sudo_log(SUDO_CONV_ERROR_MSG, "File does not exist\n");
            free(temp_file);
            return false;

        case 0:
            sudo_log(SUDO_CONV_ERROR_MSG, "Cannot copy file\n");
            unlink(temp_file);
            free(temp_file);
            return false;
    }

    /* Change file attributes */
    if (chown(temp_file, getpwnam(user)->pw_uid, getpwnam(user)->pw_gid) == -1 || chmod(temp_file, S_IRUSR | S_IWUSR) == -1)
    {
        sudo_log(SUDO_CONV_ERROR_MSG, "Cannot change file attributes\n");
        unlink(temp_file);
        free(temp_file);
        return false;
    }

    /* Run text editor */
    if (! run_editor(temp_file))
    {
        unlink(temp_file);
        free(temp_file);
        return false;
    }

    /* Changes in file? */
    if (cmp_files(orig_file, temp_file))
    {
        unlink(temp_file);
        free(temp_file);
        return true;
    }
    else
    {
        /* Save old temp file */
        char * old_temp_file = temp_file;

        if (asprintf(&temp_file, "/var/tmp/%s-XXXXXX", orig_file_basename) < 0)
        {
            sudo_log(SUDO_CONV_ERROR_MSG, "Cannot allocate data.\n");
            free(old_temp_file);
            return false;
        }

        /* Generate new temp file */
        fd = mkstemp(temp_file);
        if (fd < 0)
        {
            sudo_log(SUDO_CONV_ERROR_MSG, "Cannot create file\n");
            free(old_temp_file);
            free(temp_file);
            return false;
        }

        /* Copy old temp file to new one */
        if (!copy_file(old_temp_file, fd))
        {
            sudo_log(SUDO_CONV_ERROR_MSG, "Cannot copy file\n");
            close(fd);
            unlink(old_temp_file);
            free(old_temp_file);
            free(temp_file);
            return false;
        }

        close(fd);
        unlink(old_temp_file);
        free(old_temp_file);

        /* Save command: "mv -f -T /var/tmp/file-xxxxxx file" */
        char ** new_argv = malloc(6 * sizeof(char*));
        if (!new_argv)
        {
            sudo_log(SUDO_CONV_ERROR_MSG, "Cannot allocate data.\n");
            unlink(temp_file);
            free(temp_file);
            return false;
        }

        new_argv[0] = strdup("mv");
        new_argv[1] = strdup("-f");
        new_argv[2] = strdup("-T");
        new_argv[3] = strdup(temp_file);
        new_argv[4] = strdup(orig_file);
        new_argv[5] = NULL;

        char * path = strdup("/usr/bin/mv");

        if (!path || !new_argv[0] || !new_argv[1] || !new_argv[2] || !new_argv[3] || !new_argv[4])
        {
            sudo_log(SUDO_CONV_ERROR_MSG, "Cannot allocate data.\n");
            unlink(temp_file);
            free(path);
            free(temp_file);
            free_2d_null(new_argv);
            return false;
        }

        result = append_command(path, new_argv, true, user);

        free(path);
        free_2d_null(new_argv);
        free(temp_file);

        return result;
    }
}

/*
Marks command for execution and/or execute command list
Returns next index in command list
*/
static task_result auth_exec(command_data ** cmds, int i)
{
    // not authorised by me yet
    if (!array_null_contains(cmds[i]->exec_by_users, user))
    {
        char * exec_by_user = strdup(user);
        if (!exec_by_user)
        {
            sudo_log(SUDO_CONV_ERROR_MSG, "Cannot allocate data.\n");
            return ERROR;
        }

        // set me as authorised user
        cmds[i]->exec_by_users = add_string(cmds[i]->exec_by_users, exec_by_user);

        // syslog
        char * com_argv = concat((char**) cmds[i]->argv, " ");
        if (com_argv)
        {
            syslog(LOG_INFO, "%s authorised to execute %s", user, com_argv);
            free(com_argv);
        }

        if (!save(cmds))
        {
            sudo_log(SUDO_CONV_ERROR_MSG, "Cannot save commands.\n");
            return ERROR;
        }

        if (str_array_len(cmds[i]->exec_by_users) < min_auth_users)
        {
            return AUTHORIZED;
        }
    }
    // already authorised by me and cannot run command
    else if (str_array_len(cmds[i]->exec_by_users) < min_auth_users)
    {
        sudo_log(SUDO_CONV_ERROR_MSG, "Command already authorised, skipping.\n");
        return SKIPPED;
    }

    bool runas_root = (cmds[i]->sudoedit);

    // syslog
    char * com_argv = concat((char**) cmds[i]->argv, " ");
    char * exec_by_users = concat((char**) cmds[i]->exec_by_users, " ");
    if (com_argv && exec_by_users)
    {
        syslog(LOG_INFO, "%s executes %s, authorised by %s", user, com_argv, exec_by_users);
    }
    free(com_argv);
    free(exec_by_users);

    // execution succesfull?
    if (execute(cmds[i], runas_root))
    {
        cmds = remove_command(cmds, cmds[i]);

        // save commands
        if (!save(cmds))
        {
            sudo_log(SUDO_CONV_ERROR_MSG, "Cannot save commands.\n");
            return ERROR;
        }

        return EXECUTED;
    }
    else
    {
        // skip
        sudo_log(SUDO_CONV_ERROR_MSG, "Error in command execution, skipping.\n");
        return SKIPPED;
    }
}

/*
Marks command for delete and/or remove command list
Returns next index in command list
*/
static task_result auth_remove(command_data ** cmds, int i)
{
    // not authorised by me yet
    if (!array_null_contains(cmds[i]->rem_by_users, user))
    {
        char * rem_by_user = strdup(user);
        if (!rem_by_user)
        {
            sudo_log(SUDO_CONV_ERROR_MSG, "Cannot allocate data.\n");
            return ERROR;
        }

        // set me as authorised user
        cmds[i]->rem_by_users = add_string(cmds[i]->rem_by_users, rem_by_user);

        char * com_argv = concat((char**) cmds[i]->argv, " ");
        if (com_argv)
        {
            syslog(LOG_INFO, "%s authorised to remove %s", user, com_argv);
            free(com_argv);
        }

        // save commands
        if (!save(cmds))
        {
            sudo_log(SUDO_CONV_ERROR_MSG, "Cannot remove command.\n");
            return ERROR;
        }

        if (str_array_len(cmds[i]->rem_by_users) < min_auth_users)
        {
            return AUTHORIZED;
        }
    }
    // already authorised by me and cannot run command
    else if (str_array_len(cmds[i]->rem_by_users) < min_auth_users)
    {
        sudo_log(SUDO_CONV_ERROR_MSG, "Command already authorised, skipping.\n");
        return SKIPPED;
    }

    char * stored_user = getenv_from_envp("USER", cmds[i]->envp);

    if ((strcmp(stored_user, user) == 0) ||                      // I wrote command (and I am admin)   OR
        str_array_len(cmds[i]->rem_by_users) == min_auth_users)  // all admins already authorised
    {
        if (cmds[i]->sudoedit && remove(cmds[i]->argv[3]) == -1)
        {
            sudo_log(SUDO_CONV_ERROR_MSG, "Cannot remove %s\n", cmds[i]->argv[3]);
        }

        // syslog
        char * com_argv = concat((char**) cmds[i]->argv, " ");
        char * rem_by_users = concat((char**) cmds[i]->rem_by_users, " ");
        if (com_argv && rem_by_users)
        {
            syslog(LOG_INFO, "%s removes %s, authorised by %s", user, com_argv, rem_by_users);
        }
        free(com_argv);
        free(rem_by_users);

        // remove command
        cmds = remove_command(cmds, cmds[i]);

        // save commands
        if (!save(cmds))
        {
            sudo_log(SUDO_CONV_ERROR_MSG, "Cannot remove command.\n");
            return ERROR;
        }

        return EXECUTED;
    }
    else
    {
        // skip
        return AUTHORIZED;
    }
}

/*
Handle signals
*/
static void SIG_handler(int signal)
{
    free_2d_null(users);

    /* Unlock file with commands */
    if (commands_fd != -1)
    {
        flock(commands_fd, LOCK_UN);
        close(commands_fd);
    }

    syslog(LOG_INFO, "exiting after received signal %d", signal);
    closelog();

    exit(signal);
}

/*
Function is called by sudo to determine whether the user is allowed to run the specified commands.
*/
static int sudo_check_policy(int argc, char * const argv[], char *env_add[], char **command_info[], char **argv_out[], char **user_env_out[])
{
    if (argc == 0 || !argv[0])
    {
        return -2;
    }

    /* Exit after SIGINT */
    signal(SIGINT, SIG_handler);

    /* Administrators command */
    if (strcmp(argv[0], "auth") == 0)
    {
        bool show_only = false;
        bool exec_only = false;
        bool rem_only = false;
        int mode = NORMAL;

        /* Process parameters */
        if (argc > 1)
        {
            show_only = (strcmp(argv[1],"-s") == 0);
            exec_only = (strcmp(argv[1],"-e") == 0);
            rem_only  = (strcmp(argv[1],"-r") == 0);

            if ((!show_only && !exec_only && !rem_only) || (show_only + exec_only + rem_only > 1))
            {
                sudo_log(SUDO_CONV_ERROR_MSG, "Wrong parameters.\n");
                return -1;
            }

            if (argc > 2)
            {
                if (strcmp(argv[2],"-l") == 0)
                {
                    mode = LIST;
                }
                else if (strcmp(argv[2],"-f") == 0)
                {
                    mode = FULL;
                }
                else
                {
                    sudo_log(SUDO_CONV_ERROR_MSG, "Wrong parameters.\n");
                    return -1;
                }
            }
        }

        /* Authorise as other user? */
        if (runas_user)
        {
            if (!getpwnam(runas_user))
            {
                sudo_log(SUDO_CONV_ERROR_MSG, "User %s not found.\n", runas_user);
                return -1;
            }
            user = runas_user;
        }

        /* Is user allowed to authorise */
        if (!array_null_contains(users, user))
        {
            sudo_log(SUDO_CONV_ERROR_MSG, "User %s cannot authorise executing commands.\n", user);
            return -1;
        }

        /* Authenticate user */
        if (! check_pam(user))
        {
            return -1;
        }

        command_data ** cmds = load(commands_fd);

        /* No commands found */
        if (!cmds || !cmds[0])
        {
            sudo_log(SUDO_CONV_ERROR_MSG, "No commands found.\n");
            free_commands_null(cmds);
            return 0;
        }

        /* Prepare conversation */
        struct sudo_conv_message msgs[1];
        struct sudo_conv_reply replies[1];

        char * message = strdup("Execute, remove, skip or quit? [e/r/s/q]:");
        if (!message)
        {
            sudo_log(SUDO_CONV_ERROR_MSG, "Cannot allocate data.\n");
            return -1;
        }
        msgs[0].msg = message;
        msgs[0].msg_type = SUDO_CONV_PROMPT_ECHO_ON;

        size_t length = commands_array_len(cmds);
        size_t i = 0;
        size_t index = 0;

        sudo_log(SUDO_CONV_ERROR_MSG, "Stored commands:\n================\n");

        /*if (show_only && mode == LIST)
        {
            print_table_all_commands(cmds);
        }
        else */
        while (cmds[i])
        {
            sudo_log(SUDO_CONV_ERROR_MSG, "%s%u/%u: ", (mode != LIST && i>0) ? "\n" : "", ++index, length);
            print_command(cmds[i], mode);

            /* Show all commands */
            if (show_only)
            {
                i++;
                continue;
            }
            /* Execute all commands */
            else if (exec_only)
            {
                task_result result = auth_exec(cmds, i);

                switch (result)
                {
                    case EXECUTED:
                        // index stays same
                        break;

                    case AUTHORIZED:
                    case SKIPPED:
                        i++;
                        break;

                    case ERROR:
                        free_commands_null(cmds);
                        free(message);
                        return -1;
                }
                continue;
            }
            /* Remove all commands */
            else if (rem_only)
            {
                task_result result = auth_remove(cmds, i);

                switch (result)
                {
                    case EXECUTED:
                        // index stays same
                        break;

                    case AUTHORIZED:
                    case SKIPPED:
                        i++;
                        break;

                    case ERROR:
                        free_commands_null(cmds);
                        free(message);
                        return -1;
                }
                continue;
            }

            /* Prompt administrator */
            if (sudo_conv(1, msgs, replies) != 0)
            {
                free_commands_null(cmds);
                free(message);
                return -1;
            }

            /* Execute */
            if (strcasecmp(replies[0].reply,"e") == 0)
            {
                task_result result = auth_exec(cmds, i);

                switch (result)
                {
                    case EXECUTED:
                        // index stay same
                        break;

                    case AUTHORIZED:
                    case SKIPPED:
                        i++;
                        break;

                    case ERROR:
                        free_commands_null(cmds);
                        free(message);
                        return -1;
                }
            }
            /* Remove from list */
            else if (strcasecmp(replies[0].reply,"r") == 0)
            {
                task_result result = auth_remove(cmds, i);

                switch (result)
                {
                    case EXECUTED:
                        // index stay same
                        break;

                    case AUTHORIZED:
                    case SKIPPED:
                        i++;
                        break;

                    case ERROR:
                        free_commands_null(cmds);
                        free(message);
                        return -1;
                }
            }
            /* Skip */
            else if (strcasecmp(replies[0].reply,"s") == 0)
            {
                i++;
            }
            /* Quit */
            else if (strcasecmp(replies[0].reply,"q") == 0)
            {
                break;
            }
        }

        free_commands_null(cmds);
        free(message);

        return 0;
    }
    /* Sudoedit command */
    else if (use_sudoedit)
    {
        syslog(LOG_INFO, "sudoedit %s", argv[1]);

        /* Authorise as other user */
        if (runas_user)
        {
            if (!getpwnam(runas_user))
            {
                sudo_log(SUDO_CONV_ERROR_MSG, "User %s not found.\n", runas_user);
                return -1;
            }
            user = runas_user;
        }

        /* Is user allowed to authorise */
        if (!array_null_contains(users, user))
        {
            sudo_log(SUDO_CONV_ERROR_MSG, "User %s cannot authorise sudoedit.\n", user);
            return -1;
        }

        /* Authenticate user */
        if (! check_pam(user))
        {
            return -1;
        }

        int result = sudoedit(argv[1]);

        return (result) ? 0 : -1;
    }
    /* Store new command */
    else
    {
        char * com_argv = concat((char**) argv, " ");
        if (com_argv)
        {
            syslog(LOG_INFO, "command: %s", com_argv);
            free(com_argv);
        }

        char * authorised_by = NULL;
        bool authorised = false;

        if (always_auth)
        {
            if (check_pam(user))
            {
                authorised = true;
            }
            else
            {
                return -1;
            }
        }

        /* If user is allowed to authorise */
        if (array_null_contains(users, user))
        {
            if (authorised || check_pam(user))
            {
                authorised_by = user;
            }
            else
            {
                return -1;
            }
        }

        char * path;

        if ((path = find_in_path(argv[0], envp, X_OK)) == NULL)
        {
            sudo_log(SUDO_CONV_ERROR_MSG, "Cannot find file %s\n", argv[0]);
            return -1;
        }

        int result = append_command(path, (char**) argv, false, authorised_by);
        free(path);

        return (result) ? 0 : -1;
    }
}

/*
Create command from arguments and append to list of commands
*/
static int append_command(char * file, char ** argv, bool flag_sudoedit, char * authorised_by)
{
    command_data * command = make_command();

    if (!command)
    {
        sudo_log(SUDO_CONV_ERROR_MSG, "Cannot allocate data.\n");
        return false;
    }

    command->file = file;
    command->argv = argv;
    command->sudoedit = flag_sudoedit;
    command->envp = envp;
    command->runas_user = runas_user;
    command->runas_group = runas_group;

    if (authorised_by)
    {
        char * exec_by_user = strdup(authorised_by);
        if (!exec_by_user)
        {
            sudo_log(SUDO_CONV_ERROR_MSG, "Cannot allocate data.\n");
            return false;
        }
        command->exec_by_users = add_string(command->exec_by_users, exec_by_user);
    }

    /* Load commands from file */
    command_data ** cmds = load(commands_fd);
    command_data ** cmds_save;

    if ((cmds_save = add_command(cmds, command)) == NULL)
    {
        sudo_log(SUDO_CONV_ERROR_MSG, "Cannot allocate data.\n");
        free_commands_null(cmds);
        return false;
    }

    /* Save commands to file */
    int result = save(cmds_save);

    size_t count = commands_array_len(cmds_save);
    cmds_save[count-1] = NULL;

    free_commands_null(cmds_save);

    if (!result)
    {
        sudo_log(SUDO_CONV_ERROR_MSG, "Command was not saved.\n");
    }

    return result;
}

/*
List available privileges for the invoking user. Returns 1 on success, 0 on failure and -1 on error.
*/
static int sudo_list(int argc, char * const argv[], int verbose, const char * list_user)
{
    if (!users)
    {
        return -1;
    }

    const char * check_user = list_user ? list_user : user;

    bool allowed = array_null_contains(users, check_user);

    if (allowed)
    {
        sudo_log(SUDO_CONV_INFO_MSG, "You are allowed to authorise commands.\n");
    }
    else
    {
        sudo_log(SUDO_CONV_INFO_MSG, "You are not allowed to authorise commands.\n");
    }

    if (verbose && allowed)
    {
        /* Authenticate user */
        if (!check_pam(user))
        {
            return -1;
        }

        sudo_log(SUDO_CONV_INFO_MSG, "Users allowed to authorise commands:\n");
        int i = 0;
        while (users[i])
        {
            sudo_log(SUDO_CONV_INFO_MSG, "%s\n", users[i]);
            i++;
        }
    }

    return 1;
}

struct policy_plugin sudoers_policy =
{
    SUDO_POLICY_PLUGIN,
    SUDO_API_VERSION,
    sudo_open,
    sudo_close,
    sudo_show_version,
    sudo_check_policy,
    sudo_list,
    NULL,   /* validate */
    NULL,   /* invalidate */
    NULL,   /* init_session */
    NULL,   /* register_hooks */
    NULL    /* deregister_hooks */
};
