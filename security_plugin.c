#define _GNU_SOURCE

#include <ctype.h>
#include <fcntl.h>
#include <grp.h>
#include <memory.h>
#include <pwd.h>
#include <stdbool.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <syslog.h>
#include <sudo_plugin.h>
#include <unistd.h>

#include <security/pam_appl.h>
#include <security/pam_modules.h>
#include <security/_pam_macros.h>

#include <sys/file.h>
#include <sys/sendfile.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>

#include "sudo_helper.h"

static sudo_conv_t sudo_conv;
static sudo_printf_t sudo_log;
static char * runas_user = NULL;
static char * runas_group = NULL;
static char ** users = NULL;
static char * user = NULL;
static char * cwd = NULL;
static char ** envp = NULL;
static char use_sudoedit = false;
static int commands_fd = -1;

static char ** build_envp(command_data * command);
static int execute(command_data * command, bool as_root);
static int run_editor(char * arg);
static int run_diff(command_data * commmand);
static int load_config();
static void print_command(command_data * command, int mode);
static int auth_remove(command_data ** cmds, int i);
static int auth_exec(command_data ** cmds, int i);
static int save(command_data ** commands);
static int save_command(command_data * command, int fd);
static int append_command(char * file, char ** argv, char flag_sudoedit);
static int sudoedit(command_data * command);
static command_data ** remove_command(command_data ** array, command_data * cmd);
static command_data * load_command(int fd);
static command_data ** load();
static int try_lock(char * file);
static int check_pam();
static int check_pam_result(int result);
static int PAM_conv (int, const struct pam_message**, struct pam_response**, void*);

static struct pam_conv PAM_converse =
{
    PAM_conv,
    NULL
};

/*
Prints command with arguments
mode: 0=normal, 1=full, 2=sudoedit
*/
static void print_command(command_data * command, int mode)
{
    if (!command || !command->argv)
    {
        return;
    }

    /* Sudoedit mode */
    if (mode == 2)
    {
        run_diff(command);

        sudo_log(SUDO_CONV_INFO_MSG, "\nAuthorised to execute: %s\n",
            (command->exec_by_users ? concat(command->exec_by_users, ",") : NO_USER));

        sudo_log(SUDO_CONV_INFO_MSG, "Authorised to remove: %s\n",
            (command->rem_by_users ? concat(command->rem_by_users, ",") : NO_USER));

        return;
    }

    char ** argv;
    argv = command->argv;

    while (*argv)
    {
        if (argv == command->argv)
        {
            sudo_log(SUDO_CONV_INFO_MSG, "%s", command->file);
        }
        else
        {
            sudo_log(SUDO_CONV_INFO_MSG, " %s", *argv);
        }
        argv++;
    }

    sudo_log(SUDO_CONV_INFO_MSG, "\n");

    if (mode == 1)
    {
        if (command->runas_user)
            sudo_log(SUDO_CONV_INFO_MSG,"Run as user: %s ",command->runas_user);
        if (command->runas_group)
            sudo_log(SUDO_CONV_INFO_MSG,"Run as group: %s ",command->runas_group);

        if (command->sudoedit)
            sudo_log(SUDO_CONV_INFO_MSG,"Sudoedit: YES ");

        sudo_log(SUDO_CONV_INFO_MSG, "USER: %s PWD: %s\n", command->user, command->pwd);

        sudo_log(SUDO_CONV_INFO_MSG, "Authorised to execute: %s\n",
            (command->exec_by_users ? concat(command->exec_by_users, ",") : NO_USER));

        sudo_log(SUDO_CONV_INFO_MSG, "Authorised to remove: %s\n",
            (command->rem_by_users ? concat(command->rem_by_users, ",") : NO_USER));
    }
}

/*
Reads data (users) from conf file
*/
static int load_config()
{
    FILE * fp;
    int error = 0;
    int user_count = 0;
    int user_size = MIN_AUTH_USERS + 1;
    ssize_t len = 0;
    size_t buflen = 0;
    struct passwd *pw;
    char* buffer = NULL;

    if ((users = malloc(user_size * sizeof(char*))) == NULL)
    {
        sudo_log(SUDO_CONV_ERROR_MSG, "Cannot allocate data.\n");
        return false;
    }

    users[user_size - 1] = NULL;

    if ( (fp = fopen(PLUGIN_CONF_FILE, "r")) == NULL )
    {
        sudo_log(SUDO_CONV_ERROR_MSG, "File %s not found.\n", STR(PLUGIN_CONF_FILE));
        free(users);
        return false;
    }

    // read new line
    while ( (len = getline(&buffer, &buflen, fp)) != -1 )
    {
            // remove new line character
            buffer[len - 1] = '\0';

            // ignore empty lines and comments
            if (len == 0 || buffer[0] == '#' || buffer[0] == '\0')
            {
                continue;
            }

            if (str_case_starts(buffer, "user ") && (size_t)len > strlen("user ")) // parsing "user xxx"
            {
                char * user_name = strdup(rem_whitespace(buffer + strlen("user ")));

                if (!user_name)
                {
                    error = -1;
                    break;
                }

                // checks if user exists
                if (!getpwnam(user_name))
                {
                    sudo_log(SUDO_CONV_ERROR_MSG, "User %s not found.\n", user_name);
                    free(user_name);
                    continue;
                }

                // checks if user is already loaded
                if (array_null_contains(users, user_name))
                {
                    sudo_log(SUDO_CONV_ERROR_MSG, "Found duplicate of user %s, skipping.\n", user_name);
                    free(user_name);
                    continue;
                }

                // resize array
                if (user_count+1 == user_size)
                {
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
                uid_t id = strtol(user_id, NULL, 10);
                pw = getpwuid(id);

                if (!pw)
                {
                    sudo_log(SUDO_CONV_ERROR_MSG, "User with uid %s not found.\n", user_id);
                    free(user_id);
                    error = -2;
                    break;
                }

                free(user_id);

                // checks if user is already loaded
                if (array_null_contains(users, pw->pw_name))
                {
                    sudo_log(SUDO_CONV_ERROR_MSG, "Found duplicate of user %s, skipping.\n", pw->pw_name);
                    continue;
                }

                // resize array
                if (user_count+1 == user_size)
                {
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
    }

    fclose(fp);
    free(buffer);

    if (error == -1)
    {
        free_2d_null(users);
        sudo_log(SUDO_CONV_ERROR_MSG, "Cannot allocate data.\n");
        return false;
    }
    if (error == -2)
    {
        free_2d_null(users);
        return false;
    }
    if (user_count < MIN_AUTH_USERS)
    {
        free_2d_null(users);
        sudo_log(SUDO_CONV_ERROR_MSG, "Not enough users set in %s (minimum is %d).\n", STR(PLUGIN_CONF_FILE), MIN_AUTH_USERS);
        return false;
    }

    return true;
}

/*
Builds envp array for exec
*/
static char ** build_envp(command_data * command)
{
    static char ** envp;
    int i = 0;

    if ((envp = malloc(5 * sizeof(char *))) == NULL)
    {
        return NULL;
    }

    if (asprintf(&envp[i++], "USER=%s", command->user) == -1 ||
        asprintf(&envp[i++], "HOME=%s", command->home) == -1 ||
        asprintf(&envp[i++], "PATH=%s", command->path) == -1 ||
        asprintf(&envp[i++], "PWD=%s",  command->pwd ) == -1)
    {
        free_2d(envp, i-1);
        return NULL;
    }
    envp[i] = NULL;

    return envp;
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

    for (ui = settings; *ui != NULL; ui++)
    {
        if (str_case_starts(*ui, "runas_user="))
        {
            runas_user = *ui + sizeof("runas_user=") - 1;
            break;
        }
        if (str_case_starts(*ui, "runas_group="))
        {
            runas_group = *ui + sizeof("runas_group=") - 1;
            break;
        }

        // Check to see if sudo was called as sudoedit or with -e flag
        if (strcasecmp(*ui, "sudoedit=true") == 0)
        {
            use_sudoedit = true;
        }

        /* Plugin doesn't support running sudo with no arguments. */
        if (strcasecmp(*ui, "implied_shell=true") == 0)
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
        if (str_case_starts(*ui, "cwd="))
        {
            cwd = *ui + sizeof("cwd=") - 1;
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

    openlog("sudo", LOG_PID|LOG_CONS, LOG_USER); //LOG_AUTH?

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

    if (commands_fd != -1)
    {
        close(commands_fd);
        flock(commands_fd, LOCK_UN);
    }

    closelog();

    /* The policy might log the command exit status here. */
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
Save all commands to file
*/
static int save(command_data ** commands)
{
    int tmp_fd;
    char fileNameArray[] = PLUGIN_COMMANDS_TEMP_FILE;
    char * fileName = mktemp(fileNameArray);

    if ( !fileName || (tmp_fd = open(fileName, O_RDWR | O_CREAT | O_EXCL, S_IWUSR | S_IRUSR)) == -1 )
    {
        return false;
    }

    /* Commands count */
    size_t count = commands_array_len(commands);

    if (write(tmp_fd, &count, 4) != 4)
    {
        close(tmp_fd);
        unlink(fileName);
        return false;
    }

    /* Save each command */
    size_t i = 0;
    while (commands[i])
    {
        if (!save_command(commands[i], tmp_fd))
        {
            close(tmp_fd);
            unlink(fileName);
            return false;
        }
        i++;
    }

    if (rename(fileName, PLUGIN_COMMANDS_FILE) == -1)
    {
        close(tmp_fd);
        unlink(fileName);
        return false;
    }
    close(tmp_fd);

    return true;
}

/*
Load next command from file
*/
static command_data * load_command(int fd)
{
    unsigned char sudoedit[2];
    command_data * command;

    if ( (command = make_command()) == NULL )
    {
        return NULL;
    }

    if (!load_string(fd, &command->file))
    {
        free(command);
        return NULL;
    }

    command->argv = load_string_array(fd);

    if (!command->argv)
    {
        free_command(command);
        return NULL;
    }

    if ((read(fd, sudoedit, 2) != 2)||
        !load_string(fd, &command->runas_user) ||
        !load_string(fd, &command->runas_group) ||
        !load_string(fd, &command->user) ||
        !load_string(fd, &command->home) ||
        !load_string(fd, &command->path) ||
        !load_string(fd, &command->pwd))
    {
        free_command(command);
        return NULL;
    }

    command->sudoedit = (char)convert_from_bytes(sudoedit, 2);

    command->exec_by_users = load_string_array(fd);

    if (!command->exec_by_users)
    {
        free_command(command);
        return NULL;
    }

    command->rem_by_users = load_string_array(fd);

    if (!command->rem_by_users)
    {
        free_command(command);
        return NULL;
    }

    return command;
}

/*
Tests if file lock does not exist and locks file
*/
static int try_lock(char * file)
{
    if ( (commands_fd = open(file, O_RDWR | O_CREAT, 0666)) == -1 )
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
Load all commands from file
*/
static command_data ** load()
{
    command_data ** cmds;
    unsigned char int_buffer[4];

    if (commands_fd == -1)
    {
        return NULL;
    }

    /* Commands count */
    if (read(commands_fd, int_buffer, 4) != 4)
    {
        return NULL;
    }

    size_t count = convert_from_bytes(int_buffer, 4);

    if ( (cmds = malloc((count+1) * sizeof(command_data*))) == NULL )
    {
        sudo_log(SUDO_CONV_ERROR_MSG, "Cannot allocate data.\n");
        return NULL;
    }


    /* Load each command */
    for (size_t i = 0; i < count; i++)
    {
        if ((cmds[i] = load_command(commands_fd)) == NULL)
        {
            cmds[i] = NULL;
            free_commands_null(cmds);

            sudo_log(SUDO_CONV_ERROR_MSG, "Cannot allocate data.\n");
            return NULL;
        }
    }

    cmds[count] = NULL;

    return cmds;
}

/*
Save command to binary file
*/
static int save_command(command_data * command, int fd)
{
    size_t argc;
    char ** argv;

    int result = save_string(command->file, fd);

    /*  Arguments count  */
    if ((argc = str_array_len(command->argv)) > MAX_2_BYTES)
    {
        return false;
    }
    result &= (write(fd, &argc, 2) == 2);

    /*  Arguments  */
    argv = command->argv;
    while (*argv)
    {
        result &= save_string(*argv, fd);
        argv++;
    }

    /*  Other data  */
    result &= (write(fd, &command->sudoedit, 2) == 2) &&
              save_string(command->runas_user, fd) &&
              save_string(command->runas_group, fd) &&
              save_string(command->user, fd) &&
              save_string(command->home, fd) &&
              save_string(command->path, fd) &&
              save_string(command->pwd, fd);

    /*  exec_by_users  */
    if ((argc = str_array_len(command->exec_by_users)) > MAX_2_BYTES)
    {
        return false;
    }
    result &= (write(fd, &argc, 2) == 2);

    argv = command->exec_by_users;
    if (argv)
    while (*argv)
    {
        result &= save_string(*argv, fd);
        argv++;
    }

    /*  rem_by_users  */
    if ((argc = str_array_len(command->rem_by_users)) > MAX_2_BYTES)
    {
        return false;
    }
    result &= (write(fd, &argc, 2) == 2);

    argv = command->rem_by_users;
    if (argv)
    while (*argv)
    {
        result &= save_string(*argv, fd);
        argv++;
    }

    return result;
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
        msgs[0].msg = strdup(msg[i]->msg);
        msgs[0].msg_type = SUDO_CONV_PROMPT_MASK;

        sudo_conv(1, msgs, replies);

        reply[i].resp = strdup(replies[0].reply);
        reply[i].resp_retcode = 0;
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
    result = pam_authenticate(pamh, PAM_DISALLOW_NULL_AUTHTOK);

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

    char * com_argv = concat((char**) command->argv, " ");
    syslog(LOG_INFO, "execute %s", com_argv);
    free(com_argv);

    pid_t pid;

    if ((pid = fork()) < 0) /* Fork a child process */
    {
        return false;
    }
    else if (pid == 0) /* For the child process */
    {
        char ** envp = build_envp(command);

        if (chdir(command->pwd) == -1)
        {
            free_2d_null(envp);
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

        /* Execute the command  */
        if (execve(command->file, &command->argv[0], &envp[0]) < 0)
        {
            char * com_argv = concat((char**) command->argv, " ");
            free(com_argv);

            _exit(1);
        }

        return true;
    }
    else /* For the parent  */
    {
        int status;
        while (wait(&status) != pid)
        {
            // wait
        }
        return (status == 0);
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

    /* Run text editor */
    command_data * cmd = make_command();
    cmd->file = editor;
    cmd->argv = malloc(3 * sizeof(char*));
    cmd->argv[0] = x_strdup(basename(editor));
    cmd->argv[1] = file;
    cmd->argv[2] = NULL;
    cmd->user = strdup(getenv("USER"));
    cmd->home = strdup(getenv("HOME"));
    cmd->path = strdup(getenv("PATH"));
    cmd->pwd  = strdup(getenv("PWD"));

    cmd->runas_user = x_strdup(user);

    int result = execute(cmd, false);

    free_command(cmd);
    return result;
}

/*
DIFF function for sudoedit
*/
static int run_diff(command_data * commmand)
{
    if (!commmand || !commmand->argv)
    {
        return false;
    }

    char * file1 = commmand->argv[3];
    char * file2 = commmand->argv[4];

    if (!file1 || !file2)
    {
        return false;
    }

    /* Run diff */
    command_data * cmd = make_command();
    cmd->file = strdup("/usr/bin/diff");
    cmd->argv = malloc(4 * sizeof(char*));
    cmd->argv[0] = strdup("diff");
    cmd->argv[1] = strdup(file1);
    cmd->argv[2] = strdup(file2);
    cmd->argv[3] = NULL;
    cmd->user = strdup(getenv("USER"));
    cmd->home = strdup(getenv("HOME"));
    cmd->path = strdup(getenv("PATH"));
    cmd->pwd  = strdup(getenv("PWD"));

    sudo_log(SUDO_CONV_ERROR_MSG, "DIFF %s\n", file2);

    int result = execute(cmd, true);

    free_command(cmd);
    return result;
}

/*
Creates copy of file, open it with editor, save to list
*/
static int sudoedit(command_data * command)
{
    if (!command || !command->argv)
    {
        return false;
    }

    char * orig_file_path = command->argv[1];
    char * orig_file = basename(orig_file_path);
    char * temp_file_path;
    char * fileNameArray;

    if (asprintf(&fileNameArray, "/var/%s-XXXXXX", orig_file) < 0)
    {
        sudo_log(SUDO_CONV_ERROR_MSG, "Cannot allocate data.\n");
        return -1;
    }

    temp_file_path = mktemp(fileNameArray);

    /* Copy file xxx to xxx.tmp */
    if (! copy_file(orig_file_path, temp_file_path))
    {
        free(fileNameArray);
        sudo_log(SUDO_CONV_ERROR_MSG, "Cannot copy file.\n");
        return -1;
    }

    if (chown(temp_file_path, getpwnam(user)->pw_uid, getpwnam(user)->pw_gid) == -1 || chmod(temp_file_path, S_IRUSR | S_IWUSR) == -1)
    {
        free(temp_file_path);
        sudo_log(SUDO_CONV_ERROR_MSG, "Cannot change attributes of file.\n");
        return -1;
    }

    /* Run text editor */
    if (! run_editor(temp_file_path))
    {
        unlink(temp_file_path);
        free(fileNameArray);
        return -1;
    }

    /* Changes */
    int result = cmp_files(orig_file_path, temp_file_path);

    // error
    if (result == -1)
    {
        unlink(temp_file_path);
        free(fileNameArray);
        return false;
    }
    //no changes
    else if (result == 1)
    {
        unlink(temp_file_path);
        free(fileNameArray);
        return false;
    }
    // changes
    else if (result == 0)
    {
        /* Save command: "mv -f -T xxx.tmp xxx" */
        char ** new_argv = malloc(6 * sizeof(char*));
        char * path = strdup("/usr/bin/mv");
        new_argv[0] = strdup("mv");
        new_argv[1] = strdup("-f");
        new_argv[2] = strdup("-T");
        new_argv[3] = strdup(temp_file_path);
        new_argv[4] = strdup(orig_file_path);
        new_argv[5] = NULL;

        if (!path || !new_argv[0] || !new_argv[1] || !new_argv[2])
        {
            sudo_log(SUDO_CONV_ERROR_MSG, "Cannot allocate data.\n");
            free(path);
            free_2d_null(new_argv);
            return -1;
        }

        result = append_command(path, new_argv, 2);

        free(path);
        free_2d_null(new_argv);
    }

    return result;
}

/*
Marks command for execution and/or execute command list
Returns next index in command list
*/
static int auth_exec(command_data ** cmds, int i)
{
                if (cmds[i]->sudoedit == 1)
                {
                    if (sudoedit(cmds[i]))
                    {
                        cmds = remove_command(cmds, cmds[i]);

                        syslog(LOG_INFO, "%s edited %s", user, cmds[i]->argv[1]);

                        // save commands
                        if (!save(cmds))
                        {
                            sudo_log(SUDO_CONV_ERROR_MSG, "Cannot save commands.\n");
                            return -1;
                        }
                        return i;
                    }
                    else
                    {
                        return ++i;
                    }
                }

                if (!array_null_contains(cmds[i]->exec_by_users, user))
                {
                    // set me as authorized user
                    cmds[i]->exec_by_users = add_string(cmds[i]->exec_by_users, strdup(user));

                    char * com_argv = concat((char**) cmds[i]->argv, " ");
                    syslog(LOG_INFO, "%s authorised to run %s", user, com_argv);
                    free(com_argv);

                    if (!save(cmds))
                    {
                        sudo_log(SUDO_CONV_ERROR_MSG, "Cannot save commands.\n");
                        return -1;
                    }
                }
                else if (str_array_len(cmds[i]->exec_by_users) < MIN_AUTH_USERS)
                {
                    // already authorized by me
                    sudo_log(SUDO_CONV_ERROR_MSG, "Command already authorized, skipping.\n");
                    return ++i;
                }

                if (str_array_len(cmds[i]->exec_by_users) < MIN_AUTH_USERS)
                {
                    return ++i;
                }

                bool as_root = (cmds[i]->sudoedit == 2) ? true : false;

                if (execute(cmds[i], as_root))
                {
                    cmds = remove_command(cmds, cmds[i]);

                    // save commands
                    if (!save(cmds))
                    {
                        sudo_log(SUDO_CONV_ERROR_MSG, "Cannot save commands.\n");
                        return -1;
                    }
                }
                else
                {
                    sudo_log(SUDO_CONV_ERROR_MSG, "Error in command execution, skipping.\n");
                    return ++i;
                }

                return i;
}

/*
Marks command for delete and/or remove command list
Returns next index in command list
*/
static int auth_remove(command_data ** cmds, int i)
{
    if (!array_null_contains(cmds[i]->rem_by_users, user))
    {
        // set me as authorized user
        cmds[i]->rem_by_users = add_string(cmds[i]->rem_by_users, strdup(user));

        char * com_argv = concat((char**) cmds[i]->argv, " ");
        syslog(LOG_INFO, "%s authorised to remove %s", user, com_argv);
        free(com_argv);

        // save commands
        if (!save(cmds))
        {
            sudo_log(SUDO_CONV_ERROR_MSG, "Cannot remove command.\n");
            return -1;
        }
    }
    else if (str_array_len(cmds[i]->rem_by_users) < MIN_AUTH_USERS)
    {
        // already authorized by me
        sudo_log(SUDO_CONV_ERROR_MSG, "Command already authorized, skipping.\n");
        return ++i;
    }

    if ((strcmp(cmds[i]->user, user) == 0) ||                    // I wrote command (and I am admin)   OR
        str_array_len(cmds[i]->rem_by_users) == MIN_AUTH_USERS)  // two admins already authorised
    {
        // remove command
        cmds = remove_command(cmds, cmds[i]);

        char * com_argv = concat((char**) cmds[i]->argv, " ");
        syslog(LOG_INFO, "%s removed %s", user, com_argv);
        free(com_argv);

        // save commands
        if (!save(cmds))
        {
            sudo_log(SUDO_CONV_ERROR_MSG, "Cannot remove command.\n");
            return -1;
        }

        return i;
    }
    else
    {
        return ++i;
    }
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

    if (strcmp(argv[0],"auth") == 0 || strcmp(argv[0],"list") == 0)
    {
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
            sudo_log(SUDO_CONV_ERROR_MSG, "User %s cannot authorise executing commands.\n", user);
            return -1;
        }

        /* Authenticate user */
        if (! check_pam(user))
        {
            return -1;
        }

        command_data ** cmds = load();

        /* No commands found */
        if (!cmds || !cmds[0])
        {
            sudo_log(SUDO_CONV_ERROR_MSG, "No commands found.\n");
            free_commands_null(cmds);
            return 0;
        }

        size_t length = commands_array_len(cmds);
        int show_only = (strcmp(argv[0],"list") == 0);
        int mode = (argc > 1 && strcmp(argv[1],"verbose") == 0);

        /* Prepare conversation */
        struct sudo_conv_message msgs[1];
        struct sudo_conv_reply replies[1];

        msgs[0].msg_type = SUDO_CONV_PROMPT_ECHO_ON;
        msgs[0].msg = strdup("Execute, skip or remove? [e/s/r]:");

        size_t i = 0, index = 1;
        while (cmds[i])
        {
            sudo_log(SUDO_CONV_ERROR_MSG, "%s%u/%u: ", show_only ? "" : "\n", index, length);

            if (show_only)
            {
                print_command(cmds[i], mode);
                i++;
                index++;
                continue;
            }
            else
            {
                mode = (cmds[i]->sudoedit == 2) ? 2 : 1;
                print_command(cmds[i], mode);
            }

            sudo_conv(1, msgs, replies);

            /* Execute */
            if (strcasecmp(replies[0].reply,"e") == 0)
            {
                int result = auth_exec(cmds, i);

                if (result < 0)
                {
                    free_commands_null(cmds);
                    return -1;
                }

                index++;
                i = result;
            }
            /* Remove from list */
            else if (strcasecmp(replies[0].reply,"r") == 0)
            {
                int result = auth_remove(cmds, i);

                if (result < 0)
                {
                    free_commands_null(cmds);
                    return -1;
                }

                index++;
                i = result;
            }
            /* Skip */
            else if (strcasecmp(replies[0].reply,"s") == 0)
            {
                index++;
                i++;
            }
            /* Quit */
            else if (strcasecmp(replies[0].reply,"q") == 0)
            {
                break;
            }
        }

        free_commands_null(cmds);
        return 0;
    }
    else if (use_sudoedit)
    {
        syslog(LOG_INFO, "sudoedit %s", argv[1]);
        char * file;

        if ((file = find_in_path(argv[1], envp, F_OK)) == NULL)
        {
            sudo_log(SUDO_CONV_ERROR_MSG, "Cannot find file %s\n", argv[1]);
            return -1;
        }
        char ** new_argv = (char**) argv;
        new_argv[1] = file;

        int result = append_command(argv[0], new_argv, 1);

        return (result) ? 0 : -1;
    }
    else
    {
        char * com_argv = concat((char**) argv, " ");
        syslog(LOG_INFO, "command: %s", com_argv);
        free(com_argv);

        char * path;

        if ((path = find_in_path(argv[0], envp, X_OK)) == NULL)
        {
            sudo_log(SUDO_CONV_ERROR_MSG, "Cannot find file %s\n", argv[0]);
            return -1;
        }

        int result = append_command(path, (char**) argv, 0);
        free(path);

        return (result) ? 0 : -1;
    }
}

/*
Create command from arguments and append to list of commands
*/
static int append_command(char * file, char ** argv, char flag_sudoedit)
{
    int result;
    command_data * command = make_command();

    if (!command)
    {
        sudo_log(SUDO_CONV_ERROR_MSG, "Cannot allocate data.\n");
        return -1;
    }

    command->file = file;
    command->argv = argv;
    command->sudoedit = flag_sudoedit;
    command->user = getenv("USER");
    command->home = getenv("HOME");
    command->path = getenv("PATH");
    command->pwd  = getenv("PWD");
    command->runas_user = x_strdup(runas_user);
    command->runas_group = x_strdup(runas_group);

    /* Is user allowed to authorise */
    if (array_null_contains(users, user))
    {
        command->exec_by_users = add_string(command->exec_by_users, strdup(user));
    }

    /* Load commands from file */
    command_data ** cmds = load();
    command_data ** cmds_save;

    //print_command(command, true);

    if (cmds)
    {
        if ((cmds_save = add_command(cmds, command)) == NULL)
        {
            sudo_log(SUDO_CONV_ERROR_MSG, "Cannot allocate data.\n");
            free_commands_null(cmds);
            return -1;
        }

        /* Save commands to file */
        result = save(cmds_save);

        size_t count = commands_array_len(cmds_save);

        cmds_save[count-1] = NULL;

        free_commands_null(cmds_save);
    }
    else
    {
        if ((cmds_save = malloc(2 * sizeof(command_data*))) == NULL)
        {
            sudo_log(SUDO_CONV_ERROR_MSG, "Cannot allocate data.\n");
            free_commands_null(cmds);
            return -1;
        }
        cmds_save[0] = command;
        cmds_save[1] = NULL;

        /* Save commands to file */
        result = save(cmds_save);

        free(cmds_save);
    }

    free(command->runas_user);
    free(command->runas_group);

    if (result)
    {
        return 0;
    }
    else
    {
        sudo_log(SUDO_CONV_ERROR_MSG, "Command was not saved.\n");
        return -1;
    }
}

/*
Remove command from commands array
*/
static command_data ** remove_command(command_data ** array, command_data * cmd)
{
    if (!array || !cmd)
    {
        return NULL;
    }

    size_t i = 0;
    size_t index = 0;

    while (array[i])
    {
        if (array[i] != cmd)
        {
            array[index] = array[i];
            index++;
        }
        else
        {
            free_command(cmd);
        }
        i++;
    }

    array[index] = NULL;

    return array;
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
    bool allowed;

    if ((allowed = array_null_contains(users, check_user)))
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
