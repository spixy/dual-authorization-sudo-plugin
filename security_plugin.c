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
#include <sudo_plugin.h>
#include <unistd.h>

#include <security/pam_appl.h>
#include <security/pam_modules.h>
#include <security/_pam_macros.h>

#include <sys/sendfile.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>

#include "sudo_helper.h"

#define PACKAGE_VERSION 0.1

static struct plugin_state plugin_state;
static sudo_conv_t sudo_conv;
static sudo_printf_t sudo_log;
static const char * runas_user = NULL;
static const char * runas_group = NULL;
static char ** users = NULL;
static char * user = NULL;
static char * cwd = NULL;
static char * pwd = NULL;
static int use_sudoedit = false;

static int load_config();
static int copy_file(int fd, char * to);

static void print_command(command_data * command, int full);
static command_data * load_command(FILE * fp);
static command_data ** load();
static int save(command_data ** commands);
static int save_command(command_data * command, int fd);
static int append_command(char ** argv);

static int check_passwd(const char* auth_user);
static int check_pam_result(int result);
static int PAM_conv (int, const struct pam_message**, struct pam_response**, void*);
static struct pam_conv PAM_converse =
{
    PAM_conv,
    NULL
};

static char ** build_envp(command_data * command);
static int execute(command_data * command);

/*
Prints command with arguments
*/
static void print_command(command_data * command, int full)
{
    char ** argv;
    argv = command->argv;

    while (*argv)
    {
        sudo_log(SUDO_CONV_INFO_MSG, "%s ", *argv);
        argv++;
    }

    if (full)
    {
        sudo_log(SUDO_CONV_INFO_MSG, "\nrunas user:%s runas group:%s", command->runas_user, command->runas_group);
        sudo_log(SUDO_CONV_INFO_MSG, "\nuser:%s home:%s pwd:%s", command->user, command->home, command->pwd);
        sudo_log(SUDO_CONV_INFO_MSG, "\nauth by:%s rem by:%s\n", command->auth_by_user, command->rem_by_user);
    }
    else
    {
        sudo_log(SUDO_CONV_INFO_MSG, "\n");
    }
}

/*
Reads data (users + prompt) from conf file
*/
static int load_config()
{
    FILE * fp;

    if ( (users = calloc( (AUTH_USERS+1), sizeof(char*))) == NULL)
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
            if (len == 0 || buffer[0] == '#' || buffer[0] == '\0')
                continue;

            // parsing "user xxx"
            if (str_case_starts(buffer, "user ") && (size_t)len > strlen("user "))
            {
                char * user_name = strdup(str_no_whitespace(buffer + strlen("user ")));

                // checks if user exists
                if (!getpwnam(user_name))
                {
                    sudo_log(SUDO_CONV_ERROR_MSG, "User %s not found.\n", user_name);
                    free(user_name);
                    continue;
                }

                // checks if user is already loaded
                if (array_contains(user_name, users, usercount))
                {
                    sudo_log(SUDO_CONV_ERROR_MSG, "Found duplicate of user %s, skipping.\n", user_name);
                    free(user_name);
                    continue;
                }

                // maximum user count loaded
                if (usercount == AUTH_USERS)
                {
                    free(user_name);
                    usercount++;
                    break;
                }

                // save user name
                users[usercount] = malloc( strlen(user_name) + 1 );
                strcpy(users[usercount], user_name);

                free(user_name);
                usercount++;
            }
            else if (str_case_starts(buffer, "uid ") && (size_t)len > strlen("uid ")) // parsing "uid 123"
            {
                char * user_id = strdup(str_no_whitespace(buffer + strlen("uid ")));

                // get user struct
                uid_t id = strtol(user_id, NULL, 10);
                pw = getpwuid(id);

                if (!pw)
                {
                    sudo_log(SUDO_CONV_ERROR_MSG, "User with uid %s not found.\n", user_id);
                    free(user_id);
                    continue;
                }

                // checks if user is already loaded
                if (array_contains(pw->pw_name, users, usercount))
                {
                    free(user_id);
                    sudo_log(SUDO_CONV_ERROR_MSG, "Found duplicate of user %s, skipping.\n", pw->pw_name);
                    continue;
                }

                // maximum user count loaded
                if (usercount == AUTH_USERS)
                {
                    free(user_id);
                    usercount++;
                    break;
                }

                // save user name
                users[usercount] = malloc( strlen(pw->pw_name) + 1 );
                strcpy(users[usercount], pw->pw_name);

                free(user_id);
                usercount++;
            }
    }

    fclose(fp);
    free(buffer);

    // check if it loaded needed user count
    if (usercount > AUTH_USERS)
    {
        free_2d(users, AUTH_USERS);
        sudo_log(SUDO_CONV_ERROR_MSG, "Too many users stored in %s (maximum is %d).\n", STR(PLUGIN_CONF_FILE), AUTH_USERS);
        return false;
    }
    if (usercount < AUTH_USERS)
    {
        free_2d(users, AUTH_USERS);
        sudo_log(SUDO_CONV_ERROR_MSG, "Not enough users set in %s (minimum is %d).\n", STR(PLUGIN_CONF_FILE) , AUTH_USERS);
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

    if ( (envp = malloc(5 * sizeof(char *))) == NULL )
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
        if (str_case_starts(*ui, "sudoedit=true"))
        {
            use_sudoedit = true;
        }

        /* Plugin doesn't support running sudo with no arguments. */
        if (str_case_starts(*ui, "implied_shell=true"))
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

    /* Plugin state */
    plugin_state.envp = (char **)user_env;
    plugin_state.settings = settings;
    plugin_state.user_info = user_info;

    load_config();

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
    free_2d(users, AUTH_USERS);

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
Copy file (fd)
*/
static int copy_file(int fd, char * to)
{
    int targetfd;
    struct stat s;
    off_t offset = 0;

    if ((targetfd = open(to, O_RDWR | O_CREAT, S_IWUSR | S_IRUSR)) == -1)
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

/*
Save all commands to file
*/
static int save(command_data ** commands)
{
    int fd;
    char fileNameArray[] = PLUGIN_COMMANDS_TEMP_FILE;
    char * fileName = mktemp(fileNameArray);

    if ( (fd = open(fileName, O_RDWR | O_CREAT | O_EXCL, S_IWUSR | S_IRUSR)) == -1 )
    {
        free(fileName);
        return false;
    }

    /* Commands count */
    unsigned int count = commands_array_len(commands);

    if (write(fd, &count, 4) != 4)
    {
        close(fd);
        free(fileName);
        return false;
    }

    /* Save each command */
    unsigned int i = 0;
    while (commands[i])
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

    int result = copy_file(fd, PLUGIN_COMMANDS_FILE);

    unlink(fileName);
    close(fd);

    return result;
}

/*
Load string from file
*/
static char * load_string(FILE * fp)
{
    unsigned char int_buffer[4];

    if (fread(int_buffer, 4, 1, fp) != 1)
    {
        return NULL;
    }

    unsigned int len = int_buffer[0] + int_buffer[1]*256 + int_buffer[2]*256*256 + int_buffer[3]*256*256*256;
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

    /* Checking length */
    if (len != strlen(str)+1)
    {
        free(str);
        return NULL;
    }

    return str;
}

/*
Load next command from file
*/
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

    if ( (command->argv = malloc((argc+1)*sizeof(char*))) == NULL )
    {
        free_command(command);
        return NULL;
    }

    for (unsigned int i = 0; i < argc; i++)
    {
        char * str = load_string(fp);

        if (!str)
        {
            free(command->argv);
            free(command);
            return NULL;
        }

        command->argv[i] = str;
    }

    command->argv[argc] = NULL;
    command->runas_user = load_string(fp);
    command->runas_group = load_string(fp);
    command->user = load_string(fp);
    command->home = load_string(fp);
    command->path = load_string(fp);
    command->pwd = load_string(fp);
    command->auth_by_user = load_string(fp);
    command->rem_by_user = load_string(fp);

    return command;
}

/*
Load all commands from file
*/
static command_data ** load()
{
    FILE * fp;
    command_data ** cmds;
    unsigned char int_buffer[4];

    if ( (fp = fopen(PLUGIN_COMMANDS_FILE, "rb")) == NULL )
    {
        return NULL;
    }

    /* Commands count */
    if (fread(int_buffer, 4, 1, fp) != 1)
    {
        fclose(fp);
        return NULL;
    }

    unsigned int count = int_buffer[0] + int_buffer[1]*256 + int_buffer[2]*256*256 + int_buffer[3]*256*256*256;

    if ( (cmds = malloc( (count+1) * sizeof(command_data*) )) == NULL )
    {
        fclose(fp);
        sudo_log(SUDO_CONV_ERROR_MSG, "Cannot allocate data.\n");
        return NULL;
    }

    /* Load each command */
    for (unsigned int i = 0; i < count; i++)
    {
        if ((cmds[i] = load_command(fp)) == NULL)
        {
            cmds[i] = NULL;
            free_commands_null(cmds);
            fclose(fp);

            sudo_log(SUDO_CONV_ERROR_MSG, "Cannot allocate data.\n");
            return NULL;
        }
    }

    cmds[count] = NULL;

    fclose(fp);
    return cmds;
}

/*
Save command to binary file
*/
static int save_command(command_data * command, int fd)
{
    int result;
    char ** argv;
    argv = command->argv;

    /*  Arguments count  */
    unsigned int argc = str_array_len(command->argv);
    result = (write(fd, &argc, 2) == 2);

    /*  Arguments  */
    while (*argv)
    {
        result &= save_string(*argv, fd);
        argv++;
    }

    /*  Other data  */
    result &= save_string(command->runas_user, fd) &&
              save_string(command->runas_group, fd) &&
              save_string(command->user, fd) &&
              save_string(command->home, fd) &&
              save_string(command->path, fd) &&
              save_string(command->pwd, fd) &&
              save_string(command->auth_by_user, fd) &&
              save_string(command->rem_by_user, fd);

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
PAM conversation
*/
static int PAM_conv(int num_msg, const struct pam_message **msg, struct pam_response **resp, void *appdata_ptr)
{
    struct pam_response * reply = NULL;

    reply = (struct pam_response *) malloc(sizeof(struct pam_response) * num_msg);

    if (!reply)
        return PAM_CONV_ERR;

    reply[0].resp = strdup(pwd);
    reply[0].resp_retcode = 0;

    *resp = reply;

    return PAM_SUCCESS;
}

/*
Authenticate user via PAM
*/
static int check_passwd(const char* auth_user)
{
    pam_handle_t * pamh = NULL;

    /* Initialize PAM */
    int result = pam_start("sudo", auth_user, &PAM_converse, &pamh);

    if (!check_pam_result(result))
    {
        pam_end(pamh, result);
        return false;
    }

    /* Get password from user */
    struct sudo_conv_message msgs[1];
    char * msg = NULL;
    msgs[0].msg_type = SUDO_CONV_PROMPT_ECHO_OFF;

    if (asprintf(&msg, "%s password:", auth_user) == -1)
    {
        return false;
    }
    msgs[0].msg = msg;

    struct sudo_conv_reply replies[1];
    sudo_conv(1, msgs, replies);

    free(msg);
    pwd = replies[0].reply;

    /* Authenticate user  */
    result = pam_authenticate(pamh, PAM_DISALLOW_NULL_AUTHTOK);

    if (!check_pam_result(result))
    {
        pam_end(pamh, result);
        return false;
    }

    /* Check for account validation */
    result = pam_acct_mgmt(pamh, 0);

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
    if (!command)
        return false;

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

        /* Find executable path  */
        char * file = find_in_path(command->argv[0], envp);

        if (!file)
        {
            sudo_log(SUDO_CONV_ERROR_MSG, "Executable file not found.\n");
            return false;
        }

        /* Run as group */
        if (command->runas_group)
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
        if (command->runas_user)
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

        /* execute the command  */
        if (execve(file, &command->argv[0], &envp[0]) < 0)
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
    if (!argc || !argv[0])
    {
        sudo_log(SUDO_CONV_ERROR_MSG, "No command specified.\n");
        return -1;
    }

    if ((argc > 0) && (strcmp(argv[0],"list") == 0 || strcmp(argv[0], "la") == 0))
    {
        command_data ** cmds = load();

        /* No commands found */
        if (!cmds || !cmds[0])
        {
            sudo_log(SUDO_CONV_ERROR_MSG, "No commands found.\n");
            free_commands_null(cmds);
            return -1;
        }

        unsigned int i = 0;
        while (cmds[i])
        {
            print_command(cmds[i], false);
            i++;
        }

        free_commands_null(cmds);

        return 0;
    }
    else if (argc > 0 && strcmp(argv[0],"auth") == 0)
    {
        /* Authorise as other user */
        if (argc == 2)
        {
            if (!getpwnam(argv[1]))
            {
                sudo_log(SUDO_CONV_ERROR_MSG, "User %s not found.\n", argv[1]);
                return -1;
            }
            user = argv[1];
        }

        /* Is user allowed to authorise */
        if (!array_contains(user, users, AUTH_USERS))
        {
            sudo_log(SUDO_CONV_ERROR_MSG, "User %s cannot authorise executing commands.\n", user);
            return 0;
        }

        command_data ** cmds = load();

        /* No commands found */
        if (!cmds || !cmds[0])
        {
            sudo_log(SUDO_CONV_ERROR_MSG, "No commands found.\n");
            free_commands_null(cmds);
            return 0;
        }

        /* Authenticate user */
        if (! check_passwd(user))
        {
            free_commands_null(cmds);
            return -1;
        }

        unsigned int length = commands_array_len(cmds);

        /* Prepare conversation */
        struct sudo_conv_message msgs[1];
        struct sudo_conv_reply replies[1];

        char * msg = strdup("Execute, skip or remove? [e/s/r]:");
        msgs[0].msg_type = SUDO_CONV_PROMPT_ECHO_OFF;
        msgs[0].msg = msg;

        unsigned int i = 0, index = 1;
        while (cmds[i])
        {
            sudo_log(SUDO_CONV_ERROR_MSG, "%u/%u: ", index, length);
            print_command(cmds[i], false);

            sudo_conv(1, msgs, replies);

            /* Execute */
            if (strcasecmp(replies[0].reply,"e") == 0)
            {
                index++;
                if (!cmds[i]->auth_by_user)
                {
                    // set me as authorized user
                    cmds[i]->auth_by_user = strdup(user);
                    i++;
                }
                else if (strcmp(cmds[i]->auth_by_user, user) == 0)
                {
                    // already authorized by me
                    i++;
                    sudo_log(SUDO_CONV_ERROR_MSG, "Command already authorized, skipping.\n");
                }
                else
                {
                    cmds[i]->auth_by_user = strdup(BOTH_USERS_AUTHENTICATED);

                    // execute
                    if (execute(cmds[i]))
                    {
                        cmds = remove_command(cmds, cmds[i]);
                    }
                    else
                    {
                        i++;
                        sudo_log(SUDO_CONV_ERROR_MSG, "Error in command execution, skipping.\n");
                    }
                }
            }
            /* Remove from list */
            else if (strcasecmp(replies[0].reply,"r") == 0)
            {
                index++;
                if (!cmds[i]->rem_by_user)
                {
                    // set me as authorized user
                    cmds[i]->rem_by_user = strdup(user);
                    i++;
                }
                else if (strcmp(cmds[i]->rem_by_user, user) == 0)
                {
                    // already authorized by me
                    i++;
                    sudo_log(SUDO_CONV_ERROR_MSG, "Command already authorized, skipping.\n");
                }
                else
                {
                    // remove from list
                    cmds = remove_command(cmds, cmds[i]);
                }
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

        if (!save(cmds))
        {
            sudo_log(SUDO_CONV_ERROR_MSG, "Cannot save commands.\n");
        }

        free(msg);
        free_commands_null(cmds);

        return 1;
    }
    else if (use_sudoedit)
    {
        // copy existing file xxx to /tmp/yyy
        // open editor
        // load /tmp/yyy
        // save to /tmp/yyy
        // wait for close editor
        // save command: "mv -f -T /tmp/yyy xxx"

        char * editor = find_editor(plugin_state.envp);

        if (!editor)
        {
            sudo_log(SUDO_CONV_ERROR_MSG, "Cannot find editor.\n");
            free(editor);
            return -1;
        }

        char * env_pwd = getenv("PWD");
        char * orig_file = basename(argv[1]);
        char * orig_file_path;
        char * temp_file_path;

        if (asprintf(&orig_file_path, "%s/%s", env_pwd, orig_file) == -1 ||
            asprintf(&temp_file_path,"/tmp/%s", orig_file) == -1)
        {
            return -1;
        }

        /* Copy to tmp */
        int fd = open(orig_file_path, O_RDWR, S_IWUSR | S_IRUSR);
        copy_file(fd, temp_file_path);
        close(fd);

        /* Run text editor */
        command_data * cmd = make_command();
        cmd->argv = malloc(3 * sizeof(char*));
        cmd->argv[0] = editor;
        cmd->argv[1] = strdup(temp_file_path);
        cmd->argv[2] = NULL;
        cmd->user = getenv("USER");
        cmd->home = getenv("HOME");
        cmd->path = getenv("PATH");
        cmd->pwd  = env_pwd;
        if (runas_user)
            cmd->runas_user = strdup(runas_user);
        if (runas_group)
            cmd->runas_group = strdup(runas_group);
        execute(cmd);

        /* Save command */
        char ** new_argv = malloc(6 * sizeof(char*));
        new_argv[0] = strdup("mv");
        new_argv[1] = strdup("-f");
        new_argv[2] = strdup("-T");
        new_argv[3] = strdup(temp_file_path);
        new_argv[4] = strdup(orig_file_path);
        new_argv[5] = NULL;

        int result = append_command(new_argv);
        free_2d_null(new_argv);

        return (result) ? 0 : -1;
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

        int result = append_command((char**)argv);

        return (result) ? 0 : -1;
    }
}

/*
Create command from arguments and append to list of commands
*/
static int append_command(char ** argv)
{
    int result;

    command_data * command = make_command();
    command->argv = argv;
    command->user = getenv("USER");
    command->home = getenv("HOME");
    command->path = getenv("PATH");
    command->pwd  = getenv("PWD");
    if (runas_user)
        command->runas_user = strdup(runas_user);
    if (runas_group)
        command->runas_group = strdup(runas_group);

    /* Load commands from file */
    command_data ** cmds = load();
    command_data ** cmds_save;

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

        unsigned int count = commands_array_len(cmds_save);

        cmds_save[count-1] = NULL;

        free_commands_null(cmds_save);
    }
    else
    {
        if ( (cmds_save = malloc(2 * sizeof(command_data*))) == NULL )
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
List available privileges for the invoking user. Returns 1 on success, 0 on failure and -1 on error.
*/
static int sudo_list(int argc, char * const argv[], int verbose, const char *list_user)
{
    if (!users)
        return -1;

    const char * check_user = (list_user) ? list_user : user;

    if (array_contains(check_user, users, AUTH_USERS))
    {
        sudo_log(SUDO_CONV_INFO_MSG, "You are allowed to authorise commands.\n");
    }
    else
    {
        sudo_log(SUDO_CONV_INFO_MSG, "You are not allowed to authorise commands.\n");
    }

    if (verbose)
    {
        sudo_log(SUDO_CONV_INFO_MSG, "Users allowed to authorise commands:\n");

        /* Write authorities list */
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
