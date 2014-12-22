#ifndef SUDO_HELPER_INCLUDED
#define SUDO_HELPER_INCLUDED

#define PLUGIN_CONF_FILE "/etc/sudo_security_plugin.conf"
#define MAX_USER_LENGTH 32
#define MAX_GROUP_LENGTH 255 //"255 for AIX 5.3 and above"
#define MAX_NUM_LENGTH 15
#define MAX_LINE 40
#define MIN_USERS 2
#define MAX_USERS 2

#ifdef __TANDEM
# define ROOT_UID       65535
#else
# define ROOT_UID       0
#endif

struct plugin_state {
    char **envp;
    char * const *settings;
    char * const *user_info;
};

#endif // SUDO_HELPER_INCLUDED


/* The passwd structure.  */
//struct passwd
//{
//  char *pw_name;		/* Username.  */
//  char *pw_passwd;	/* Password.  */
//  __uid_t pw_uid;		/* User ID.  */
//  __gid_t pw_gid;		/* Group ID.  */
//  char *pw_gecos;		/* Real name.  */
//  char *pw_dir;		/* Home directory.  */
//  char *pw_shell;		/* Shell program.  */
//};

/* The group structure.	 */
//struct group
//{
//  char *gr_name;		/* Group name.	*/
//  char *gr_passwd;	/* Password.	*/
//  __gid_t gr_gid;		/* Group ID.	*/
//  char **gr_mem;		/* Member list.	*/
//};
