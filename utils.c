/*
 * Copyright 2015 Horváth Henrich
 *
 * Sudo security plugin is free software
 * released under GNU Lesser General Public License.
 *
*/

#include "utils.h"

bool str_starts(const char * a, const char * b)
{
    return (strncmp(a, b, strlen(b)) == 0);
}

bool str_case_starts(const char * a, const char * b)
{
    return (strncasecmp(a, b, strlen(b)) == 0);
}

bool array_null_contains(char ** array, const char * str)
{
    if (!array || !str)
    {
        return false;
    }

    char ** item = array;

    while (*item)
    {
        if (strcmp(*item, str) == 0)
        {
            return true;
        }

        item++;
    }

    return false;
}

char * concat(char ** array, char * separator)
{
    if (!array)
    {
        return NULL;
    }

    char * str = NULL;
    size_t total_length = 0;
    size_t separator_length = (separator) ? strlen(separator) : 1;  // 1 for '0'

    char ** current = array;

    while (*current != NULL)
    {
        total_length += strlen(*current) + separator_length;
        current++;
    }

    if (total_length == 0 || (str = malloc(total_length)) == NULL)
    {
        return NULL;
    }

    str[0] = '\0';
    current = array;

    while (*current != NULL)
    {
        strcat(str, *current);

        if (*(++current) && separator)
        {
            strcat(str, separator);
        }
    }

  return str;
}

char ** add_string(char ** array, char * str)
{
    if (!str)
    {
        return NULL;
    }

    size_t count = str_array_len(array);

    char ** strings;

    if ( (strings = realloc(array, (count+2) * sizeof(char*) )) == NULL )
    {
        return NULL;
    }

    strings[count] = str;
    strings[count+1] = NULL;

    return strings;
}

char * rem_whitespace(char * str)
{
    if (!str)
    {
        return NULL;
    }

    char * c = str;

    while (*c != '\0' && !isspace((unsigned char)*c))
    {
        ++c;
    }

    if (*c != '\0')
    {
        *c = '\0';
    }

    return str;
}

size_t str_array_len(char ** array)
{
    if (!array)
    {
        return 0;
    }

    size_t len = 0;

    char ** str = array;

    while (*str != NULL)
    {
        str++;
        len++;
    }

    return len;
}

void free_2d_null(char ** array)
{
    if (!array)
    {
        return;
    }

    char ** str = array;

    while (*str)
    {
        free(*str);
        str++;
    }

    free(array);
}

size_t convert_from_bytes(unsigned char * array, size_t bytes)
{
    if (!array)
    {
        return -1;
    }

    switch (bytes)
    {
        case 1:
            return array[0];
        case 2:
            return array[0] + (array[1] << 8);
        case 4:
            return array[0] + (array[1] << 8) + (array[2] << 16) + (array[3] << 24);
        default:
            return -1;
    }
}

char * find_in_path(char * command, char ** envp, int mode)
{
    if (!command)
    {
        return NULL;
    }

    char * path = NULL, * cp_path = NULL, * cmd = NULL;

    /* Already a path */
    if (strchr(command,'/') != NULL)
    {
        if (access(command, mode) == 0)
        {
            return strdup(command);
        }
    }

    for (char ** ep = envp; *ep != NULL; ep++)
    {
        if (str_starts(*ep,"PATH="))
        {
            path = * ep + 5;
            break;
        }
    }

    if (!path)
    {
        return NULL;
    }

    if ((cp_path = strdup(path)) != NULL)
    {
        char * token;

        /* First path */
        token = strtok(cp_path, ":");

        while (token)
        {
            if (strcmp(token,".") == 0)
            {
                char * cwd = get_current_dir_name();
                if (!cwd)
                {
                    return NULL;
                }
                if (asprintf(&cmd, "%s/%s", cwd, command) < 0)
                {
                    free(cwd);
                    return NULL;
                }
                free(cwd);
            }
            else if (token[0] == '\0')
            {
                char * cwd = get_current_dir_name();
                if (!cwd)
                {
                    return NULL;
                }
                if (asprintf(&cmd, "%s/%s", cwd, command) < 0)
                {
                    free(cwd);
                    return NULL;
                }
                free(cwd);
            }
            else
            {
                if (asprintf(&cmd, "%s/%s", token, command) < 0)
                {
                    free(cp_path);
                    return NULL;
                }
            }

            if (access(cmd, mode) == 0)
            {
                free(cp_path);
                return cmd;
            }
            free(cmd);

            /* Next path */
            token = strtok(NULL, ":");
        };
    }
    free(cp_path);

    for (char ** ep = envp; *ep != NULL; ep++)
    {
        if (str_starts(*ep,"PATH="))
        {
            path = * ep + 5;
            break;
        }
    }

    return NULL;
}

char * getenv_from_envp(char * name, char ** envp)
{
    char * key;

    if (asprintf(&key, "%s=", name) < 0)
    {
        return NULL;
    }

    for (char ** ep = envp; *ep != NULL; ep++)
    {
        if (str_starts(*ep, key))
        {
            size_t len = strlen(key);
            free(key);
            return *ep + len;
        }
    }

    free(key);
    return NULL;
}

char * find_editor(char ** envp)
{
    char * editor;

    if ((editor = getenv_from_envp("SUDO_EDITOR", envp)))
    {
        return strdup(editor);
    }

    if ((editor = getenv_from_envp("VISUAL", envp)))
    {
        return strdup(editor);
    }

    if ((editor = getenv_from_envp("EDITOR", envp)))
    {
        return strdup(editor);
    }

    /* Try to search for VIM editor */
    if (access("/usr/bin/vi", X_OK) == 0)
    {
        return strdup("/usr/bin/vi");
    }

    return NULL;
}
