#include "io.h"

int copy_file(char * from, int target_fd)
{
    int source_fd;
    struct stat s;
    off_t offset = 0;

    /* Source file does not exist, do not need to copy */
    if ((source_fd = open(from, O_RDONLY)) == -1)
    {
        return -1;
    }

    if (fstat(source_fd, &s) < 0)
    {
        close(source_fd);
        return 0;
    }

    int result = (s.st_size > 0) ? (sendfile(target_fd, source_fd, &offset, s.st_size) == s.st_size) : 1;

    close(source_fd);
    return result;
}

bool cmp_files(char * oldFile, char * newFile)
{
    int ch1, ch2;
    bool result = true;

    FILE * fp1 = fopen(oldFile, "r");
    if (!fp1)
    {
        return false;
    }

    FILE * fp2 = fopen(newFile, "r");
    if (!fp2)
    {
        fclose(fp2);
        return false;
    }

    do
    {
        ch1 = fgetc(fp1);
        ch2 = fgetc(fp2);

        if (ch1 != ch2)
        {
            result = false;
            break;
        }
    } while (ch1 != EOF);

    fclose(fp1);
    fclose(fp2);

    return result;
}

bool save_int(size_t value, int bytes, int fd)
{
    unsigned char val1, val2, val3, val4;

    switch (bytes)
    {
        case 1:
            return (write(fd, &value, 1) == 1);
        case 2:
            val1 =  value        & 0xFF;
            val2 = (value >> 8)  & 0xFF;
            return (write(fd, &val1, 1) == 1) && (write(fd, &val2, 1) == 1);
        case 4:
            val1 =  value        & 0xFF;
            val2 = (value >> 8)  & 0xFF;
            val3 = (value >> 16) & 0xFF;
            val4 = (value >> 24) & 0xFF;
            return (write(fd, &val1, 1) == 1) && (write(fd, &val2, 1) == 1) && (write(fd, &val3, 1) == 1) && (write(fd, &val4, 1) == 1);
        default:
            return false;
    }
}

bool save_string(char * str, int fd)
{
    if (str)
    {
        // <length:4bytes><string>
        size_t length = strlen(str) + 1;

        return (length <= UINT32_MAX &&
                save_int(length, 4, fd) &&
                write(fd, str, length) == (ssize_t)length);
    }
    else
    {
        // 0000 (4 bytes)
        return save_int(0, 4, fd);
    }
}

bool save_string_array(char ** str_array, int fd)
{
    size_t len;
    char ** str;

    /*  Array length  */
    if ((len = str_array_len(str_array)) > UINT16_MAX)
    {
        return false;
    }
    int result = save_int(len, 2, fd);

    /*  Items  */
    str = str_array;

    if (str)
    while (*str)
    {
        result &= save_string(*str, fd);
        str++;
    }

    return result;
}

bool load_string(int fd, char ** str)
{
    unsigned char int_buffer[4];
    char * string;

    if (read(fd, int_buffer, 4) != 4)
    {
        return false;
    }

    size_t len = convert_from_bytes(int_buffer, 4);

    // Empty string
    if (len == 0)
    {
        *str = NULL;
        return true;
    }

    // Load string <length:4bytes><string>
    if ((string = malloc(sizeof(char) * len)) == NULL)
    {
        return false;
    }

    if (len > SSIZE_MAX || read(fd, string, sizeof(char) * len) != (ssize_t)len)
    {
        free(string);
        return false;
    }

    /* Checking length */
    if (string[len-1] != '\0' || strlen(string)+1 != len)
    {
        free(string);
        return false;
    }

    *str = string;

    return true;
}

bool load_string_array(int fd, char *** str_array)
{
    unsigned char int_buffer[2];
    char ** array;

    /* Arguments count */
    if (read(fd, int_buffer, 2) != 2)
    {
        return false;
    }

    size_t len = convert_from_bytes(int_buffer, 2);

    if (len == 0)
    {
        *str_array = NULL;
        return true;
    }

    if ( (array = calloc(len+1, sizeof(char*))) == NULL )
    {
        return false;
    }

    for (size_t i = 0; i < len; i++)
    {
        char * str = NULL;

        if (!load_string(fd, &str))
        {
            free_2d_null(array);
            return false;
        }

        array[i] = str;
    }

    *str_array = array;

    return true;
}

command_data ** load(int fd)
{
    command_data ** cmds;
    unsigned char int_buffer[4];

    if (fd == -1)
    {
        return NULL;
    }

    /* Commands count */
    if (read(fd, int_buffer, 4) != 4)
    {
        return NULL;
    }

    size_t count = convert_from_bytes(int_buffer, 4);

    if (count > (SIZE_MAX / sizeof(command_data*) - 1) || (cmds = calloc((count+1), sizeof(command_data*))) == NULL)
    {
        //sudo_log(SUDO_CONV_ERROR_MSG, "Cannot allocate data.\n");
        return NULL;
    }

    /* Load each command */
    for (size_t i = 0; i < count; i++)
    {
        if ((cmds[i] = load_command(fd)) == NULL)
        {
            free_commands_null(cmds);

            //sudo_log(SUDO_CONV_ERROR_MSG, "Cannot allocate data.\n");
            return NULL;
        }
    }

    return cmds;
}

command_data * load_command(int fd)
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

    if (!load_string_array(fd, &command->argv))
    {
        free_command(command);
        return NULL;
    }

    if (!load_string_array(fd, &command->envp))
    {
        free_command(command);
        return NULL;
    }

    if ((read(fd, sudoedit, 1) != 1)||
        !load_string(fd, &command->runas_user) ||
        !load_string(fd, &command->runas_group))
    {
        free_command(command);
        return NULL;
    }

    command->sudoedit = sudoedit[0];

    if (!load_string_array(fd, &command->exec_by_users))
    {
        free_command(command);
        return NULL;
    }

    if (!load_string_array(fd, &command->rem_by_users))
    {
        free_command(command);
        return NULL;
    }

    return command;
}

int save(command_data ** commands)
{
    int tmp_fd;
    char fileName[] = PLUGIN_COMMANDS_TEMP_FILE;

    if ((tmp_fd = mkstemp(fileName)) == -1)
    {
        return false;
    }

    /* Commands count */
    size_t count = commands_array_len(commands);

    if (count > UINT32_MAX || !save_int(count, 4, tmp_fd))
    {
        close(tmp_fd);
        unlink(fileName);
        return false;
    }

    /* Save each command */
    command_data ** command = commands;
    while (*command)
    {
        if (!save_command(*command, tmp_fd))
        {
            close(tmp_fd);
            unlink(fileName);
            return false;
        }
        command++;
    }

    /* Rename temp file to original file */
    if (rename(fileName, PLUGIN_COMMANDS_FILE) == -1)
    {
        close(tmp_fd);
        unlink(fileName);
        return false;
    }

    close(tmp_fd);
    return true;
}

int save_command(command_data * command, int fd)
{
    int result = save_string(command->file, fd) &&
                 save_string_array(command->argv, fd) &&
                 save_string_array(command->envp, fd) &&
                 save_int(command->sudoedit, 1, fd) &&
                 save_string(command->runas_user, fd) &&
                 save_string(command->runas_group, fd) &&
                 save_string_array(command->exec_by_users, fd) &&
                 save_string_array(command->rem_by_users, fd);
    return result;
}
