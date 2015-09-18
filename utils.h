/*
 * Copyright 2015 Horváth Henrich
 *
 * Sudo security plugin is free software
 * released under GNU Lesser General Public License.
 *
*/

#ifndef UTILS_H_INCLUDED
#define UTILS_H_INCLUDED

#define _GNU_SOURCE

#define QUOTE(name) #name
#define STR(macro) QUOTE(macro)

#include <ctype.h>
#include <limits.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

/*
Check if strings starts with substring
*/
bool str_starts(const char * a, const char * b);

/*
Check if strings starts with substring, not case sensitive
*/
bool str_case_starts(const char * a, const char * b);

/*
Check if array contains string
*/
bool array_null_contains(char ** array, const char * str);

/*
Concaterate string arrays to one string, with separators
*/
char * concat(char ** array, char * separator);

/*
Add string to string array
*/
char ** add_string(char ** array, char * str);

/*
Removes whitespaces from string
*/
char * rem_whitespace(char * str);

/*
Return array length
*/
size_t str_array_len(char ** array);

/*
Frees 2D array
*/
void free_2d_null(char ** array);

/*
Convert bytes to inteteger variable
*/
size_t convert_from_bytes(unsigned char * array, size_t bytes);

/*
Search for file in a PWD or PATH
*/
char * find_in_path(char * command, char ** envp, int mode);

/*
Getenv from envp array
*/
char * getenv_from_envp(char * name, char ** envp);

/*
Find editor for sudoedit
*/
char * find_editor(char ** envp);

#endif // UTILS_H_INCLUDED
