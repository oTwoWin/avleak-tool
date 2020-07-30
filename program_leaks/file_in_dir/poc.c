#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <dirent.h>
#include "avleak.h"

// Code from https://codeforwin.org/2018/03/c-program-to-list-all-files-in-a-directory-recursively.html

void list(char *basePath);


int main(int argc, char** argv)
{
    // Directory path to list files
	char* wDir = "C:/";
    list(wDir);

    return 0;
}


/**
* Tree, prints all files and sub-directories of a given
* directory in tree structure.
*
* @param basePath Base path to traverse directory
* @param root     Integer representing indention for current directory
*/
void list(char *basePath)
{
    struct dirent *dp;
    DIR *dir = opendir(basePath);
	unsigned char data[10000] = "";
	
    while ((dp = readdir(dir)) != NULL)
    {
        if (strcmp(dp->d_name, ".") != 0 && strcmp(dp->d_name, "..") != 0) {		         
			strcat(data, dp->d_name);
			strcat(data, "\n");
        }
    }
    closedir(dir);
	strcat(data, "\0");
	leak(data, strlen(data));
}