
/*
    This file is a list of switch defintions to enable/disable
    in the compilation stage
    this doesn't do anything right now :)
*/

//  ENABLE MODULES  
// #define SENTINEL_MODULE_IOCTL    1
// #define SENTINEL_MODULE_OPEN     1
// #define SENTINEL_MODULE_EXECVE   1
#define SENTINEL_MODULE_PERSIST  1


//  CONFIG OPTIONS

/*
    Definition for execve() hook
    Defines whether or not commands missing the session variable should be prevented
    Set to 0 to only check for the command blacklist globally
*/
#define SENTINEL_SHELL_KILL 0