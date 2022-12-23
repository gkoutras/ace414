# ACE414 Assignment 3

In this assignment, an enhanced access control logging system was implemented using C.

---

## Enhanced Access Control Logging System
### logger.c

The access control logging process works with the classic functions `fopen()` and `fwrite()` of C. Each logging entry contains information about the user's actions. These actions are the following:

1. **UID**: The unique ID of the user who called the function. It is taken with `getuid()` function from `unitsd.h` library.

2. **FILE**: In `fopen()`, it is taken from the corresponding argument from its call
function. In `fwrite()`, it is taken from the corresponding File Descriptor
in the function's file pointer/argument. The latter is done by the use of functions `fileno(stream)` and `readlink("/proc/self/fd/(file_desc)", ...)`.

3. **DATE**: This field is taken by the `time()` function.

4. **TIME**: This field is taken by the `localtime()` function.

5. **ACCESS TYPE**: In `fopen()`, `access()` function is used with argument filename and mode F_OK. So, if the file already exists, then access type is 1. Otherwise, the file does not exist, so `fopen()` will create the desired file and access type is 0. In `fwrite()`, the access type is always 2, as each call there, changes the contents of the file.

6. **ACTION DENIED FLAG**: In `fopen()`, `access('filename', R_OK | W_OK)` function is used, checking if the user who called them has read or write permission. In
`fwrite()`, `access('filename', W_OK)` function is used.

7. **FINGERPRINT**: At first, and once the content of the final text of the file is read, the user is checked whether they have permission to call `fopen()`, through actionDenied from field 5. If they don't, then fingerprint is 0. After getting the text reading pointer to the beginning (as there are cases where it is at the end eg. append), the whole text is read and the fingerprint is taken, by calling `str2md5()` function. 

### acmonitor.c

In all cases, the file `file_logging.log` is read at the start and its data stored in a struct entry table. This tool has the following two functions:

1. **LIST MALICIOUS USERS**: At first, all the unique IDs are obtained in all records as well as their distinct values. Each of these is checked whether access permission was denied (actionDenied = 1). If so, and if this file does not already exist in a table, then it is added to the table as well, increasing at the same time the number of files the user has edited. If this number exceeds 7, then the UID of the user is printed.

2. **LIST FILE'S MODIFICATIONS**: After obtaining all the distinct UIDs found in the record table, the first fingerprint recorded for the wanted file is searched for each. Every time the new fingerprint is different from the last, number of conversions is incremented. If this number is at least 1, then it is printed, along with the UID of the user who made them.

### test_aclog.c:

To test the tool, some functions/scripts have been created in which files are created/rewritten, while the access rights of the user who called them are removed. To test for more users, new users were created via `adduser` and `su`, and the program was called by the superuser.
