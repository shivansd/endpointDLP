/*++

Copyright (c) 1999-2002  Microsoft Corporation

Module Name:

    scanUser.c

Abstract:

    This file contains the implementation for the main function of the
    user application piece of scanner.  This function is responsible for
    actually scanning file contents.

Environment:

    User mode

--*/

#include <windows.h>
#include <stdlib.h>
#include <stdio.h>
#include <winioctl.h>
#include <string.h>
#include <crtdbg.h>
#include <assert.h>
#include <fltuser.h>
#include "scanuk.h"
#include "scanuser.h"
#include <dontuse.h>

//
//  Default and Maximum number of threads.
//

#define SCANNER_DEFAULT_REQUEST_COUNT       5
#define SCANNER_DEFAULT_THREAD_COUNT        2
#define SCANNER_MAX_THREAD_COUNT            64

UCHAR FoulString[] = "foul";

//
//  Context passed to worker threads
//

typedef struct _SCANNER_THREAD_CONTEXT {

    HANDLE Port;
    HANDLE Completion;

} SCANNER_THREAD_CONTEXT, * PSCANNER_THREAD_CONTEXT;

#define MAX_PATH_LENGTH 512 



VOID
Usage(
    VOID
)
/*++

Routine Description

    Prints usage

Arguments

    None

Return Value

    None

--*/
{

    printf("Connects to the scanner filter and scans buffers \n");
    printf("Usage: scanuser [requests per thread] [number of threads(1-64)]\n");
}

BOOL
ScanBuffer(
    _In_reads_bytes_(BufferSize) PUCHAR Buffer,
    _In_ ULONG BufferSize
)
/*++

Routine Description

    Scans the supplied buffer for an instance of FoulString.

    Note: Pattern matching algorithm used here is just for illustration purposes,
    there are many better algorithms available for real world filters

Arguments

    Buffer      -   Pointer to buffer
    BufferSize  -   Size of passed in buffer

Return Value

    TRUE        -    Found an occurrence of the appropriate FoulString
    FALSE       -    Buffer is ok

--*/
{
    PUCHAR p;
    ULONG searchStringLength = sizeof(FoulString) - sizeof(UCHAR);

    for (p = Buffer;
        p <= (Buffer + BufferSize - searchStringLength);
        p++) {

        if (RtlEqualMemory(p, FoulString, searchStringLength)) {

            printf("Found a string\n");

            //
            //  Once we find our search string, we're not interested in seeing
            //  whether it appears again.
            //

            return TRUE;
        }
    }

    return FALSE;
}

void ConvertWCharToChar(const WCHAR* wideStr, char* outStr, size_t outSize) {
    int requiredSize = WideCharToMultiByte(CP_UTF8, 0, wideStr, -1, NULL, 0, NULL, NULL);
    if (requiredSize > 0 && requiredSize <= (int)outSize) {
        WideCharToMultiByte(CP_UTF8, 0, wideStr, -1, outStr, requiredSize, NULL, NULL);
    }
    else {
        printf("Buffer too small or conversion error!\n");
    }
}



#include <windows.h>
#include <stdio.h>
#include <windows.h>
#include <stdio.h>
#include <string.h>

void ConvertNtPathToWin32(const char* ntPath, char* win32Path, size_t size) {

    char logicalDrives[MAX_PATH] = { 0 };
    if (GetLogicalDriveStringsA(sizeof(logicalDrives), logicalDrives)) {
        char* drive = logicalDrives;
        while (*drive) {
            char devicePath[MAX_PATH] = { 0 };

            char driveLetter[4] = { 0 };
            strncpy_s(driveLetter, sizeof(driveLetter), drive, 2);

            if (QueryDosDeviceA(driveLetter, devicePath, sizeof(devicePath))) {

                size_t len = strlen(devicePath);
                if (_strnicmp(ntPath, devicePath, len) == 0) {
                    snprintf(win32Path, size, "%s%s", driveLetter, ntPath + len);
                    return;
                }
            }
            drive += strlen(drive) + 1;
        }
    }
    printf("No Match Found, Returning Original NT Path\n");
    strncpy_s(win32Path, size, ntPath, size - 1);
    win32Path[size - 1] = '\0';
}

void RemoveAlternateDataStream(char* path) {
    if (!path) return;
    printf("Removing ADS from the path ");
    char* colonPos = strchr(path, ':');
    if (colonPos && (colonPos != path + 1)) {
        *colonPos = '\0';
    }
}

DWORD
ScannerWorker(
    _In_ PSCANNER_THREAD_CONTEXT Context
)
/*++

Routine Description

    This is a worker thread that


Arguments

    Context  - This thread context has a pointer to the port handle we use to send/receive messages,
                and a completion port handle that was already associated with the comm. port by the caller

Return Value

    HRESULT indicating the status of thread exit.

--*/
{
    PSCANNER_NOTIFICATION notification;
    SCANNER_REPLY_MESSAGE replyMessage;
    PSCANNER_MESSAGE message;
    LPOVERLAPPED pOvlp;
    BOOL result;
    DWORD outSize;
    HRESULT hr;
    ULONG_PTR key;

#pragma warning(push)
#pragma warning(disable:4127) // conditional expression is constant

    while (TRUE) {

#pragma warning(pop)

        //
        //  Poll for messages from the filter component to scan.
        //

        result = GetQueuedCompletionStatus(Context->Completion, &outSize, &key, &pOvlp, INFINITE);

        //
        //  Obtain the message: note that the message we sent down via FltGetMessage() may NOT be
        //  the one dequeued off the completion queue: this is solely because there are multiple
        //  threads per single port handle. Any of the FilterGetMessage() issued messages can be
        //  completed in random order - and we will just dequeue a random one.
        //

        message = CONTAINING_RECORD(pOvlp, SCANNER_MESSAGE, Ovlp);

        if (!result) {

            //
            //  An error occured.
            //

            hr = HRESULT_FROM_WIN32(GetLastError());
            break;
        }

        printf("Received message, size %Id\n", pOvlp->InternalHigh);

        notification = &message->Notification;

        assert(notification->BytesToScan <= SCANNER_READ_BUFFER_SIZE);
        _Analysis_assume_(notification->BytesToScan <= SCANNER_READ_BUFFER_SIZE);

        PSCANNER_PATHS paths = (PSCANNER_PATHS)notification->Contents;


        result = ScanBuffer(notification->Contents, notification->BytesToScan);

        replyMessage.ReplyHeader.Status = 0;
        replyMessage.ReplyHeader.MessageId = message->MessageHeader.MessageId;

        //
        //  Need to invert the boolean -- result is true if found
        //  foul language, in which case SafeToOpen should be set to false.
        //


        printf("DLP engine scanning in progress... \n");

        wprintf(L"Sandbox Path: %s\n", paths->SandboxPath);
        wprintf(L"Original Path: %s\n", paths->OriginalPath);

        char srcNtPath[512];
        char destNtPath[512];
        char srcPath[512];
        char destPath[512];

        ConvertWCharToChar(paths->SandboxPath, srcNtPath, sizeof(srcNtPath));
        ConvertWCharToChar(paths->OriginalPath, destNtPath, sizeof(destNtPath));

        RemoveAlternateDataStream(srcNtPath);
        RemoveAlternateDataStream(destNtPath);

        ConvertNtPathToWin32(srcNtPath, srcPath, sizeof(srcPath));
        ConvertNtPathToWin32(destNtPath, destPath, sizeof(destPath));

        printf("Final Source Path: %s\n", srcPath);
        printf("Final Destination Path: %s\n", destPath);



        if (remove(destPath)) {
            printf("Failed to delete destination file!\n");
        }
        else {
            printf("Deleted destination file!\n");
        }

        FILE* sourceFile = fopen(srcPath, "rb");
        if (sourceFile == NULL) {
            perror("Error opening file\n");
        }
        FILE* destFile = fopen(destPath, "wb");
        if (destFile == NULL) {
            perror("Error opening destination file\n");
        }
        if (sourceFile && destFile) {

            int sensitive = 0;

            printf("Enter 0 if file is not sensitive else 1: ");
            scanf_s("%d", &sensitive);
            printf("Scanning done!\n");

            if (!sensitive) {
                printf("File is not sensitive\n");

                unsigned char buffer[4096];
                size_t bytesRead;

                fseek(sourceFile, 0, SEEK_SET);
                while ((bytesRead = fread(buffer, 1, sizeof(buffer), sourceFile)) > 0) {
                    fwrite(buffer, 1, bytesRead, destFile);
                }

                printf("Pasting file to original destination\n");
            }
            else {
                printf("File is sensitive!\n");
            }
            fclose(sourceFile);
            fclose(destFile);

            if (remove(srcPath)) {
                printf("Failed to delete sandbox file!\n");
            }
            else {
                printf("Deleted sandbox file!\n");
            }
            if (sensitive) {
                if (remove(destPath)) {
                    printf("Failed to delete destination file!\n");
                }
                else {
                    printf("Deleted destination file!\n");
                }
            }
        }
        else {
            printf("Error in opening files\n");
        }

        replyMessage.Reply.SafeToOpen = !result;
        printf("Received scan request:\n");
        //wprintf(L"  - Sandbox Path: %s\n", notification->SandboxPath);
        //wprintf(L"  - Original Path: %s\n", notification->OriginalPath);
        printf("Replying message, SafeToOpen: %d\n", replyMessage.Reply.SafeToOpen);

        hr = FilterReplyMessage(Context->Port,
            (PFILTER_REPLY_HEADER)&replyMessage,
            sizeof(replyMessage));

        if (SUCCEEDED(hr)) {

            printf("Replied message\n");

        }
        else {

            printf("Scanner: Error replying message. Error = 0x%X\n", hr);
            break;
        }
        memset(&message->Ovlp, 0, sizeof(OVERLAPPED));

        hr = FilterGetMessage(Context->Port,
            &message->MessageHeader,
            FIELD_OFFSET(SCANNER_MESSAGE, Ovlp),
            &message->Ovlp);

        if (hr != HRESULT_FROM_WIN32(ERROR_IO_PENDING)) {

            break;
        }
    }

    if (!SUCCEEDED(hr)) {

        if (hr == HRESULT_FROM_WIN32(ERROR_INVALID_HANDLE)) {

            //
            //  Scanner port disconncted.
            //

            printf("Scanner: Port is disconnected, probably due to scanner filter unloading.\n");

        }
        else {

            printf("Scanner: Unknown error occured. Error = 0x%X\n", hr);
        }
    }

    return hr;
}


int _cdecl
main(
    _In_ int argc,
    _In_reads_(argc) char* argv[]
)
{
    DWORD requestCount = SCANNER_DEFAULT_REQUEST_COUNT;
    DWORD threadCount = SCANNER_DEFAULT_THREAD_COUNT;
    HANDLE threads[SCANNER_MAX_THREAD_COUNT] = { NULL };
    SCANNER_THREAD_CONTEXT context;
    HANDLE port, completion;
    PSCANNER_MESSAGE messages;
    DWORD threadId;
    HRESULT hr;

    //
    //  Check how many threads and per thread requests are desired.
    //

    if (argc > 1) {

        requestCount = atoi(argv[1]);

        if (requestCount <= 0) {

            Usage();
            return 1;
        }

        if (argc > 2) {

            threadCount = atoi(argv[2]);
        }

        if (threadCount <= 0 || threadCount > 64) {

            Usage();
            return 1;
        }
    }

    //
    //  Open a commuication channel to the filter
    //

    printf("Scanner: Connecting to the filter ...\n");

    hr = FilterConnectCommunicationPort(ScannerPortName,
        0,
        NULL,
        0,
        NULL,
        &port);

    if (IS_ERROR(hr)) {

        printf("ERROR: Connecting to filter port: 0x%08x\n", hr);
        return 2;
    }

    //
    //  Create a completion port to associate with this handle.
    //

    completion = CreateIoCompletionPort(port,
        NULL,
        0,
        threadCount);

    if (completion == NULL) {

        printf("ERROR: Creating completion port: %d\n", GetLastError());
        CloseHandle(port);
        return 3;
    }

    printf("Scanner: Port = 0x%p Completion = 0x%p\n", port, completion);

    context.Port = port;
    context.Completion = completion;

    //
    //  Allocate messages.
    //

    messages = calloc(((size_t)threadCount) * requestCount, sizeof(SCANNER_MESSAGE));

    if (messages == NULL) {

        hr = ERROR_NOT_ENOUGH_MEMORY;
        goto main_cleanup;
    }

    //
    //  Create specified number of threads.
    //

    for (DWORD i = 0; i < threadCount; i++) {

        threads[i] = CreateThread(NULL,
            0,
            (LPTHREAD_START_ROUTINE)ScannerWorker,
            &context,
            0,
            &threadId);

        if (threads[i] == NULL) {

            //
            //  Couldn't create thread.
            //

            hr = GetLastError();
            printf("ERROR: Couldn't create thread: %d\n", hr);
            goto main_cleanup;
        }

        for (DWORD j = 0; j < requestCount; j++) {

            PSCANNER_MESSAGE msg = &(messages[i * requestCount + j]);

            memset(&msg->Ovlp, 0, sizeof(OVERLAPPED));

            //
            //  Request messages from the filter driver.
            //

            hr = FilterGetMessage(port,
                &msg->MessageHeader,
                FIELD_OFFSET(SCANNER_MESSAGE, Ovlp),
                &msg->Ovlp);

            if (hr != HRESULT_FROM_WIN32(ERROR_IO_PENDING)) {
                goto main_cleanup;
            }
        }
    }

    hr = S_OK;

main_cleanup:

    for (INT i = 0; threads[i] != NULL; ++i) {
        WaitForSingleObjectEx(threads[i], INFINITE, FALSE);
    }

    printf("Scanner:  All done. Result = 0x%08x\n", hr);
    CloseHandle(port);
    CloseHandle(completion);

    free(messages);

    return hr;
}

/*++

Copyright (c) 1999-2002  Microsoft Corporation

Module Name:

    scanUser.c

Abstract:

    This file contains the implementation for the main function of the
    user application piece of scanner.  This function is responsible for
    actually scanning file contents.

Environment:

    User mode

--*/

#include <windows.h>
#include <stdlib.h>
#include <stdio.h>
#include <winioctl.h>
#include <string.h>
#include <crtdbg.h>
#include <assert.h>
#include <fltuser.h>
#include "scanuk.h"
#include "scanuser.h"
#include <dontuse.h>

//
//  Default and Maximum number of threads.
//

#define SCANNER_DEFAULT_REQUEST_COUNT       5
#define SCANNER_DEFAULT_THREAD_COUNT        2
#define SCANNER_MAX_THREAD_COUNT            64

UCHAR FoulString[] = "foul";

//
//  Context passed to worker threads
//

typedef struct _SCANNER_THREAD_CONTEXT {

    HANDLE Port;
    HANDLE Completion;

} SCANNER_THREAD_CONTEXT, *PSCANNER_THREAD_CONTEXT;

#define MAX_PATH_LENGTH 512 



VOID
Usage (
    VOID
    )
/*++

Routine Description

    Prints usage

Arguments

    None

Return Value

    None

--*/
{

    printf( "Connects to the scanner filter and scans buffers \n" );
    printf( "Usage: scanuser [requests per thread] [number of threads(1-64)]\n" );
}

BOOL
ScanBuffer (
    _In_reads_bytes_(BufferSize) PUCHAR Buffer,
    _In_ ULONG BufferSize
    )
/*++

Routine Description

    Scans the supplied buffer for an instance of FoulString.

    Note: Pattern matching algorithm used here is just for illustration purposes,
    there are many better algorithms available for real world filters

Arguments

    Buffer      -   Pointer to buffer
    BufferSize  -   Size of passed in buffer

Return Value

    TRUE        -    Found an occurrence of the appropriate FoulString
    FALSE       -    Buffer is ok

--*/
{
    PUCHAR p;
    ULONG searchStringLength = sizeof(FoulString) - sizeof(UCHAR);

    for (p = Buffer;
         p <= (Buffer + BufferSize - searchStringLength);
         p++) {

        if (RtlEqualMemory( p, FoulString, searchStringLength )) {

            printf( "Found a string\n" );

            //
            //  Once we find our search string, we're not interested in seeing
            //  whether it appears again.
            //

            return TRUE;
        }
    }

    return FALSE;
}

void ConvertWCharToChar(const WCHAR* wideStr, char* outStr, size_t outSize) {
    int requiredSize = WideCharToMultiByte(CP_UTF8, 0, wideStr, -1, NULL, 0, NULL, NULL);
    if (requiredSize > 0 && requiredSize <= (int)outSize) {
        WideCharToMultiByte(CP_UTF8, 0, wideStr, -1, outStr, requiredSize, NULL, NULL);
    }
    else {
        printf("Buffer too small or conversion error!\n");
    }
}



#include <windows.h>
#include <stdio.h>
#include <windows.h>
#include <stdio.h>
#include <string.h>

void ConvertNtPathToWin32(const char* ntPath, char* win32Path, size_t size) {

    char logicalDrives[MAX_PATH] = { 0 };
    if (GetLogicalDriveStringsA(sizeof(logicalDrives), logicalDrives)) {
        char* drive = logicalDrives;
        while (*drive) {
            char devicePath[MAX_PATH] = { 0 };

            char driveLetter[4] = { 0 };
            strncpy_s(driveLetter, sizeof(driveLetter), drive, 2);

            if (QueryDosDeviceA(driveLetter, devicePath, sizeof(devicePath))) {

                size_t len = strlen(devicePath);
                if (_strnicmp(ntPath, devicePath, len) == 0) {
                    snprintf(win32Path, size, "%s%s", driveLetter, ntPath + len);
                    return;
                }
            }
            drive += strlen(drive) + 1;
        }
    }
    printf("No Match Found, Returning Original NT Path\n");
    strncpy_s(win32Path, size, ntPath, size - 1);
    win32Path[size - 1] = '\0';
}



DWORD
ScannerWorker(
    _In_ PSCANNER_THREAD_CONTEXT Context
    )
/*++

Routine Description

    This is a worker thread that


Arguments

    Context  - This thread context has a pointer to the port handle we use to send/receive messages,
                and a completion port handle that was already associated with the comm. port by the caller

Return Value

    HRESULT indicating the status of thread exit.

--*/
{
    PSCANNER_NOTIFICATION notification;
    SCANNER_REPLY_MESSAGE replyMessage;
    PSCANNER_MESSAGE message;
    LPOVERLAPPED pOvlp;
    BOOL result;
    DWORD outSize;
    HRESULT hr;
    ULONG_PTR key;

#pragma warning(push)
#pragma warning(disable:4127) // conditional expression is constant

    while (TRUE) {

#pragma warning(pop)

        //
        //  Poll for messages from the filter component to scan.
        //

        result = GetQueuedCompletionStatus( Context->Completion, &outSize, &key, &pOvlp, INFINITE );

        //
        //  Obtain the message: note that the message we sent down via FltGetMessage() may NOT be
        //  the one dequeued off the completion queue: this is solely because there are multiple
        //  threads per single port handle. Any of the FilterGetMessage() issued messages can be
        //  completed in random order - and we will just dequeue a random one.
        //

        message = CONTAINING_RECORD( pOvlp, SCANNER_MESSAGE, Ovlp );

        if (!result) {

            //
            //  An error occured.
            //

            hr = HRESULT_FROM_WIN32( GetLastError() );
            break;
        }

        printf( "Received message, size %Id\n", pOvlp->InternalHigh );

        notification = &message->Notification;

        assert(notification->BytesToScan <= SCANNER_READ_BUFFER_SIZE);
        _Analysis_assume_(notification->BytesToScan <= SCANNER_READ_BUFFER_SIZE);

        PSCANNER_PATHS paths = (PSCANNER_PATHS)notification->Contents;


        result = ScanBuffer( notification->Contents, notification->BytesToScan );

        replyMessage.ReplyHeader.Status = 0;
        replyMessage.ReplyHeader.MessageId = message->MessageHeader.MessageId;

        //
        //  Need to invert the boolean -- result is true if found
        //  foul language, in which case SafeToOpen should be set to false.
        //

        replyMessage.Reply.SafeToOpen = !result;
        printf("Received scan request:\n");
        //wprintf(L"  - Sandbox Path: %s\n", notification->SandboxPath);
        //wprintf(L"  - Original Path: %s\n", notification->OriginalPath);
        printf( "Replying message, SafeToOpen: %d\n", replyMessage.Reply.SafeToOpen );

        hr = FilterReplyMessage( Context->Port,
                                 (PFILTER_REPLY_HEADER) &replyMessage,
                                 sizeof( replyMessage ) );

        if (SUCCEEDED( hr )) {

            printf( "Replied message\n" );

        } else {

            printf( "Scanner: Error replying message. Error = 0x%X\n", hr );
            break;
        }
        printf("DLP engine scanning in progress... \n");

        wprintf(L"Sandbox Path: %s\n", paths->SandboxPath);
        wprintf(L"Original Path: %s\n", paths->OriginalPath);

        char srcNtPath[512];
        char destNtPath[512];
        char srcPath[512];
        char destPath[512];

        ConvertWCharToChar(paths->SandboxPath, srcNtPath, sizeof(srcNtPath));
        ConvertWCharToChar(paths->OriginalPath, destNtPath, sizeof(destNtPath));

        ConvertNtPathToWin32(srcNtPath, srcPath, sizeof(srcPath));
        ConvertNtPathToWin32(destNtPath, destPath, sizeof(destPath));

        printf("Final Source Path: %s\n", srcPath);
        printf("Final Destination Path: %s\n", destPath);

   

        if (remove(destPath)) {
            printf("Failed to delete destination file!\n");
        }
        else {
            printf("Deleted destination file!\n");
        }

        FILE* sourceFile = fopen(srcPath, "rb");
        if (sourceFile == NULL) {
            perror("Error opening file\n");
        }
        FILE* destFile = fopen(destPath, "wb");
        if (destFile == NULL) {
            perror("Error opening destination file\n");
        }
        if (sourceFile && destFile) {
            
            int sensitive = 0;

            printf("Enter 0 if file is not sensitive else 1: ");
            scanf_s("%d", &sensitive);
            printf("Scanning done!\n");

            if (!sensitive) {
                printf("File is not sensitive\n");

                unsigned char buffer[4096]; 
                size_t bytesRead;

                fseek(sourceFile, 0, SEEK_SET); 
                while ((bytesRead = fread(buffer, 1, sizeof(buffer), sourceFile)) > 0) {
                    fwrite(buffer, 1, bytesRead, destFile);
                }

                printf("Pasting file to original destination\n");
            }
            else {
                printf("File is sensitive!\n");
            }
            fclose(sourceFile);
            fclose(destFile);

            if (remove(srcPath)) {
                printf("Failed to delete sandbox file!\n");
            }
            else {
                printf("Deleted sandbox file!\n");
            }
            if (sensitive) {
                if (remove(destPath)) {
                    printf("Failed to delete destination file!\n");
                }
                else {
                    printf("Deleted destination file!\n");
                }
            }
        }
        else {
            printf("Error in opening files\n");
        }
        memset( &message->Ovlp, 0, sizeof( OVERLAPPED ) );

        hr = FilterGetMessage( Context->Port,
                               &message->MessageHeader,
                               FIELD_OFFSET( SCANNER_MESSAGE, Ovlp ),
                               &message->Ovlp );

        if (hr != HRESULT_FROM_WIN32( ERROR_IO_PENDING )) {

            break;
        }
    }

    if (!SUCCEEDED( hr )) {

        if (hr == HRESULT_FROM_WIN32( ERROR_INVALID_HANDLE )) {

            //
            //  Scanner port disconncted.
            //

            printf( "Scanner: Port is disconnected, probably due to scanner filter unloading.\n" );

        } else {

            printf( "Scanner: Unknown error occured. Error = 0x%X\n", hr );
        }
    }

    return hr;
}


int _cdecl
main (
    _In_ int argc,
    _In_reads_(argc) char *argv[]
    )
{
    DWORD requestCount = SCANNER_DEFAULT_REQUEST_COUNT;
    DWORD threadCount = SCANNER_DEFAULT_THREAD_COUNT;
    HANDLE threads[SCANNER_MAX_THREAD_COUNT] = { NULL };
    SCANNER_THREAD_CONTEXT context;
    HANDLE port, completion;
    PSCANNER_MESSAGE messages;
    DWORD threadId;
    HRESULT hr;

    //
    //  Check how many threads and per thread requests are desired.
    //

    if (argc > 1) {

        requestCount = atoi( argv[1] );

        if (requestCount <= 0) {

            Usage();
            return 1;
        }

        if (argc > 2) {

            threadCount = atoi( argv[2] );
        }

        if (threadCount <= 0 || threadCount > 64) {

            Usage();
            return 1;
        }
    }

    //
    //  Open a commuication channel to the filter
    //

    printf( "Scanner: Connecting to the filter ...\n" );

    hr = FilterConnectCommunicationPort( ScannerPortName,
                                         0,
                                         NULL,
                                         0,
                                         NULL,
                                         &port );

    if (IS_ERROR( hr )) {

        printf( "ERROR: Connecting to filter port: 0x%08x\n", hr );
        return 2;
    }

    //
    //  Create a completion port to associate with this handle.
    //

    completion = CreateIoCompletionPort( port,
                                         NULL,
                                         0,
                                         threadCount );

    if (completion == NULL) {

        printf( "ERROR: Creating completion port: %d\n", GetLastError() );
        CloseHandle( port );
        return 3;
    }

    printf( "Scanner: Port = 0x%p Completion = 0x%p\n", port, completion );

    context.Port = port;
    context.Completion = completion;

    //
    //  Allocate messages.
    //

    messages = calloc(((size_t) threadCount) * requestCount, sizeof(SCANNER_MESSAGE));

    if (messages == NULL) {

        hr = ERROR_NOT_ENOUGH_MEMORY;
        goto main_cleanup;
    }
    
    //
    //  Create specified number of threads.
    //

    for (DWORD i = 0; i < threadCount; i++) {
        
        threads[i] = CreateThread( NULL,
                                   0,
                                   (LPTHREAD_START_ROUTINE) ScannerWorker,
                                   &context,
                                   0,
                                   &threadId );

        if (threads[i] == NULL) {

            //
            //  Couldn't create thread.
            //

            hr = GetLastError();
            printf( "ERROR: Couldn't create thread: %d\n", hr );
            goto main_cleanup;
        }

        for (DWORD j = 0; j < requestCount; j++) {
        
            PSCANNER_MESSAGE msg = &(messages[i * requestCount + j]);

            memset( &msg->Ovlp, 0, sizeof( OVERLAPPED ) );

            //
            //  Request messages from the filter driver.
            //

            hr = FilterGetMessage( port,
                                   &msg->MessageHeader,
                                   FIELD_OFFSET( SCANNER_MESSAGE, Ovlp ),
                                   &msg->Ovlp );

            if (hr != HRESULT_FROM_WIN32( ERROR_IO_PENDING )) {
                goto main_cleanup;
            }
        }
    }

    hr = S_OK;
    
main_cleanup:

    for (INT i = 0; threads[i] != NULL; ++i) {
        WaitForSingleObjectEx(threads[i], INFINITE, FALSE);
    }
    
    printf( "Scanner:  All done. Result = 0x%08x\n", hr );
    CloseHandle( port );
    CloseHandle( completion );

    free(messages);

    return hr;
}

