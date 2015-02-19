/*
* SPDXVersion: SPDX-1.1
* Creator: Person: Nuno Brito (nuno.brito@triplecheck.de)
* Creator: Organization: TripleCheck (contact@triplecheck.de)
* Created: 2015-02-19T00:00:00Z
* LicenseName: EUPL
* FileName: BootLogger.c
* FileCopyrightText: <text>
* Copyright (c) 2014 Nuno Brito, TripleCheck
* </text>
* FileComment: <text> An example Windows driver for logging to a 
	a text file the processes executed during the start phase
	of a Windows operating system. Tested on Windows XP to 
	Windows 10, see README for details.</text>
*/

#include <ntifs.h>
#include <Ntstrsafe.h>

#define DRIVER_TAG                      'tdlb'
#define LOG_ENTRY_MAX_LENGTH_IN_WCHARS  512 

NTSTATUS DriverEntry ( IN PDRIVER_OBJECT DriverObject, IN PUNICODE_STRING RegistryPath );
#pragma alloc_text ( INIT, DriverEntry )

PDEVICE_OBJECT    g_BootLogDevice = NULL;
LIST_ENTRY        g_LogHead;
KSPIN_LOCK        g_LogLock;
WCHAR             g_LogFileDirectoryNameBuffer[LOG_ENTRY_MAX_LENGTH_IN_WCHARS+4] = { 0 };
UNICODE_STRING    g_LogFileDirectoryName = { 0 };
LONG              g_SessionLogonCounter = 0;
PCALLBACK_OBJECT  g_SessionNotificationCallback = NULL;
PVOID             g_SessionNotificationCallbackRegistration = NULL;
BOOLEAN           g_SystemSessionNotification = TRUE;

UNICODE_STRING    LogFileDirValueName = RTL_CONSTANT_STRING ( L"LogFileDir" );
UNICODE_STRING    IoSessionNotificationsCallbackName = RTL_CONSTANT_STRING ( L"\\Callback\\IoSessionNotifications" );
UNICODE_STRING    ExplorerExeName = RTL_CONSTANT_STRING ( L"\\Windows\\explorer.exe" );

typedef struct _LOG_ENTRY
{
    LIST_ENTRY  ListEntry;
    WCHAR       Data[LOG_ENTRY_MAX_LENGTH_IN_WCHARS];
} LOG_ENTRY, *PLOG_ENTRY;

typedef enum _IMAGE_TYPE
{
    DRIVER = 0,
    PROCESS,
    MODULE
} IMAGE_TYPE, *PIMAGE_TYPE;

PVOID NTAPI PsGetProcessSectionBaseAddress ( PEPROCESS Process );
VOID FinishLogging ();

VOID LogLoad ( IN PLARGE_INTEGER SystemTime, IN PUNICODE_STRING ImageName, IN HANDLE Pid, IN IMAGE_TYPE Type )
{
    PLOG_ENTRY NewEntry = (PLOG_ENTRY)ExAllocatePoolWithTag ( NonPagedPool, sizeof ( LOG_ENTRY ), DRIVER_TAG );
    if ( NewEntry )
    {
        LARGE_INTEGER  LocalTime;
        TIME_FIELDS    TimeFields;

        ExSystemTimeToLocalTime ( SystemTime, &LocalTime );
        RtlTimeToTimeFields ( &LocalTime, &TimeFields );

        if ( NT_SUCCESS ( RtlStringCchPrintfW ( NewEntry -> Data, LOG_ENTRY_MAX_LENGTH_IN_WCHARS, L"%02u/%02u/%04u %02u:%02u:%02u.%03u, %ws, %u, %wZ\r\n", 
                                                TimeFields.Day, TimeFields.Month, TimeFields.Year, TimeFields.Hour, TimeFields.Minute, TimeFields.Second, TimeFields.Milliseconds,
                                                ( DRIVER == Type ) ? L"Driver" : ( PROCESS == Type ? L"Process" : L"Module" ), (ULONG)Pid, ImageName ) ) )
            ExInterlockedInsertTailList ( &g_LogHead, &NewEntry -> ListEntry, &g_LogLock );
        else
            ExFreePoolWithTag ( NewEntry, DRIVER_TAG );
    }
}

VOID WorkItemRoutine ( IN PDEVICE_OBJECT DeviceObject, IN PVOID Context OPTIONAL )
{
    FinishLogging ();
    IoFreeWorkItem ( (PIO_WORKITEM)Context );
}

VOID SessionNotificationCallbackFunction ( IN PVOID CallbackContext, IN PVOID Argument1, IN PVOID Argument2 )
{
    IO_SESSION_EVENT SessionEvent = IoSessionEventLogon;
    if ( NULL != Argument1 )
        SessionEvent = *(PIO_SESSION_EVENT)( (ULONG_PTR)Argument1 + 4 * sizeof ( PVOID ) );

    if ( IoSessionEventLogon == SessionEvent && 1 == InterlockedIncrement ( &g_SessionLogonCounter ) )
    {
        PIO_WORKITEM WorkItem = IoAllocateWorkItem ( g_BootLogDevice );
        if ( WorkItem )
            IoQueueWorkItem ( WorkItem, WorkItemRoutine, DelayedWorkQueue, WorkItem );
    }
}

VOID LoadImageNotify ( IN PUNICODE_STRING FullImageName, IN HANDLE ProcessId, IN PIMAGE_INFO ImageInfo )
{
    LARGE_INTEGER SystemTime;
    KeQuerySystemTime ( &SystemTime );
    
    if ( ImageInfo -> SystemModeImage )
    {
        LogLoad ( &SystemTime, FullImageName, PsGetProcessId ( PsInitialSystemProcess ), DRIVER );
    } else
    {
        PEPROCESS Process;
        if ( NT_SUCCESS ( PsLookupProcessByProcessId ( ProcessId, &Process ) ) )
        {
            BOOLEAN IsProcess = PsGetProcessSectionBaseAddress ( Process ) == ImageInfo -> ImageBase;
            LogLoad ( &SystemTime, FullImageName, ProcessId,  IsProcess ? PROCESS : MODULE );
            if ( IsProcess && FALSE == g_SystemSessionNotification && FullImageName -> Length > ExplorerExeName.Length )
            {
                UNICODE_STRING usTestStr;
                usTestStr.Length = usTestStr.MaximumLength = ExplorerExeName.Length;
                usTestStr.Buffer = (PWCH)( (ULONG_PTR)FullImageName -> Buffer + FullImageName -> Length - ExplorerExeName.Length );

                if ( RtlEqualUnicodeString ( &usTestStr, &ExplorerExeName, TRUE ) )
                    SessionNotificationCallbackFunction ( NULL, NULL, NULL );
            }
            ObDereferenceObject ( Process );
        }
    }
}

VOID FinishLogging ()
{
    OBJECT_ATTRIBUTES  ObjectAttributes;
    IO_STATUS_BLOCK    IoStatusBlock;
    HANDLE             Directory, LogFile = NULL;
    PLIST_ENTRY        Entry;

    PsRemoveLoadImageNotifyRoutine ( LoadImageNotify );
    
    InitializeObjectAttributes ( &ObjectAttributes, &g_LogFileDirectoryName, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL );

    if ( 0 != g_LogFileDirectoryName.Length &&
         NT_SUCCESS ( ZwCreateFile ( &Directory, FILE_ALL_ACCESS, &ObjectAttributes, &IoStatusBlock, NULL, 
                                     FILE_ATTRIBUTE_NORMAL, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, 
                                     FILE_OPEN_IF, FILE_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT, NULL, 0 ) ) )
    {
        WCHAR          Buffer[128];
        LARGE_INTEGER  SystemTime, LocalTime;
        TIME_FIELDS    TimeFields;

        KeQuerySystemTime ( &SystemTime );
        ExSystemTimeToLocalTime ( &SystemTime, &LocalTime );
        RtlTimeToTimeFields ( &LocalTime, &TimeFields );

        if ( NT_SUCCESS ( RtlStringCbPrintfW ( Buffer, sizeof ( Buffer ), L"%02u-%02u-%04u-%02u-%02u-%02u.log", 
                                               TimeFields.Day, TimeFields.Month, TimeFields.Year, TimeFields.Hour, TimeFields.Minute, TimeFields.Second ) ) )
        {
            UNICODE_STRING FileName;
            RtlInitUnicodeString ( &FileName, Buffer );

            InitializeObjectAttributes ( &ObjectAttributes, &FileName, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, Directory, NULL );
            if ( !NT_SUCCESS ( ZwCreateFile ( &LogFile, FILE_ALL_ACCESS, &ObjectAttributes, &IoStatusBlock, NULL, 
                                              FILE_ATTRIBUTE_NORMAL, 0, FILE_SUPERSEDE, FILE_NON_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT, NULL, 0 ) ) )
                                              LogFile = NULL;
        }

        ZwClose ( Directory );
    }

    g_LogFileDirectoryName.Length = 0;

    if ( NULL != LogFile )
        ZwWriteFile ( LogFile, NULL, NULL, NULL, &IoStatusBlock, "\xFF\xFE", 2, NULL, NULL );

    while ( NULL != ( Entry = ExInterlockedRemoveHeadList ( &g_LogHead, &g_LogLock ) ) )
    {
        if ( NULL != LogFile )
        {
            SIZE_T CbLen;
            RtlStringCbLengthW ( ((PLOG_ENTRY)Entry) -> Data, LOG_ENTRY_MAX_LENGTH_IN_WCHARS, &CbLen );
            ZwWriteFile ( LogFile, NULL, NULL, NULL, &IoStatusBlock, ((PLOG_ENTRY)Entry) -> Data, (ULONG)CbLen, NULL, NULL );
        }
        ExFreePoolWithTag ( Entry, DRIVER_TAG );
    }

    if ( NULL != LogFile )
        ZwClose ( LogFile );

    if ( NULL != g_SessionNotificationCallbackRegistration )
    {
        ExUnregisterCallback ( g_SessionNotificationCallbackRegistration );
        g_SessionNotificationCallbackRegistration = NULL;
    }
    if ( NULL != g_SessionNotificationCallback )
    {
        ObDereferenceObject ( g_SessionNotificationCallback );
        g_SessionNotificationCallback = NULL;
    } 
}

VOID DriverUnload ( IN PDRIVER_OBJECT DriverObject )
{
    FinishLogging ();
    if ( NULL != g_BootLogDevice )
        IoDeleteDevice ( g_BootLogDevice );
}

NTSTATUS ReadSettings ( IN PUNICODE_STRING RegistryPath )
{
    NTSTATUS           Status;
    OBJECT_ATTRIBUTES  ObjectAttributes;
    HANDLE             Handle;

    InitializeObjectAttributes ( &ObjectAttributes, RegistryPath, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL );
    Status = ZwOpenKey ( &Handle, KEY_ALL_ACCESS, &ObjectAttributes );
    if ( NT_SUCCESS ( Status ) )
    {
        UCHAR  Buffer[LOG_ENTRY_MAX_LENGTH_IN_WCHARS];
        ULONG  RetLen;

        Status = ZwQueryValueKey ( Handle, &LogFileDirValueName, KeyValuePartialInformation, Buffer, sizeof ( Buffer ), &RetLen );
        if ( NT_SUCCESS ( Status ) )
        {
            PKEY_VALUE_PARTIAL_INFORMATION KeyValuePartialInfo = (PKEY_VALUE_PARTIAL_INFORMATION)Buffer;
            if ( KeyValuePartialInfo -> DataLength > sizeof ( WCHAR ) )
            {
                g_LogFileDirectoryName.Buffer        = g_LogFileDirectoryNameBuffer;
                g_LogFileDirectoryName.MaximumLength = sizeof ( g_LogFileDirectoryNameBuffer );
                g_LogFileDirectoryName.Length        = 4 * sizeof ( WCHAR ) + (USHORT)KeyValuePartialInfo -> DataLength - sizeof ( WCHAR );
                RtlCopyMemory ( g_LogFileDirectoryNameBuffer, L"\\??\\", 4 * sizeof ( WCHAR ) ); 
                RtlCopyMemory ( &g_LogFileDirectoryNameBuffer[4], KeyValuePartialInfo -> Data, KeyValuePartialInfo -> DataLength - sizeof ( WCHAR ) );
            } else
                Status = STATUS_INVALID_PARAMETER;
        }
        ZwClose ( Handle );
    }

    return Status;
}

NTSTATUS DriverEntry ( IN PDRIVER_OBJECT DriverObject, IN PUNICODE_STRING RegistryPath )
{
    InitializeListHead ( &g_LogHead );
    KeInitializeSpinLock ( &g_LogLock );

    if ( NT_SUCCESS ( ReadSettings ( RegistryPath ) ) )
    {
        OBJECT_ATTRIBUTES  ObjectAttributes;
        NTSTATUS           Status;
        
        if ( NT_SUCCESS ( IoCreateDevice ( DriverObject, 0, NULL, FILE_DEVICE_UNKNOWN, 0, FALSE, &g_BootLogDevice ) ) )
        {
            InitializeObjectAttributes ( &ObjectAttributes, &IoSessionNotificationsCallbackName, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL );
            Status = ExCreateCallback ( &g_SessionNotificationCallback, &ObjectAttributes, FALSE, FALSE );
            if ( STATUS_OBJECT_NAME_NOT_FOUND == Status )
            {
                g_SystemSessionNotification = FALSE;
                Status = ExCreateCallback ( &g_SessionNotificationCallback, &ObjectAttributes, TRUE, TRUE );
            }

            if ( NT_SUCCESS ( Status ) )
            {
                g_SessionNotificationCallbackRegistration = ExRegisterCallback ( g_SessionNotificationCallback, SessionNotificationCallbackFunction, NULL );
                if ( NULL != g_SessionNotificationCallbackRegistration )
                {
                    Status = PsSetLoadImageNotifyRoutine ( LoadImageNotify );
                    if ( !NT_SUCCESS ( Status ) )
                    {
                        ExUnregisterCallback ( g_SessionNotificationCallbackRegistration );
                        g_SessionNotificationCallbackRegistration = NULL;
                        ObDereferenceObject ( g_SessionNotificationCallback );
                        g_SessionNotificationCallback = NULL;
                    }
                } else
                {
                    ObDereferenceObject ( g_SessionNotificationCallback );
                    g_SessionNotificationCallback = NULL;
                }
            }
        } else
            g_BootLogDevice = NULL;
    }

    DriverObject -> DriverUnload = DriverUnload;
    
    return STATUS_SUCCESS;
}

