#pragma once

typedef enum _SYSCALL_ID
{
    SyscallIdIdentifyVersion,
    SyscallIdDisableSyscalls,

    // Thread Management
    SyscallIdThreadExit,
    SyscallIdThreadCreate,
    SyscallIdThreadGetTid,
    SyscallIdThreadWaitForTermination,
    SyscallIdThreadCloseHandle,

    // Process Management
    SyscallIdProcessExit,
    SyscallIdProcessCreate,
    SyscallIdProcessGetPid,
    SyscallIdProcessWaitForTermination,
    SyscallIdProcessCloseHandle,

    // Memory management 
    SyscallIdVirtualAlloc,
    SyscallIdVirtualFree,
    SyscallIdMemset,

    // File management
    SyscallIdFileCreate,
    SyscallIdFileClose,
    SyscallIdFileRead,
    SyscallIdFileWrite,

    SyscallIdReserved = SyscallIdFileWrite + 1
} SYSCALL_ID;
