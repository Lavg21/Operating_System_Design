#pragma once

typedef enum _SYSCALL_ID
{
    SyscallIdIdentifyVersion,

    // Thread Management
    SyscallIdThreadExit,
    SyscallIdThreadCreate,
    SyscallIdThreadGetTid,
    SyscallIdThreadWaitForTermination,
    SyscallIdThreadCloseHandle,

    SyscallIdProcessGetName,
    SyscallIdGetThreadPriority,
    SyscallIdSetThreadPriorityfunction,
    SyscallIdGetCurrentCPUID,
    SyscallIdGetNumberOfThreadsForCurrentProcess,
    SyscallIdGetCPUUtilization,

    // Process Management
    SyscallIdProcessExit,
    SyscallIdProcessCreate,
    SyscallIdProcessGetPid,
    SyscallIdProcessWaitForTermination,
    SyscallIdProcessCloseHandle,

    // Memory management 
    SyscallIdVirtualAlloc,
    SyscallIdVirtualFree,

    // File management
    SyscallIdFileCreate,
    SyscallIdFileClose,
    SyscallIdFileRead,
    SyscallIdFileWrite,
    // Student

    SyscallIdReserved = SyscallIdFileWrite + 1
} SYSCALL_ID;
