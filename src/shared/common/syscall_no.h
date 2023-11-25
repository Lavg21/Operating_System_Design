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
    //SyscallIdThreadGetTid,
    SyscallIdProcessGetName,
    SyscallIdGetThreadPriority,
    SyscallIdSetThreadPriorityfunction,
    SyscallIdGetCurrentCPUID,
    SyscallIdGetNumberOfThreadsForCurrentProcess,
    SyscallIdGetCPUUtilization,

    SyscallIdReserved = SyscallIdFileWrite + 1
} SYSCALL_ID;
