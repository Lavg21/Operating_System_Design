#include "common_lib.h"
#include "syscall_if.h"
#include "um_lib_helper.h"

FUNC_ThreadStart _HelloWorldFromThread;

STATUS
__main(
    DWORD       argc,
    char**      argv
)
{
    STATUS status;
    TID tid;
    PID pid;
    UM_HANDLE umHandle;

    LOG("Hello from your usermode application!\n");

    LOG("Number of arguments 0x%x\n", argc);
    LOG("Arguments at 0x%X\n", argv);
    for (DWORD i = 0; i < argc; ++i)
    {
        LOG("Argument[%u] is at 0x%X\n", i, argv[i]);
        LOG("Argument[%u] is %s\n", i, argv[i]);
    }

    // Student
    char* processName = NULL;
    status = SyscallProcessGetName(processName, 1);
    if (!SUCCEEDED(status))
    {
        LOG_FUNC_ERROR("SyscallProcessGetName", status);
        return status;
    }

    LOG("The name of the process with length 1 is : %s\n", &processName);

    status = SyscallProcessGetName(processName, 3);
    if (!SUCCEEDED(status))
    {
        LOG_FUNC_ERROR("SyscallProcessGetName", status);
        return status;
    }

    LOG("The name of the process with length 3 is : %s\n", &processName);

    status = SyscallProcessGetName(processName, 0x1234);
    if (!SUCCEEDED(status))
    {
        LOG_FUNC_ERROR("SyscallProcessGetName", status);
        return status;
    }

    LOG("The name of the process with length 0x1234 is : %s\n", &processName);

    BYTE currentPriority = 0;
    status = SyscallGetThreadPriority(&currentPriority);
    if (!SUCCEEDED(status))
    {
        LOG_FUNC_ERROR("SyscallGetThreadPriority", status);
        return status;
    }
    LOG("Status: %d, Current priority: %d", status, currentPriority);

    currentPriority++;
    status = SyscallSetThreadPriority(currentPriority);
    if (!SUCCEEDED(status))
    {
        LOG_FUNC_ERROR("SyscallSetThreadPriority", status);
        return status;
    }
    LOG("Status: %d, Current set priority: %d", status, currentPriority);

    status = SyscallGetThreadPriority(&currentPriority);
    if (!SUCCEEDED(status))
    {
        LOG_FUNC_ERROR("SyscallGetThreadPriority", status);
        return status;
    }
    LOG("Status: %d, Current priority: %d", status, currentPriority);

    status = SyscallProcessGetPid(UM_INVALID_HANDLE_VALUE, &pid);
    if (!SUCCEEDED(status))
    {
        LOG_FUNC_ERROR("SyscallProcessGetPid", status);
        return status;
    }

    LOG("Hello from process with ID 0x%X\n", pid);

    QWORD* threadNo = NULL;
    status = SyscallGetNumberOfThreadsForCurrentProcess(threadNo);
    if (!SUCCEEDED(status))
    {
        LOG_FUNC_ERROR("SyscallGetNumberOfThreadsForCurrentProcess", status);
        return status;
    }
    LOG("Status: %d, Number of thread: %d", status, &threadNo);

    /*
    BYTE utilization;
    PCPU* pCpu;

    pCpu = GetCurrentPcpu();

    status = SyscallGetCPUUtilization(pCpu->ApicId, &utilization);
    if (!SUCCEEDED(status))
    {
        LOG_FUNC_ERROR("SyscallGetCPUUtilization", status);
        return status;
    }

    LOG("Status: %d, CPU ID: %d", status, pcpu->ApicId);*/

    // Stop
    status = SyscallThreadGetTid(UM_INVALID_HANDLE_VALUE, &tid);
    if (!SUCCEEDED(status))
    {
        LOG_FUNC_ERROR("SyscallThreadGetTid", status);
        return status;
    }

    LOG("Hello from thread with ID 0x%X\n", tid);

    status = UmThreadCreate(_HelloWorldFromThread, (PVOID)(QWORD)argc, &umHandle);
    if (!SUCCEEDED(status))
    {
        LOG_FUNC_ERROR("SyscallThreadCreate", status);
        return status;
    }

    //SyscallThreadCloseHandle()

    return STATUS_SUCCESS;
}

STATUS
(__cdecl _HelloWorldFromThread)(
    IN_OPT      PVOID       Context
    )
{
    STATUS status;
    TID tid;

    ASSERT(Context != NULL);

    status = SyscallThreadGetTid(UM_INVALID_HANDLE_VALUE, &tid);
    if (!SUCCEEDED(status))
    {
        LOG_FUNC_ERROR("SyscallThreadGetTid", status);
        return status;
    }

    LOG("Hello from thread with ID 0x%X\n", tid);
    LOG("Context is 0x%X\n", Context);

    return status;
}