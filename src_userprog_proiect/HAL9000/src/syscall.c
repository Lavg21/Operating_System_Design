#include "HAL9000.h"
#include "syscall.h"
#include "gdtmu.h"
#include "syscall_defs.h"
#include "syscall_func.h"
#include "syscall_no.h"
#include "mmu.h"
#include "process_internal.h"
#include "dmp_cpu.h"
#include "thread_internal.h"
#include "cpumu.h"
#include "smp.h"

extern void SyscallEntry();

#define SYSCALL_IF_VERSION_KM       SYSCALL_IMPLEMENTED_IF_VERSION

void
SyscallHandler(
    INOUT   COMPLETE_PROCESSOR_STATE    *CompleteProcessorState
    )
{
    SYSCALL_ID sysCallId;
    PQWORD pSyscallParameters;
    PQWORD pParameters;
    STATUS status;
    REGISTER_AREA* usermodeProcessorState;

    ASSERT(CompleteProcessorState != NULL);

    // It is NOT ok to setup the FMASK so that interrupts will be enabled when the system call occurs
    // The issue is that we'll have a user-mode stack and we wouldn't want to receive an interrupt on
    // that stack. This is why we only enable interrupts here.
    ASSERT(CpuIntrGetState() == INTR_OFF);
    CpuIntrSetState(INTR_ON);

    LOG_TRACE_USERMODE("The syscall handler has been called!\n");

    status = STATUS_SUCCESS;
    pSyscallParameters = NULL;
    pParameters = NULL;
    usermodeProcessorState = &CompleteProcessorState->RegisterArea;

    __try
    {
        if (LogIsComponentTraced(LogComponentUserMode))
        {
            DumpProcessorState(CompleteProcessorState);
        }

        // Check if indeed the shadow stack is valid (the shadow stack is mandatory)
        pParameters = (PQWORD)usermodeProcessorState->RegisterValues[RegisterRbp];
        status = MmuIsBufferValid(pParameters, SHADOW_STACK_SIZE, PAGE_RIGHTS_READ, GetCurrentProcess());
        if (!SUCCEEDED(status))
        {
            LOG_FUNC_ERROR("MmuIsBufferValid", status);
            __leave;
        }

        sysCallId = usermodeProcessorState->RegisterValues[RegisterR8];

        LOG_TRACE_USERMODE("System call ID is %u\n", sysCallId);

        // The first parameter is the system call ID, we don't care about it => +1
        pSyscallParameters = (PQWORD)usermodeProcessorState->RegisterValues[RegisterRbp] + 1;

        // Dispatch syscalls
        switch (sysCallId)
        {
        case SyscallIdIdentifyVersion:
            status = SyscallValidateInterface((SYSCALL_IF_VERSION)*pSyscallParameters);
            break;
        case SyscallIdFileWrite:
            status = SyscallFileWrite((UM_HANDLE)pSyscallParameters[0],
                                      (PVOID)pSyscallParameters[1],
                                      (QWORD)pSyscallParameters[2],
                                      (QWORD*)pSyscallParameters[3]);
            break;
        case SyscallIdProcessExit:
            status = SyscallProcessExit((STATUS)pSyscallParameters[0]);
            break;
        case SyscallIdThreadExit:
            status = SyscallThreadExit((STATUS)pSyscallParameters[0]);
            break;
        // STUDENT TODO: implement the rest of the syscalls
        case SyscallIdThreadGetTid:
            status = SyscallThreadGetTid((UM_HANDLE)pSyscallParameters[0],
                                          (TID*)pSyscallParameters[1]);
            break;
        case SyscallIdProcessGetName:
            status = SyscallProcessGetName((char*)pSyscallParameters[0],
                                           (QWORD)pSyscallParameters[1]);
            break;
        case SyscallIdGetThreadPriority:
            status = SyscallGetThreadPriority((BYTE*)pSyscallParameters[0]);
            break;
        case SyscallIdSetThreadPriorityfunction:
            status = SyscallSetThreadPriority((BYTE)pSyscallParameters[0]);
            break;
        case SyscallIdGetCurrentCPUID:
            status = SyscallGetCurrentCPUID((BYTE*)pSyscallParameters[0]);
            break;
        case SyscallIdGetNumberOfThreadsForCurrentProcess:
            status = SyscallGetNumberOfThreadsForCurrentProcess((QWORD*)pSyscallParameters[0]);
            break;
        case SyscallIdGetCPUUtilization:
            status = SyscallGetCPUUtilization((BYTE*)pSyscallParameters[0], 
                                              (BYTE*)pSyscallParameters[1]);
            break;
        default:
            LOG_ERROR("Unimplemented syscall called from User-space!\n");
            status = STATUS_UNSUPPORTED;
            break;
        }

    }
    __finally
    {
        LOG_TRACE_USERMODE("Will set UM RAX to 0x%x\n", status);

        usermodeProcessorState->RegisterValues[RegisterRax] = status;

        CpuIntrSetState(INTR_OFF);
    }
}

void
SyscallPreinitSystem(
    void
    )
{

}

STATUS
SyscallInitSystem(
    void
    )
{
    return STATUS_SUCCESS;
}

STATUS
SyscallUninitSystem(
    void
    )
{
    return STATUS_SUCCESS;
}

void
SyscallCpuInit(
    void
    )
{
    IA32_STAR_MSR_DATA starMsr;
    WORD kmCsSelector;
    WORD umCsSelector;

    memzero(&starMsr, sizeof(IA32_STAR_MSR_DATA));

    kmCsSelector = GdtMuGetCS64Supervisor();
    ASSERT(kmCsSelector + 0x8 == GdtMuGetDS64Supervisor());

    umCsSelector = GdtMuGetCS32Usermode();
    /// DS64 is the same as DS32
    ASSERT(umCsSelector + 0x8 == GdtMuGetDS32Usermode());
    ASSERT(umCsSelector + 0x10 == GdtMuGetCS64Usermode());

    // Syscall RIP <- IA32_LSTAR
    __writemsr(IA32_LSTAR, (QWORD) SyscallEntry);

    LOG_TRACE_USERMODE("Successfully set LSTAR to 0x%X\n", (QWORD) SyscallEntry);

    // Syscall RFLAGS <- RFLAGS & ~(IA32_FMASK)
    __writemsr(IA32_FMASK, RFLAGS_INTERRUPT_FLAG_BIT);

    LOG_TRACE_USERMODE("Successfully set FMASK to 0x%X\n", RFLAGS_INTERRUPT_FLAG_BIT);

    // Syscall CS.Sel <- IA32_STAR[47:32] & 0xFFFC
    // Syscall DS.Sel <- (IA32_STAR[47:32] + 0x8) & 0xFFFC
    starMsr.SyscallCsDs = kmCsSelector;

    // Sysret CS.Sel <- (IA32_STAR[63:48] + 0x10) & 0xFFFC
    // Sysret DS.Sel <- (IA32_STAR[63:48] + 0x8) & 0xFFFC
    starMsr.SysretCsDs = umCsSelector;

    __writemsr(IA32_STAR, starMsr.Raw);

    LOG_TRACE_USERMODE("Successfully set STAR to 0x%X\n", starMsr.Raw);
}

// SyscallIdIdentifyVersion
STATUS
SyscallValidateInterface(
    IN  SYSCALL_IF_VERSION          InterfaceVersion
)
{
    LOG_TRACE_USERMODE("Will check interface version 0x%x from UM against 0x%x from KM\n",
        InterfaceVersion, SYSCALL_IF_VERSION_KM);

    if (InterfaceVersion != SYSCALL_IF_VERSION_KM)
    {
        LOG_ERROR("Usermode interface 0x%x incompatible with KM!\n", InterfaceVersion);
        return STATUS_INCOMPATIBLE_INTERFACE;
    }

    return STATUS_SUCCESS;
}

STATUS
SyscallFileWrite(
    IN  UM_HANDLE                   FileHandle,
    IN_READS_BYTES(BytesToWrite)
    PVOID                           Buffer,
    IN  QWORD                       BytesToWrite,
    OUT QWORD* BytesWritten
)
{
    if (FileHandle == UM_FILE_HANDLE_STDOUT) {
        LOG("Buffer:%s\n", Buffer);
        *BytesWritten = BytesToWrite;
    }

    return STATUS_SUCCESS;
}

STATUS
SyscallProcessExit(
    IN      STATUS                  ExitStatus
)
{
    UNREFERENCED_PARAMETER(ExitStatus);

    ProcessTerminate(NULL);

    return STATUS_SUCCESS;
}

STATUS
SyscallThreadExit(
    IN      STATUS                  ExitStatus
)
{
    ThreadExit(ExitStatus);

    return STATUS_SUCCESS;
}
// STUDENT TODO: implement the rest of the syscalls

STATUS
SyscallThreadGetTid(
    IN_OPT UM_HANDLE                ThreadHandle,
    OUT TID*                        ThreadId
)
{
    if (ThreadHandle == UM_INVALID_HANDLE_VALUE) {
        *ThreadId = GetCurrentThread()->Id;
        return STATUS_SUCCESS;
    }

    *ThreadId = ((PTHREAD) ThreadHandle)->Id;

    return STATUS_SUCCESS;
}


STATUS SyscallProcessGetName(OUT char* ProcessName, IN QWORD ProcessNameMaxLen) {

    // Retrieve the process name
    char* currentProcessName = GetCurrentProcess()->ProcessName;

    if (currentProcessName == NULL) {
        return STATUS_INVALID_PARAMETER1;
    }

    // Determine the length of the process name
    int processNameLength = strlen(currentProcessName);

    if (processNameLength >= ProcessNameMaxLen) {
        // Truncate the process name if it doesn't fit entirely
        strncpy(ProcessName, currentProcessName, (DWORD) ProcessNameMaxLen - 1);
        // Ensure the last character is '\0'
        ProcessName[ProcessNameMaxLen - 1] = '\0';
        return STATUS_SUCCESS;
    }
    else {
        // Copy the entire process name
        strcpy(ProcessName, currentProcessName);
        return STATUS_SUCCESS;
    }
}

STATUS SyscallGetThreadPriority(OUT BYTE* ThreadPriority) {

    // Get the priority of the current thread
    PTHREAD pThread = GetCurrentThread();

    // Get priority of thread
    THREAD_PRIORITY threadPriority = ThreadGetPriority(pThread);

    if (threadPriority == ThreadPriorityLowest) {
        ThreadPriority = (BYTE*)0;
    } else if (threadPriority == ThreadPriorityDefault) {
        ThreadPriority = (BYTE*)16;
    } else if (threadPriority == ThreadPriorityMaximum) {
        ThreadPriority = (BYTE*)31;
    }

    return STATUS_SUCCESS;
}

STATUS SyscallSetThreadPriority(IN BYTE ThreadPriority) {

    // Assign the thread priority to the input priority
    ThreadSetPriority(ThreadPriority);

    return STATUS_SUCCESS;
}

STATUS SyscallGetCurrentCPUID(OUT BYTE* CpuId) {

    PCPU* pCpu;

    // Retrieve the CPU ID where the current thread
    pCpu = GetCurrentPcpu();

    // Check if the CPU ID can be retrieved
    if (pCpu->ApicId < 0) {
        return STATUS_UNSUCCESSFUL;
    }

    // Assign the CPU ID to the output parameter
    *CpuId = pCpu->ApicId;

    return STATUS_SUCCESS;
}

STATUS SyscallGetNumberOfThreadsForCurrentProcess(OUT QWORD* ThreadNo) {

    // Count the number of threads for the current process
    DWORD threads = GetCurrentProcess()->NumberOfThreads;

    // Assign the thread count to the output parameter
    *ThreadNo = threads;

    return STATUS_SUCCESS;
}

STATUS SyscallGetCPUUtilization(IN_OPT BYTE* CpuId, OUT BYTE* Utilization) {
    PLIST_ENTRY pCpuListHead;
    SmpGetCpuList(&pCpuListHead);

    LIST_ENTRY* pCurEntry;
    for (pCurEntry = pCpuListHead->Flink; pCurEntry != pCpuListHead; pCurEntry = pCurEntry->Flink) {
        PCPU* pCpu = CONTAINING_RECORD(pCurEntry, PCPU, ListEntry);

        if (CpuId == NULL || *CpuId == pCpu->ApicId) {
            QWORD totalTicks = pCpu->ThreadData.IdleTicks + pCpu->ThreadData.KernelTicks;

            // Check if totalTicks is not 0 to avoid division by zero
            QWORD percentage = (totalTicks != 0) ? (pCpu->ThreadData.IdleTicks * 10000) / totalTicks : 0;

            // Assign the calculated percentage to the OUT parameter
            *Utilization = (BYTE)percentage;

            if (CpuId != NULL) {
                break;
            }
        }
    }

    return STATUS_SUCCESS;
}

/*
(10%) Handle the SyscallFileWrite() system call for the particular case of the UM_FILE_HANDLE_STDOUT file handle, to provide the user processes the way to display something on the screen, e.g. by using the printf() function.
(10%) Handle the SyscallThreadGetTid() system call to return the id of the calling thread.
(10%) Add a new system call STATUS SyscallProcessGetName(OUT char* ProcessName, IN QWORD ProcessNameMaxLen) such that to
check if the given memory address (i.e. ProcessName) is valid,
copy at the given address the calling process’ name, but no more than ProcessNameMaxLen characters, the last one being always '\0',
return STATUS_SUCCESS if the entire name was successfully copied, or STATUS_TRUNCATED_PROCESS_NAME in the other case.
(5%) Add a new system call STATUS SyscallGetThreadPriority(OUT BYTE* ThreadPriority) to return the priority of the current thread.
(5%) Add a new system call STATUS SyscallSetThreadPriority(IN BYTE ThreadPriority) to set the priority of the current thread.
(5%) Add a new system call STATUS SyscallGetCurrentCPUID(OUT BYTE* CpuId) to return the ID of the CPU the current thread is executing on.
(5%) Add a new system call STATUS SyscallGetNumberOfThreadsForCurrentProcess(OUT QWORD* ThreadNo) to return the total number of threads started by the current process.
(10%) Add a new system call STATUS SyscallGetCPUUtilization(IN_OPT BYTE* CpuId, OUT BYTE* Utilization) the CPU utilization of a given CPU, or the average utilization of all CPUs if CpuId is NULL.
The returned number should represent the utilization in percent (i.e. be in the range [0 - 100]).
The utilization of a CPU can be calculated as ((total ticks - idle ticks) / total ticks).
(30%) Create a new user application named LightProjectApp to perform the following steps:
(15%) Displays on the screen the name of the current process using SyscallProcessGetName. You should also call SyscallProcessGetName with:
ProcessNameMaxLen = 1 to confirm that function successfully handles this case
ProcessNameMaxLen = 3 to confirm that function successfully handles this case
ProcessName = 0x1234 to confirm that function successfully handles this case
(5%) Displays on the screen the priority of the current thread. Then changes the priority and displays it again.
(5%) Displays on the screen the number of threads started by the current process and the current CPU id.
(5%) Displays on the screen the CPU utilization of the current CPU and all CPUs.
*/

/*
* (20%) Implement the system calls SyscallVirtualAlloc(...) and SyscallVirtualFree(...), whose signatures are given in file syscall_func.h. You should only handle cases when the following conditions on the given parameters hold simultaneously, otherwise return STATUS_INVALID_PARAMETERx (x is the number of the invalid parameter, starting from 1):
BaseAddress == NULL (i.e. let the kernel decide where in the calling process’ virtual address space to reserve the needed pages for the requested memory)
FileHandle == UM_INVALID_HANDLE_VALUE (i.e. not a memory-mapped file), and
Key == 0 (no sharing). NOTE: you could make use the kernel functions VmmAllocRegionEx(...) and VmmFreeRegionEx(...).
(20%) Add a new system call STATUS SyscallGetPageFaultNo(IN PVOID AllocatedVirtAddr, OUT QWORD PageFaultNo);, which stores in PageFaultNo the number of page faults generated during accesses to the virtual page containing the address given by the AllocatedVirtAddr parameter.
(20%) Add a new system call STATUS SyscallGetPagePhysAddr(IN PVOID AllocatedVirtAddr, OUT PVOID AllocatedPhysAddr);, AllocatedPhysAddr the physical address the given AllocatedVirtAddr is mapped to. If the page containing the given virtual address is not mapped (i.e. not present) in the physical memory, NULL should be returned.
(20%) Add a new system call STATUS SyscallGetPageInternalFragmentation(IN PVOID AllocatedVirtAddr, OUT QWORD IntFragSize);, which stores in IntFragSize the number of bytes lost due to internal fragmentation (i.e. space not required, yet allocated) in the virtual page the given AllocatedVirtAddr belongs to. This could occur when the size in bytes of the allocated memory is not a multiple of page size.
*/

/*
STATUS
SyscallVirtualAlloc(
    IN_OPT      PVOID                   BaseAddress,
    IN          QWORD                   Size,
    IN          VMM_ALLOC_TYPE          AllocType,
    IN          PAGE_RIGHTS             PageRights,
    IN_OPT      UM_HANDLE               FileHandle,
    IN_OPT      QWORD                   Key,
    OUT         PVOID*                  AllocatedAddress
)
{
    if (BaseAddress != NULL)
    {
        return STATUS_INVALID_PARAMETER1;
    }

    if (FileHandle != UM_INVALID_HANDLE_VALUE)
    {
        return STATUS_INVALID_PARAMETER5;
    }

    if (Key != 0)
    {
        return STATUS_INVALID_PARAMETER6;
    }

    STATUS status = VmmAllocRegionEx(
        BaseAddress,
        Size,
        AllocType,
        PageRights,
        /*Uncacheable=*/FALSE,
            /*FileObject=*/NULL, // FileObject is not used in this case
            /*VaSpace=*/NULL,    // VaSpace is not used in this case
            /*PagingData=*/NULL, // PagingData is not used in this case
            /*Mdl=*/NULL         // Mdl is not used in this case
            );

            if (!SUCCEEDED(status))
            {
                LOG_FUNC_ERROR("VmmAllocRegionEx", status);
            }

            *AllocatedAddress = BaseAddress;

            g_pageFaultCount++;

            return STATUS_SUCCESS;
}

STATUS SyscallVirtualFree(
    IN          PVOID                   Address,
    _When_(VMM_FREE_TYPE_RELEASE == FreeType, _Reserved_)
    _When_(VMM_FREE_TYPE_RELEASE != FreeType, IN)
    QWORD                   Size,
    IN          VMM_FREE_TYPE           FreeType
)
{
    if (Address == NULL)
    {
        return STATUS_INVALID_PARAMETER1;
    }

    STATUS status = VmmFreeRegionEx(
        Address,
        Size,
        FreeType,
        /*Release=*/TRUE,
        /*VaSpace=*/NULL,     // VaSpace is not used in this case
        /*PagingData=*/NULL   // PagingData is not used in this case
    );

    return STATUS_SUCCESSFUL;
}

QWORD g_pageFaultCount = 0; // global counter 

STATUS SyscallGetPageFaultNo(
    IN          PVOID                   AllocatedVirtAddr,
    OUT         QWORD* PageFaultNo
)
{
    // Check the specified conditions
    if (AllocatedVirtAddr == NULL)
    {
        return STATUS_INVALID_PARAMETER1;
    }

    if (PageFaultNo == NULL)
    {
        return STATUS_INVALID_PARAMETER2;
    }

    // Retrieve page fault count for the given virtual address
    // In this example, we use a simple global counter
    *PageFaultNo = g_pageFaultCount;

    return STATUS_SUCCESS;
}

STATUS SyscallGetPagePhysAddr(
    IN          PVOID                   AllocatedVirtAddr,
    OUT         PVOID* AllocatedPhysAddr
)
{
    // Check the specified conditions
    if (AllocatedVirtAddr == NULL)
    {
        return STATUS_INVALID_PARAMETER1;
    }

    if (AllocatedPhysAddr == NULL)
    {
        return STATUS_INVALID_PARAMETER2;
    }

    *AllocatedPhysAddr = AllocatedVirtAddr;

    return STATUS_SUCCESSFUL;

}

STATUS SyscallGetPageInternalFragmentation(
    IN          PVOID                   AllocatedVirtAddr,
    OUT         QWORD* IntFragSize
)
{
    // Check the specified conditions
    if (AllocatedVirtAddr == NULL)
    {
        return STATUS_INVALID_PARAMETER1;
    }

    if (IntFragSize == NULL)
    {
        return STATUS_INVALID_PARAMETER2;
    }

    *IntFragSize = 0; // For demonstration purposes, 
                     //assuming no internal fragmentation

    return STATUS_SUCCESS;
}

*/

/*
Build the User-mode/Util/CopyUmAppsToVm project. You should see the list of applications copied in the Output window.
*/

/*
STATUS
SyscallReadMemory(IN_READS(1) PBYTE Address, OUT Byte ValueRead){
BOOLEAN isAddress Accesable = FALSE;
PROCESS process = GetCurrentProcess();
PVMM_RESERVATION_SPACE reservation = process->VaSpace;
PAGE RIGHTS memoryRights; 
BOOLEAN unchaceable;
PFILE_OBJECT fileObject; 
QWORD fileOffset;

isAddressAccessable = VmReservationCanAddressBeAccessed(
reservation, (PVOID) Address, PAGE_RIGHTS_READ, &memoryRights,
&unchaceable,
fileObject,
&fileOffset
);
if (!isAddressAccessable) {
ValueRead = NULL;
return STATUS_UNSUCCESSFUL;
}
}
*/

/*
adaugi syscall ul nou pe peste tot ca de obicei : syscall_no.h, syscall_func.h, syscall_if.c, si in case switch ul din syscall.c, dupa faci implementarea in syscall.c :
*/