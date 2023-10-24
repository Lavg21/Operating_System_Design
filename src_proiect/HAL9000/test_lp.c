#include "test_lp.h"
#include "test_common.h"
#include "test_thread.h"
#include "test_timer.h"
#include "test_priority_scheduler.h"
#include "test_priority_donation.h"

#include "mutex.h"

FUNC_ThreadStart                MultithreadFibonacci;


const THREAD_TEST THREADS_TEST_FIBONACCI[] =
{
	{"MultithreadFibonacci", MultithreadFibonacci, NULL, NULL, NULL, NULL, FALSE, FALSE }
};

STATUS
(__cdecl MultithreadFibonacci)(
	IN_OPT      PVOID       Context
	)
{
	STATUS status; // added

	LOG_FUNC_START_THREAD;

	UNREFERENCED_PARAMETER(Context);

	PLP_FIB_THREAD_CONTEXT context =
		(PLP_FIB_THREAD_CONTEXT)Context;
	if (context->Index == 0 || context->Index == 1) {
		context->Result = 1;
		return STATUS_SUCCESS;
	}
	LP_FIB_THREAD_CONTEXT context1 = { 0 };
	LP_FIB_THREAD_CONTEXT context2 = { 0 };
	PTHREAD thread1 = NULL;
	PTHREAD thread2 = NULL;
	char thName[MAX_PATH];
	__try
	{
		printf(thName, MAX_PATH, "Fib -%d", context->Index);
		status = ThreadCreate(thName,
			ThreadPriorityDefault,
			MultithreadFibonacci,
			&context1,
			&thread1
		);
		if (!SUCCEEDED(status))
		{
			LOG_FUNC_ERROR(" ThreadCreate ", status);
			__leave;
		}
		printf(thName, MAX_PATH, "Fib -%d", context->Index);
		status = ThreadCreate(thName,
			ThreadPriorityDefault,
			MultithreadFibonacci,
			&context2,
			&thread2
		);
		if (!SUCCEEDED(status))
		{
			LOG_FUNC_ERROR(" ThreadCreate ", status);
			__leave;
		}
		context->Result = context1.Result + context2.Result;
	}
	__finally
	{
		if (thread1)
		{
			ThreadCloseHandle(thread1);
		}
		if (thread2)
		{
			ThreadCloseHandle(thread2);
		}
	}

	LOG_FUNC_END_THREAD;

	return status;
}