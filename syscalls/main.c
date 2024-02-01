#include <Windows.h>
#include <stdio.h>


extern NTSTATUS aCall();
extern VOID aSetup(DWORD, PVOID);

int AreWeHooked(UINT_PTR funcAddr) {
	if (((unsigned char*)(funcAddr))[0] == 0x4c && 
		((unsigned char*)(funcAddr))[1] == 0x8b && 
		((unsigned char*)(funcAddr))[2] == 0xd1 &&
		((unsigned char*)(funcAddr))[3] == 0xb8) {
		return 0;
	}

	return 1;
}

int GetSyscallNumber(UINT_PTR funcAddr) {
	BYTE high;
	BYTE low;

	if (!AreWeHooked(funcAddr)) {
		high = ((unsigned char*)(funcAddr + 5))[0];
		low = ((unsigned char*)(funcAddr + 4))[0];

		return (high << 8) | low;// if not hooked return syscall number.
	}

	for (int i = 0; i < 24; i++) {
		if (((unsigned char*)(funcAddr))[i] == 0xb8) {
			high = ((unsigned char*)(funcAddr))[i + 2];
			low =  ((unsigned char*)(funcAddr))[i + 1];
			return (high << 8) | low;
		}
	}

	return 0;
}


UINT_PTR GetSyscallJumpAddress(UINT_PTR funcAddr) {
	if (!AreWeHooked(funcAddr)) {
		return funcAddr + 0x12;// if not hooked return syscall addr.
	}

	for (int i = 0; i < 24; i++) {
		if (((unsigned char*)(funcAddr))[i] == 0x0f && ((unsigned char*)(funcAddr))[i + 1] == 0x05 && ((unsigned char*)(funcAddr))[i + 2] == 0xC3) {
			return funcAddr + i;
		}
	}
}

int main() {
	DWORD SysNum;
	UINT_PTR jmpAddr;

	HANDLE hNtdll = GetModuleHandleA("ntdll.dll");
	UINT_PTR delayexecution = (UINT_PTR)GetProcAddress(hNtdll, "NtDelayExecution");


	UINT_PTR NtSuspendProcess = (UINT_PTR)GetProcAddress(hNtdll, "NtSuspendProcess");
	printf("[+] NtSuspendProcess\n");
	printf("[+] Hooked: %d\n", AreWeHooked(NtSuspendProcess));
	SysNum = GetSyscallNumber(NtSuspendProcess);
	printf("[+] Syscall Number: %d \n", SysNum);
	printf("[+] Syscall Number: %x \n", SysNum);
	jmpAddr = GetSyscallJumpAddress(NtSuspendProcess);
	printf("[+] Syscall Jump: %p \n\n\n", jmpAddr);

	printf("[+] NtDelayExecution\n");
	printf("[+] Hooked: %d\n", AreWeHooked(delayexecution));
	SysNum = GetSyscallNumber(delayexecution);
	printf("[+] Syscall Number: %d \n", SysNum);
	printf("[+] Syscall Number: %x \n", SysNum);
	jmpAddr = GetSyscallJumpAddress(delayexecution);
	printf("[+] Syscall Jump: %p \n", jmpAddr);



	printf("%p \n", jmpAddr);
	printf("About to wait 10seconds\n");
	aSetup(SysNum, (PVOID)jmpAddr);
	LARGE_INTEGER interval;
	interval.QuadPart = -1 * (int)(10000.0f * 10000.0f);

	aCall(-1, &interval);
	printf("Should have waited 10 seconds\n");

	getchar();


	return 0;
}