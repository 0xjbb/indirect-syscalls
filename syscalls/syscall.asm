.data
jmpAddr QWORD 0h
sysNum DWORD 0h

.code

aSetup PROC
	mov eax, ecx ; make it look kinda different
	mov sysNum, eax
	mov rax, rdx
	mov jmpAddr, rax
	ret
aSetup ENDP

aCall PROC
	push jmpAddr
	mov rax, rcx
	mov r10, rax
	mov eax, sysNum
	ret
aCall ENDP

END