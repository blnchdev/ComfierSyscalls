# Comfier Syscalls
![Example Implementation](https://blanche.dev/img/comfier_syscalls.png)
Bit of a meme that dynamically retrieves syscall indexes on Windows and then calls them directly using ComfySyscalls  
This is only useful if you need to dynamically call functions like [NtReadVirtualMemoryEx](https://ntdoc.m417z.com/ntreadvirtualmemoryex) and don't want to hard-code the IDX by WinVer  
Do be warned that this doesn't cache the syscall IDX and it'll call GetProcAddress on every pass  

### Credits
[ComfySyscalls](https://www.unknowncheats.me/forum/c-and-c-/267587-comfy-direct-syscall-caller-x64.html) by namazso - This is just a 'modernization' of their code
