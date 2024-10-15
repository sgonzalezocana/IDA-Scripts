# Latrodectus

Tested on the following sample:
https://www.virustotal.com/gui/file/9e4ebf3412a36099adf96f26ffc3265a7a5b9eefc5f1a0d87f10dbadf82474c1

Unpacked sample: 7fadf078fe8f52245aeb541c34544156c3289cef002c490547940d4a7125b35b

**Hashed Apis**
```
Ws2_32.dll : 0x28ec9370 -> socket
Ws2_32.dll : 0xebe108a6 -> connect
Ws2_32.dll : 0x63fba7ac -> send
user32.dll : 0xb97e70e8 -> ToUnicode
user32.dll : 0xd4e1b90d -> GetKeyState
user32.dll : 0xd649c1d -> GetWindowTextW
ntdll.dll : 0xc5a118b3 -> LdrLoadDll
ntdll.dll : 0xe15b7d06 -> RtlDosPathNameToNtPathName_U
ntdll.dll : 0x898814a7 -> RtlQueryEnvironmentVariable_U
ntdll.dll : 0x7143b014 -> RtlSetEnvironmentVariable
ntdll.dll : 0xdbbf8f64 -> NtOpenProcess
ntdll.dll : 0x1bde40b5 -> NtOpenThread
ntdll.dll : 0x5c821402 -> NtGetContextThread
ntdll.dll : 0xc02fbf40 -> NtSetContextThread
ntdll.dll : 0x2a567650 -> NtSuspendThread
ntdll.dll : 0xe55bb31 -> NtResumeThread
ntdll.dll : 0xc4e42017 -> NtQueueApcThread
ntdll.dll : 0x4c830c46 -> NtDelayExecution
ntdll.dll : 0x1f3674b2 -> NtQuerySystemInformation
ntdll.dll : 0x57c3bab -> NtQueryInformationProcess
ntdll.dll : 0x9f738476 -> NtOpenDirectoryObject
ntdll.dll : 0x1d9fba27 -> NtCreateMutant
ntdll.dll : 0xa683555b -> NtCreateSection
ntdll.dll : 0x80955070 -> NtMapViewOfSection
ntdll.dll : 0x777d865e -> NtUnmapViewOfSection
ntdll.dll : 0x4130bffa -> NtCreateKey
ntdll.dll : 0x8fd4a6f9 -> NtSetValueKey
ntdll.dll : 0x6139afeb -> NtQueryValueKey
ntdll.dll : 0xc9f09fd4 -> NtEnumerateKey
ntdll.dll : 0xb132f47f -> NtEnumerateValueKey
ntdll.dll : 0x7f73177d -> NtOpenProcessToken
ntdll.dll : 0xefe501c2 -> NtQueryInformationToken
ntdll.dll : 0x6072f845 -> NtAdjustPrivilegesToken
ntdll.dll : 0xa5c9cf4e -> NtWaitForSingleObject
ntdll.dll : 0xa34c409d -> NtQueryInformationFile
ntdll.dll : 0xf87d2124 -> NtSetInformationFile
ntdll.dll : 0x1993bbcb -> NtCreateFile
ntdll.dll : 0x326ebeb -> NtWriteFile
ntdll.dll : 0x21e041ba -> NtReadFile
ntdll.dll : 0x760d3090 -> NtDeleteFile
ntdll.dll : 0xf2943785 -> NtClose
ntdll.dll : 0xfed367d -> NtQueryVirtualMemory
ntdll.dll : 0xb8e2291b -> NtReadVirtualMemory
ntdll.dll : 0x9e0f4cc4 -> NtAllocateVirtualMemory
ntdll.dll : 0x3de92315 -> NtProtectVirtualMemory
ntdll.dll : 0x71d66a8c -> NtFreeVirtualMemory
ntdll.dll : 0xb814f8a4 -> RtlGetProcessHeaps
ntdll.dll : 0xebb04c4c -> RtlAllocateHeap
ntdll.dll : 0x976d8b4 -> RtlFreeHeap
kernel32.dll : 0xf82f9e01 -> ExitProcess
kernel32.dll : 0x173f20df -> CreateProcessInternalW
kernel32.dll : 0xf2830664 -> GetPrivateProfileSectionNamesW
kernel32.dll : 0xa6971779 -> GetPrivateProfileStringW
advapi32.dll : 0x31820165 -> LookupPrivilegeValueW
advapi32.dll : 0x46047551 -> ConvertSidToStringSidW
Ws2_32.dll : 0x381883d6 -> htons
Ws2_32.dll : 0xee4f2e57 -> WSAStartup
Ws2_32.dll : 0xfc05cbfa -> closesocket
ntdll.dll : 0xd9a5ef82 -> NtCreateProcessEx
ntdll.dll : 0xaa6449c7 -> NtQuerySection
ntdll.dll : 0x1770601 -> NtWriteVirtualMemory
```
