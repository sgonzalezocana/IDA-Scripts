# Lumma Stealer

Tested on Lumma Stealer v4.0 on the following sample:
https://www.virustotal.com/gui/file/c68856eee73796bc835c205be54888e3c99caf983dc5d35aedf2981fd41be527

**C2 servers:**
```
gnFpbh6lzeg2J9ls0gmqctKYZtfim+5c3D04iq8TBVXhHQwPbMSji1NM9x+7fc8= ----> clearancek.site
gnFpbh6lzeg2J9ls0gmqctKYZtfim+5c3D04iq8TBVXvHgsMd9WohlxS9x+mZtgX ----> mobbipenju.store
gnFpbh6lzeg2J9ls0gmqctKYZtfim+5c3D04iq8TBVXnEA4Ce9Wsn1hIoEKhfcUAtw== ----> eaglepawnoy.store
gnFpbh6lzeg2J9ls0gmqctKYZtfim+5c3D04iq8TBVXmGBodf9WigUxJrkKhfcUAtw== ----> dissapoiznw.store
gnFpbh6lzeg2J9ls0gmqctKYZtfim+5c3D04iq8TBVXxBRwKe8ujh0JCvQWlJ9kGveoD ----> studennotediw.store
gnFpbh6lzeg2J9ls0gmqctKYZtfim+5c3D04iq8TBVXgEB0GesqihVFGo0KhfcUAtw== ----> bathdoomgaz.store
gnFpbh6lzeg2J9ls0gmqctKYZtfim+5c3D04iq8TBVXxAQAcd9G5nVhCskKhfcUAtw== ----> spirittunek.store
gnFpbh6lzeg2J9ls0gmqctKYZtfim+5c3D04iq8TBVXuGAoLcMGrgVpTvAP8esMGtw== ----> licendfilteo.site
gnFpbh6lzeg2J9ls0gmqctKYZtfim+5c3D04iq8TBVXhHQwPbMSji1NM9x+7fc8= ----> clearancek.site
```

**Hashed Apis**
```
0x4acba761 -> WinHttpOpen (winhttp.dll)
0x5cafdff1 -> WinHttpConnect (winhttp.dll)
0x2bcbe176 -> WinHttpOpenRequest (winhttp.dll)
0xd543a40a -> WinHttpCrackUrl (winhttp.dll)
0x1802d93f -> WinHttpSetTimeouts (winhttp.dll)
0x2cca4b49 -> WinHttpAddRequestHeaders (winhttp.dll)
0x93b7a228 -> WinHttpSendRequest (winhttp.dll)
0xfe02a2d -> WinHttpReceiveResponse (winhttp.dll)
0xf1adad3a -> WinHttpQueryDataAvailable (winhttp.dll)
0x754c8fbd -> WinHttpReadData (winhttp.dll)
0x754c8fbd -> WinHttpReadData (winhttp.dll)
0xc8d440dc -> WinHttpWriteData (winhttp.dll)
0x557de69d -> WinHttpCloseHandle (winhttp.dll)
0x1987ef4b -> CreateProcessW (kernel32.dll)
0x1987ef4b -> CreateProcessW (kernel32.dll)
0xd80d2c4a -> LocalFree (kernel32.dll)
0xd80d2c4a -> LocalFree (kernel32.dll)
0x7205114d -> LoadLibraryW (kernel32.dll)
0xf2e10859 -> GetProcAddress (kernel32.dll)
0xd80d2c4a -> LocalFree (kernel32.dll)
0xd80d2c4a -> LocalFree (kernel32.dll)
0xa031abd0 -> GetComputerNameA (kernel32.dll)
0x52d6fd7 -> GetComputerNameExA (kernel32.dll)
0xfc327aac -> GetUserDefaultLocaleName (kernel32.dll)
0xfd7a6173 -> GetPhysicallyInstalledSystemMemory (kernel32.dll)
0xfd7a6173 -> GetPhysicallyInstalledSystemMemory (kernel32.dll)
0xc89947f6 -> EnumDisplayDevicesW (user32.dll)
0x80fdacc0 -> EnumDisplaySettingsW (user32.dll)
0xd2e7977e -> GetVolumeInformationW (kernel32.dll)
0xf8eb88df -> IsWow64Process (kernel32.dll)
0xf8eb88df -> IsWow64Process (kernel32.dll)
0xf8eb88df -> IsWow64Process (kernel32.dll)
0xf8eb88df -> IsWow64Process (kernel32.dll)
0xf8eb88df -> IsWow64Process (kernel32.dll)
0x6fbdd3ec -> RtlAllocateHeap (ntdll.dll)
0x7695f9b5 -> RtlReAllocateHeap (ntdll.dll)
0x4b724709 -> RtlFreeHeap (ntdll.dll)
0x9d70c490 -> RtlExpandEnvironmentStrings (ntdll.dll)
0xeb2bb7e -> LoadLibraryExW (kernel32.dll)
0x1263c032 -> FreeLibrary (kernel32.dll)
```
