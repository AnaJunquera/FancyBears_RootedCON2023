# Credential Access queries

## LSASS dump with rundll32 (T1003.001)
```
process = "rundll32.exe" and command_line regex "(?i).*comsvcs\.dll, MiniDump.*"
```

## SAM database dump (T1003.002)
```
process = "reg.exe" and command_line regex "(?i).* .*save.*(hklm|HKEY_LOCAL_MACHINE)\\(sam|security|system).*"
```

## NTDS.dit dump (T1003.003)
For this dump, it is common to use "ntdsutil.exe"
```
(event_type = FILE_OPENED
and file_path  = "C:\Windows\NTDS\Ntds.dit") or (command_line contains "ntdsutil")
```
