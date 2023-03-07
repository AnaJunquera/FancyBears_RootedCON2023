# Collection queries

## Making screenshots in victim machine (T1113)
```
event_type = FILE_CREATED and parent_process in ("powershell.exe", "nircmd.exe") and file_path regex  "\.(png|jpeg|jpg|svg|bmp)$"
```

## Storing collected information in temporal file in %ALLUSERSPROFILE% (T1074.001)
```
event_type = FILE_CREATED and file_path regex "^C:\\ProgramData\\[\w\s\_]+\.tmp$"
```
