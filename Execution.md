# Execution queries

## PowerShell used for downloading scripts or malware (T1059.001)
```
process = "powershell.exe" and command_line in contains ("DownloadFile", "Invoke-WebRequest", "DownloadString", "iwr")
```

## LNK files executed manually by the user (T1204.001)
It is necessary to exclude the LNKs from the shells (i.e. "Command Prompt.lnk") and other false positive depending on the infrastructure.

```
event_type = FILE_OPENED and parent_process = "explorer.exe" and extension = "lnk"
| join (event_type = PROCESS and process in ("cmd.exe", "powershell.exe", "wscript.exe", "mshta.exe")) by endpoint_id, process_id
| where time_difference (t1, t2) < 5 seg
```
