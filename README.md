# Fancy Bear related queries
These queries are shown here in pseudocode, before using them in any EDR you should translate them to the correct language.

## Execution queries

### PowerShell used for downloading scripts or malware (T1059.001)
```
process = "powershell.exe" and command_line in contains ("DownloadFile", "Invoke-WebRequest", "DownloadString", "iwr")
```

### LNK files executed manually by the user (T1204.001)
It is necessary to exclude the LNKs from the shells (i.e. "Command Prompt.lnk") and other false positive depending on the infrastructure.

```
event_type = FILE_OPENED and parent_process = "explorer.exe" and extension = "lnk"
| join (event_type = PROCESS and process in ("cmd.exe", "powershell.exe", "wscript.exe", "mshta.exe")) by endpoint_id, process_id
| where time_difference (t1, t2) < 5 seg
```

## Defense Evasion queries

### Certutil used for decoding Base64 payload stored in .txt file (T1140)
```
process = "certutil.exe" and command_line regex "(?i).*\-decode.*\.txt.*"
```

### Event registry entries removed by using wevtutil (T1070.001)
```
command_line regex "(?i).*wevtutil\s+cl\s+(system|security|application).*"
```

### Malicious DLLs run with rundll32 (T1218.011)
It looks for DLLs stored directly in "C:\Windows" or "C:\Users\User\AppData\" and executed with rundll32. Some malware has been found to store malicious DLLs in those directories.
```
command_line regex "(?i).*rundll32\.exe.*(C:\\Windows|C:\\Users\\[\w\s\.]+\\AppData|[A-Z]:)\\[\w\s\.]+\.dll.*"
```
## Credential Access queries

### LSASS dump with rundll32 (T1003.001)
```
process = "rundll32.exe" and command_line regex "(?i).*comsvcs\.dll, MiniDump.*"
```

### SAM database dump (T1003.002)
```
process = "reg.exe" and command_line regex "(?i).* .*save.*(hklm|HKEY_LOCAL_MACHINE)\\(sam|security|system).*"
```

### NTDS.dit dump (T1003.003)
For this dump, it is common to use "ntdsutil.exe"
```
(event_type = FILE_OPENED
and file_path  = "C:\Windows\NTDS\Ntds.dit") or (command_line contains "ntdsutil")
```

## Persistence queries

### Logon scripts used for persistence (T1037.001)
```
event_type = REGISTRY_SET_VALUE and registry_key contains "\Environment\UserInitMprLogonScript"
```

### Use of Startup folder for persistence (T1547.001)
```
event_type = FILE_CREATED 
and file_path regex "(?i)^(C:\\Users\\.*\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\|C:\\ProgramData\\Microsoft\\Windows\\Start Menu\\Programs\\StartUp).*" 
and file_name != "desktop.ini"
```

### Use of "Office Test" registry key for persistence (T1137.002)
```
event_type in (REGISTRY_CREATE_KEY, REGISTRY_SET_VALUE) and registry_key contains "\Software\Microsoft\Office test\Special\Perf" 
```

## Privilege Escalation queries

### UAC bypass using common Windows LOLBins (T1548.002)
```
event_type = PROCESS_START 
and parent_process in ("WSReset.exe", "slui.exe", "fodhelper.exe", "eventvwr.exe", "cmstp.exe", "sethc.exe") 
and child_process_integrity_level in ("High", "System")
```

## Lateral Movement queries

### Send malicious files through SMB (T1570)
```
event_type = NETWORK_INBOUND and local_port in (445,139)
| join (event_type = FILE_CREATED and file_extension in ("exe", "dll", "bat", "vbs") by endpoint_id, process_id
| where time_difference (t1, t2) < 5seg
```

### Using net for mapping network drives (T1547.001)
```
process in ("net.exe", "net1.exe") and command_line regex "(?i).*net.*use.*[A-Z]:.*\\\\.*"
```

## Command and Control queries

### Using Google Drive as C2 server (T1102.002)
```
event_type = NETWORK_CONNECTION
and URL contains "www.googleapis.com/upload/drive"
and parent_process not in ("msedge.exe", "chrome.exe", "firefox.exe", "opera.exe", "iexplore.exe", "GoogleUpdate.exe", "OUTLOOK.EXE")
```

## Discovery queries

### Using forfiles for locating PDF, Excel or Word files (T1083)
```
process = "forfiles.exe" and command_line regex "(?i).*\.(xls|xlsx|doc|docx|pdf|ppt|pptx).*"
```

### Reading files from sensitive folders (T1083, T1518) - SkinnyBoy stealer
```
event_type = FILE_OPENED
and parent_process is not signed
and file_path REGEX "(?i)^(C:\\Users\\.*\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Administrative Tools\\|C:\\Users\\.*\\AppData\\Roaming\\|C:\\Users\\.*\\AppData\\Roaming\\Microsoft\\Windows\\Templates\\|C:\\Users\\.*\\AppData\\Local\\Programs\\|C:\\Program Files( \(x86\))?\\)([a-zA-Z0-9\-\._]+)\\.*"
| set folder = regextract(file_path,"(?i)^(C:\\Users\\.*\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Administrative Tools\\[a-zA-Z0-9\-\._]+\\|C:\\Users\\.*\\AppData\\Roaming\\[a-zA-Z0-9\-\._]+\\|C:\\Users\\.*\\AppData\\Roaming\\Microsoft\\Windows\\Templates\\[a-zA-Z0-9\-\._]+\\|C:\\Users\\.*\\AppData\\Local\\Programs\\[a-zA-Z0-9\-\._]+\\|C:\\Program Files\\[a-zA-Z0-9\-\._]+|C:\\Program Files \(x86\)\\[a-zA-Z0-9\-\._]+)\\.*"),1)
| counter = count_distinct(folder) by host, parent_process_pid
| where counter > 5
```

## Collection queries

### Making screenshots in victim machine (T1113)
```
event_type = FILE_CREATED and parent_process in ("powershell.exe", "nircmd.exe") and file_path regex  "\.(png|jpeg|jpg|svg|bmp)$"
```

### Storing collected information in temporal file in %ALLUSERSPROFILE% (T1074.001)
```
event_type = FILE_CREATED and file_path regex "(?i)^C:\\ProgramData\\[\w\s\_]+\.tmp$"
```

## Exfiltration queries

### Dividing files in fragments smaller than 1MB (T1030)
```
event_type = FILE_CREATED and file_path regex "(?i)^[A-Z]:(\\Windows\\|\\Users\\[\w\s\.]+\\AppData\\|\\ProgramData\\|\\)[\w\s\.\_]+\.\w+" and file_size < 1MB
| count as created_files by parent_pid, endpoint_id
| where created files > 5
```

### Data exfiltration using Google Drive (volumetry) (T1567.002)
This query will show a graph with the number of bytes uploaded to Google Drive each day.
```
event_type = NETWORK_CONNECTION and URL contains any ("drive.google.com", "www.googleapis.com")
| sum (bytes_uploaded) by date
```


