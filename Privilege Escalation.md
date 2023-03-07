# Privilege Escalation queries

## UAC bypass using common Windows LOLBins (T1548.002)
```
event_type = PROCESS_START 
and parent_process in ("WSReset.exe", "slui.exe", "fodhelper.exe", "eventvwr.exe", "cmstp.exe", "sethc.exe", "werfault.exe") 
and child_process_integrity_level in ("High", "System")
```
