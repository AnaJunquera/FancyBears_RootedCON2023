# Command and Control queries

## Using Google Drive as C2 server (T1102.002)
```
event_type = NETWORK_CONNECTION
and URL contains "www.googleapis.com/upload/drive"
and parent_process not in ("msedge.exe", "chrome.exe", "firefox.exe", "opera.exe", "iexplore.exe", "GoogleUpdate.exe", "OUTLOOK.EXE")
```
