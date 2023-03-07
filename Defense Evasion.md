# Defense Evasion queries

## Certutil used for decoding Base64 payload stored in .txt file (T1140)
```
process = "certutil.exe" and command_line regex ".*\-decode.*\.txt.*"
```

## Event registry entries removed by using wevtutil (T1070.001)
```
command_line regex "(?i).*wevtutil\s+cl\s+(system|security|application).*"
```

## Malicious DLLs run with rundll32 (T1218.011)
It looks for DLLs stored directly in "C:\Windows" or "C:\Users\User\AppData\" and executed with rundll32. Some malware has been found to store malicious DLLs in those directories.
```
command_line regex ".*rundll32\.exe.*(C:\\Windows|C:\\Users\\[\w\s\.]+\\AppData|[A-Z]:)\\[\w\s\.]+\.dll.*"
```
