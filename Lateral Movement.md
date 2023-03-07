# Lateral Movement queries

## Send malicious files through SMB (T1570)
```
event_type = NETWORK_INBOUND and local_port in (445,139)
| join (event_type = FILE_CREATED and file_extension in ("exe", "dll", "bat", "vbs") by endpoint_id, process_id
| where time_difference (t1, t2) < 5min
```

## Using net for mapping network drives (T1547.001)
```
process in ("net.exe", "net1.exe") and command_line regex ".*net.*use.*\\\\.*"
```
