# Exfiltration queries

## Dividing files in fragments smaller than 1MB (T1030)
```
event_type = FILE_CREATED and file_path regex "^[A-Z]:(\\Windows\\|\\Users\\[\w\s\.]+\\AppData\\|\\ProgramData\\|\\)[\w\s\.\_]+\.\w+" and file_size < 1MB
| count as created_files by parent_pid, endpoint_id
| where created files > 5
```

## Data exfiltration using Google Drive (volumetry) (T1567.002)
```
event_type = NETWORK_CONNECTION and URL contains any ("drive.google.com", "www.googleapis.com")
| sum (bytes_uploaded) by date
```
