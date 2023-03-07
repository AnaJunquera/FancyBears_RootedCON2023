# Discovery queries

## Using forfiles for locating PDF, Excel or Word files (T1083)
```
process = "forfiles.exe" and command_line regex ".*\.(xls|xlsx|doc|docx|pdf|ppt|pptx).*"
```

## Reading files from sensitive folders (T1083, T1518) - SkinnyBoy stealer
```
event_type = FILE_OPENED
and parent_process is not signed
and file_path REGEX "^(C:\\Users\\.*\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Administrative Tools\\|C:\\Users\\.*\\AppData\\Roaming\\|C:\\Users\\.*\\AppData\\Roaming\\Microsoft\\Windows\\Templates\\|C:\\Users\\.*\\AppData\\Local\\Programs\\|C:\\Program Files( \(x86\))?\\)([a-zA-Z0-9\-\._]+)\\.*"
| set folder = regextract(file_path,"^(C:\\Users\\.*\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Administrative Tools\\[a-zA-Z0-9\-\._]+\\|C:\\Users\\.*\\AppData\\Roaming\\[a-zA-Z0-9\-\._]+\\|C:\\Users\\.*\\AppData\\Roaming\\Microsoft\\Windows\\Templates\\[a-zA-Z0-9\-\._]+\\|C:\\Users\\.*\\AppData\\Local\\Programs\\[a-zA-Z0-9\-\._]+\\|C:\\Program Files\\[a-zA-Z0-9\-\._]+|C:\\Program Files \(x86\)\\[a-zA-Z0-9\-\._]+)\\.*"),1)
| counter = count_distinct(folder) by host, parent_process_pid
| where counter > 5
```
