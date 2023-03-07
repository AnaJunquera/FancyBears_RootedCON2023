# Persistence queries

## Logon scripts used for persistence (T1037.001)
```
event_type = REGISTRY_SET_VALUE and registry_key contains "\Environment\UserInitMprLogonScript"
```

## Use of Startup folder for persistence (T1547.001)
```
event_type = FILE_CREATED 
and file_path regex "^(C:\\Users\\.*\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\|C:\\ProgramData\\Microsoft\\Windows\\Start Menu\\Programs\\StartUp).*" 
and file_name != "desktop.ini"
```

## Use of "Office Test" registry key for persistence (T1137.002)
```
event_type in (REGISTRY_CREATE_KEY, REGISTRY_SET_VALUE) and registry_key contains "\Software\Microsoft\Office test\Special\Perf" 
```
