# Sentinel-Detection-Queries

### Suspicious Public Folders in Use.
Description: Suspicous BAT/CMD/DLL/EXE/ZIP/PS1/HTA/HTML files being Created, Modified, Deleted and Renamed in Public Users directory.
```
(FileFullName RegExp "Users\\Public\\[^\\\{\}]+$" AND ( EventType IN ( "File Creation", "File Modification" , "File Deletion" , "File Rename" ) AND (FileFullName EndsWithCIS ".bat" OR FileFullName EndsWithCIS ".cmd" OR FileFullName EndsWithCIS ".dll" OR FileFullName EndsWithCIS ".exe" OR FileFullName EndsWithCIS ".zip" OR FileFullName EndsWithCIS ".ps1" OR FileFullName ContainsCIS ".ht" )))
```

### Qakbot detection in C, ProgramData, and AppData.
Description: These OCX files are renamed DLLs and are executed using the regsvr32.exe command to install the malware payload.
C:\Users\<username>\AppData\Microsoft\[Random]\
C:\ProgramData\Microsoft\[Random]\
C:\[a-z]{5}\
This regex will detect any of the below folder names and if change to new ones.
```
SrcProcParentName = "regsvr32.exe" AND (TgtFilePath RegExp "ProgramData\\Microsoft" OR TgtFilePath RegExp "AppData\\Roaming\\Microsoft" OR TgtFilePath RegExp "C:\\[a-z]{5}\\[^\\\{\}]+$") AND TgtFileExtension In ("dll", "ocx", "good")
```
