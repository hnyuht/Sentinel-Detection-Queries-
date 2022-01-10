# Sentinel-Detection-Queries

### Suspicious Public Folders in Use.
Description: Suspicous BAT/CMD/DLL/EXE/ZIP/PS1/HTA/HTML files being Created, Modified, Deleted and Renamed in Public Users directory.
```
FileFullName RegExp "Users\\Public\\[^\\\{\}]+$" AND ( EventType IN ( "File Creation", "File Modification" , "File Deletion" , "File Rename" ) AND (FileFullName EndsWithCIS ".bat" OR FileFullName EndsWithCIS ".cmd" OR FileFullName EndsWithCIS ".dll" OR FileFullName EndsWithCIS ".exe" OR FileFullName EndsWithCIS ".zip" OR FileFullName EndsWithCIS ".ps1" OR FileFullName ContainsCIS ".ht" ))
```

### Qakbot detection in C, ProgramData, and AppData.
Description: These OCX files are renamed DLLs and are executed using the regsvr32.exe command to install the malware payload.
C:\Users\<username>\AppData\Microsoft\[Random]\
C:\ProgramData\Microsoft\[Random]\
C:\[a-z]{5}\
Examples:
C:\Datop\[Random].ocx 
C:\Jambo\[Random].ocx 
C:\Babmo\[Random].ocx 
C:\Dabmo\[Random].ocx 
C:\Badna\[Random].ocx
Note: This will detect all the above because the regex is looking for any 5 characters in the folder name.

Regex is for any five characters.
Credit to Drew Hjelm (Tetra Defense) and Max_Malyutin(Twitter Handle)

```
SrcProcParentName = "regsvr32.exe" AND (TgtFilePath RegExp "ProgramData\\Microsoft" OR TgtFilePath RegExp "AppData\\Roaming\\Microsoft" OR TgtFilePath RegExp "C:\\[a-z]{5}\\[^\\\{\}]+$") AND TgtFileExtension In ("dll", "ocx", "good")
```

