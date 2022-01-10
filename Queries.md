I decided to start sharing my detection and threat hunting queries that I made in SentinelOne. First, I want to thank Tetra Defense for allowing me to research, develop, hunt, and build here. I also wish to thank Brad, Dan, Drew, Joe, Billy, and credit other security resources for helping me create these queries. All other credit will be found under each query.

# Sentinel-Detection-Queries

### Suspicious Public Folders in Use.
Description: Suspicous BAT/CMD/DLL/EXE/ZIP/PS1/HTA/HTML files being Created, Modified, Deleted and Renamed in Public Users directory.
```
FileFullName RegExp "Users\\Public\\[^\\\{\}]+$" AND ( EventType IN ( "File Creation", "File Modification" , "File Deletion" , "File Rename" ) AND (FileFullName EndsWithCIS ".bat" OR FileFullName EndsWithCIS ".cmd" OR FileFullName EndsWithCIS ".dll" OR FileFullName EndsWithCIS ".exe" OR FileFullName EndsWithCIS ".zip" OR FileFullName EndsWithCIS ".ps1" OR FileFullName ContainsCIS ".ht" ))
```

### Qakbot detection in the following Directories\Folders C:, ProgramData, and AppData.
Description: These OCX files are renamed DLLs and are executed using the regsvr32.exe command to install the malware payload.
C:\Users\<username>\AppData\Microsoft\[Random]\
C:\ProgramData\Microsoft\[Random]\
C:\[a-z]{5}\
Examples:                                                                                                                                                                   C:\Datop\[Random].ocx
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


### Suspicious ISO sent as Outlook Attachments.
Description: Email gateway scanners don’t scan ISO file attachments properly and can contain malware.
Windows (Windows 8 and Windows 10) feature a native ISO mounting tool. Opening an ISO file is now as simple as double-clicking the file. This increases the chances of the target opening the file and infecting their system. This query was created if you needed to find the suspicious ISO attachment.

```
TgtFilePath RegExp "AppData\\Local\\Microsoft\\Windows\\INetCache\\Content.Outlook" AND TgtFileExtension In ("iso", "img")
```
