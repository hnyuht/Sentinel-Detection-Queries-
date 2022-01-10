# Sentinel-Detection-Queries

### Suspicious Public Folders in Use.
Description: Suspicous BAT/CMD/DLL/EXE/ZIP/PS1/HTA/HTML files being Modified, Created, Deleted and Renamed.
```FileFullName RegExp "Users\\Public\\[^\\\{\}]+$" AND ( EventType IN ( "File Modification" , "File Creation" , "File Deletion" , "File Rename" ) AND (FileFullName EndsWithCIS ".bat" OR FileFullName EndsWithCIS ".cmd" OR FileFullName EndsWithCIS ".dll" OR FileFullName EndsWithCIS ".exe" OR FileFullName EndsWithCIS ".zip" OR FileFullName EndsWithCIS ".ps1" OR FileFullName ContainsCIS ".ht" ))
```
