```
title: Suspicious Public Folders in Use.
description: Suspicous BAT/CMD/DLL/EXE/ZIP/PS1/HTA/HTML files being Created, Modified, Deleted and Renamed in Public Users directory.
operating_system: Windows
hypotheses: threat intelligence
query: FileFullName RegExp "Users\\Public\\[^\\\{\}]+$" AND ( EventType IN ( "File Creation", "File Modification" , "File Deletion" , "File Rename" ) AND (FileFullName EndsWithCIS ".bat" OR FileFullName EndsWithCIS ".cmd" OR FileFullName EndsWithCIS ".dll" OR FileFullName EndsWithCIS ".exe" OR FileFullName EndsWithCIS ".zip" OR FileFullName EndsWithCIS ".ps1" OR FileFullName ContainsCIS ".ht" ))              
-------------------------------------------
title: ProxyShell
description: ProxyShell IOC's in inetpub directory.
operating_system: Windows
hypotheses: threat intelligence
query: TgtFilePath RegExp "inetpub\\wwwroot\\aspnet_client" AND TgtFileExtension = "aspx" AND EndpointMachineType = "server"
```
