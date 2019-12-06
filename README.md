# TokenManage

A project used primarily as aid in learning Windows developement for future purposes. 
The project will contain one class library and one command line client. When the 
project is mature enough, i will start adding the compiled versions targeting several 
.NET frameworks to simplify the usage in real life situations.

Currently, both the library and the CLI application are compiled for .NET Framework 4.0, .NET Framework 4.5 and .NET Core.
This list of compilation targets is likely to expand in the future, as well as providing compiled binaries.

## TokenManage CLI

TODO: 

## TokenManage class library and PowerShell

Some examples of how i envision the class library can be used with powershell in the future.
This may not be possible, we will see. I need to experiment with how process and thread tokens
are used.

Currently, this works:

```powershell
PS C:\Users\user> powershell -sta
Windows PowerShell
Copyright (C) Microsoft Corporation. All rights reserved.

Try the new cross-platform PowerShell https://aka.ms/pscore6

PS C:\Users\user> add-type -path C:\Users\user\source\repos\TokenManage\TokenManage\bin\Debug\netstandard2.0\TokenManage.dll

PS C:\Users\user> whoami /priv

PRIVILEGES INFORMATION
----------------------

Privilege Name                Description                            State
============================= ====================================== ========
SeShutdownPrivilege           Avsluta datorn                         Disabled
SeChangeNotifyPrivilege       Kringgå bläddringskontroll             Enabled
SeUndockPrivilege             Ta bort datorn från dockningsstationen Disabled
SeIncreaseWorkingSetPrivilege Öka allokerat minne för en process     Disabled
SeTimeZonePrivilege           Ändra tidszon                          Disabled

PS C:\Users\user> [TokenManage.PS]::EnablePrivilege("SeShutdownPrivilege")
True

PS C:\Users\user> whoami /priv

PRIVILEGES INFORMATION
----------------------

Privilege Name                Description                            State
============================= ====================================== ========
SeShutdownPrivilege           Avsluta datorn                         Enabled
SeChangeNotifyPrivilege       Kringgå bläddringskontroll             Enabled
SeUndockPrivilege             Ta bort datorn från dockningsstationen Disabled
SeIncreaseWorkingSetPrivilege Öka allokerat minne för en process     Disabled
SeTimeZonePrivilege           Ändra tidszon                          Disabled
```

```
powershell.exe -sta # Ensure single thread is used
[System.Reflection.Assembly]::Load([IO.File]::ReadAllBytes("path-to-dll-or-download-from-internet"))
[TokenManage.PS]::ListTokens()
[TokenManage.PS]::EnablePrivilege("SeDebugPrivilege")
[TokenManage.PS]::ImpersonateByPID(1064)
[TokenManage.PS]::GetSystem()
[TokenManage.PS]::Rev2self()
```
