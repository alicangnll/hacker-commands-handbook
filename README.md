# Windows / Linux Komutlar Arşivi
Merhabalar,
<br><p>
Bu repository içerisinde Windows ve Linux tarafında anlamsız ve nedensiz şekilde kullanıldığında muhtemelen size zarar vereceğini düşünebileceğiniz komutları derledim.
Siz de elinizden geldiğince eklemeler yapabilirsiniz</p>

<b>Systeminfo</b>
<ul>
<li>hostname</li>
<li>whoami /all</li>
<li>net use</li>
<li>route print</li>
<li>ipconfig /all</li>
<li>arp -a</li>
</ul>

<b>CMD, Netsh and Regedit</b>
<ul>
<li>cmdkey /list</li>
<li>whoami /all</li>
<li>systeminfo</li>
<li>netsh firewall set service type = remotedesktop mode = enable /all</li>
<li>REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server" /v fDenyTSConnections /t REG_DWORD /d 0 /f</li>
</ul>

<b>Net Accounts</b>
<ul>
<li>net user</li>
<li>net accounts</li>
<li>net share</li>
<li>net statistics workstation</li>
<li>net statistics server</li>
<li>net config workstation</li>
<li>net config server</li>
<li>net localgroup administrators</li>
</ul>

<b>WMI</b>
<ul>
<li>wmic qfe list full /format:list</li>
<li>start /wait /min "msinfo32 /report c:\windows\temp\msinforeport.txt"</li>
<li>wmic product get name</li>
</ul>

<b>Scheduled Tasks</b>
<ul>
<li>schtasks /Query</li>
<li>schtasks /create /tn Demo /tr notepad.exe /sc ONIDLE /I 1 /f</li>
<li>schtasks | findstr Demo</li>
<li>schtasks /End /Tn Demo</li>
<li>schtasks /Delete /Tn Demo /f</li>
<li>REM schtasks /create /tn Demo1 /tr notepad.exe /sc once /st time /T /sd date /T /ru System</li>
</ul>
