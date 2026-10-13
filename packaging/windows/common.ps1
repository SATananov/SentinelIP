Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Get-SensorPaths {
    $programFiles = [Environment]::GetFolderPath('ProgramFiles')
    $programData = [Environment]::GetFolderPath('CommonApplicationData')
    if (-not $programFiles -or -not $programData) { throw 'Windows known folders are unavailable.' }
    return @{
        App = (Join-Path $programFiles 'SentinelIP\Sensor')
        Data = (Join-Path $programData 'SentinelIP\Sensor')
    }
}

function Assert-NoReparse([string]$Path) {
    if (-not [IO.Path]::IsPathRooted($Path) -or $Path.StartsWith('\\') -or $Path.Substring(2).Contains(':')) {
        throw 'Only absolute local paths without alternate streams are supported.'
    }
    $item = $Path
    while ($item) {
        if (Test-Path -LiteralPath $item) {
            if ((Get-Item -LiteralPath $item -Force).Attributes -band [IO.FileAttributes]::ReparsePoint) {
                throw 'Reparse points are not permitted in installation paths.'
            }
        }
        $parent = Split-Path -Parent $item
        if ($parent -eq $item) { break }
        $item = $parent
    }
}

function Assert-TrustedExecutable([string]$Path, [string]$Name) {
    Assert-NoReparse $Path
    if ([IO.Path]::GetFileName($Path) -ine $Name -or -not (Test-Path -LiteralPath $Path -PathType Leaf)) {
        throw 'Required executable is missing or has an unexpected filename.'
    }
    $trusted = @('S-1-5-18', 'S-1-5-32-544', 'S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464')
    $item = $Path
    while ((Split-Path -Parent $item)) {
        $acl = Get-Acl -LiteralPath $item
        if ($trusted -notcontains $acl.GetOwner([Security.Principal.SecurityIdentifier]).Value) {
            throw 'Executable owner is not trusted.'
        }
        foreach ($rule in $acl.GetAccessRules($true, $true, [Security.Principal.SecurityIdentifier])) {
            if ($rule.AccessControlType -eq 'Allow' -and -not ($rule.PropagationFlags -band [Security.AccessControl.PropagationFlags]::InheritOnly)) {
                if (($rule.FileSystemRights.value__ -band 0x500D0156) -ne 0 -and $trusted -notcontains $rule.IdentityReference.Value) {
                    throw 'Executable directory or file is writable by an untrusted identity.'
                }
            }
        }
        $item = Split-Path -Parent $item
    }
}

function Set-SensorDirectoryAcl([string]$Path, [bool]$Secret) {
    Assert-NoReparse $Path
    New-Item -ItemType Directory -Path $Path -Force | Out-Null
    $acl = [Security.AccessControl.DirectorySecurity]::new()
    $acl.SetAccessRuleProtection($true, $false)
    $admin = [Security.Principal.SecurityIdentifier]::new('S-1-5-32-544')
    $acl.SetOwner($admin)
    foreach ($sid in @('S-1-5-18', 'S-1-5-32-544')) {
        $acl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new(
            [Security.Principal.SecurityIdentifier]::new($sid), 'FullControl', 'ContainerInherit,ObjectInherit', 'None', 'Allow'))
    }
    $rights = if ($Secret) { 'Modify' } else { 'ReadAndExecute' }
    $acl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new(
        [Security.Principal.SecurityIdentifier]::new('S-1-5-19'), $rights, 'ContainerInherit,ObjectInherit', 'None', 'Allow'))
    Set-Acl -LiteralPath $Path -AclObject $acl
}

function Assert-SensorTree([string]$Path) {
    Assert-NoReparse $Path
    if (Test-Path -LiteralPath $Path) {
        foreach ($item in Get-ChildItem -LiteralPath $Path -Force) {
            Assert-NoReparse $item.FullName
            if ($item.PSIsContainer) { Assert-SensorTree $item.FullName }
        }
    }
}

function Set-SensorFileAcl([string]$Path, [bool]$Secret) {
    Assert-NoReparse $Path
    $acl = [Security.AccessControl.FileSecurity]::new()
    $acl.SetAccessRuleProtection($true, $false)
    $acl.SetOwner([Security.Principal.SecurityIdentifier]::new('S-1-5-32-544'))
    foreach ($sid in @('S-1-5-18', 'S-1-5-32-544')) {
        $acl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new(
            [Security.Principal.SecurityIdentifier]::new($sid), 'FullControl', 'Allow'))
    }
    $rights = if ($Secret) { 'Modify' } else { 'ReadAndExecute' }
    $acl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new(
        [Security.Principal.SecurityIdentifier]::new('S-1-5-19'), $rights, 'Allow'))
    Set-Acl -LiteralPath $Path -AclObject $acl
}
