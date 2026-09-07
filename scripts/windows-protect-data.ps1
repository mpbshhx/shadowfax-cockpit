param(
  [Parameter(Mandatory=$true)][string]$Path,
  [switch]$VerifyOnly
)
$ErrorActionPreference = 'Stop'

$resolved = [System.IO.Path]::GetFullPath($Path)
$currentSid = [System.Security.Principal.WindowsIdentity]::GetCurrent().User.Value
$allowedSids = @($currentSid, 'S-1-5-18', 'S-1-5-32-544') | Sort-Object -Unique

function New-ProtectedAcl([bool]$isDirectory) {
  $acl = if ($isDirectory) { [System.Security.AccessControl.DirectorySecurity]::new() } else { [System.Security.AccessControl.FileSecurity]::new() }
  $acl.SetAccessRuleProtection($true, $false)
  foreach ($sidText in $allowedSids) {
    $sid = [System.Security.Principal.SecurityIdentifier]::new($sidText)
    $inheritance = if ($isDirectory) {
      [System.Security.AccessControl.InheritanceFlags]'ContainerInherit, ObjectInherit'
    } else {
      [System.Security.AccessControl.InheritanceFlags]::None
    }
    $rule = [System.Security.AccessControl.FileSystemAccessRule]::new(
      $sid,
      [System.Security.AccessControl.FileSystemRights]::FullControl,
      $inheritance,
      [System.Security.AccessControl.PropagationFlags]::None,
      [System.Security.AccessControl.AccessControlType]::Allow
    )
    [void]$acl.AddAccessRule($rule)
  }
  return $acl
}

function Set-ExactAcl([string]$itemPath, [bool]$isDirectory) {
  $acl = New-ProtectedAcl $isDirectory
  if ($isDirectory) { [System.IO.Directory]::SetAccessControl($itemPath, $acl) }
  else { [System.IO.File]::SetAccessControl($itemPath, $acl) }
}

if (-not $VerifyOnly) {
  if (-not [System.IO.Directory]::Exists($resolved)) {
    [void][System.IO.Directory]::CreateDirectory($resolved)
  }
  Set-ExactAcl $resolved $true
  foreach ($item in Get-ChildItem -LiteralPath $resolved -Force -Recurse) {
    Set-ExactAcl $item.FullName $item.PSIsContainer
  }
}

$targets = @((Get-Item -LiteralPath $resolved -Force)) + @(Get-ChildItem -LiteralPath $resolved -Force -Recurse)
$failures = @()
foreach ($item in $targets) {
  $acl = Get-Acl -LiteralPath $item.FullName
  $actual = @($acl.Access | ForEach-Object { $_.IdentityReference.Translate([System.Security.Principal.SecurityIdentifier]).Value } | Sort-Object -Unique)
  $wrongPrincipal = @($actual | Where-Object { $_ -notin $allowedSids })
  $missingPrincipal = @($allowedSids | Where-Object { $_ -notin $actual })
  $wrongRule = @($acl.Access | Where-Object {
    $_.AccessControlType -ne [System.Security.AccessControl.AccessControlType]::Allow -or
    ($_.FileSystemRights -band [System.Security.AccessControl.FileSystemRights]::FullControl) -ne [System.Security.AccessControl.FileSystemRights]::FullControl
  })
  if (-not $acl.AreAccessRulesProtected -or $wrongPrincipal.Count -or $missingPrincipal.Count -or $wrongRule.Count) {
    $failures += [pscustomobject]@{
      path = $item.FullName
      protected = $acl.AreAccessRulesProtected
      unexpectedSids = @($wrongPrincipal)
      missingSids = @($missingPrincipal)
      wrongRuleCount = $wrongRule.Count
    }
  }
}

$result = [pscustomobject]@{
  path = $resolved
  serviceSid = $currentSid
  allowedSids = @($allowedSids)
  checked = $targets.Count
  protected = ($failures.Count -eq 0)
  failures = @($failures)
}
$result | ConvertTo-Json -Depth 6 -Compress
if ($failures.Count) { exit 73 }
