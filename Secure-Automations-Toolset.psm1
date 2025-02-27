#requires -psedition Core

Set-StrictMode -Version Latest

function _AuthenticateIntoBitwardenPasswordManagerCLI {
  _PrerequisiteConditions

  # Capture status of Bitwarden Password Manager CLI. Only values of interest for our purposes are 'locked' and 'unauthenticated'
  $RedirectedErrors = $(
    ${Authentication Status of the Bitwarden CLI} = bw.exe status | ConvertFrom-Json | Select-Object -ExpandProperty 'status'
  ) 2>&1

  # Authenticate into Bitwarden Password Manager CLI
  switch (${Authentication Status of the Bitwarden CLI}) {
    'unauthenticated' {
      $emailaddr = Read-Host -Prompt "Username of Bitwarden account"
      [string[]]$(bw.exe login $emailaddr) | ForEach-Object {
        if (
          $_ -match '^>\ \$env:BW_SESSION="(?<BW_SESSION>.*)"$'
        ) {
          $env:BW_SESSION = $Matches['BW_SESSION']
        }
      }
      break
    }
    'locked' {
      [string[]]$(bw.exe unlock) | ForEach-Object {
        if (
          $_ -match '^>\ \$env:BW_SESSION="(?<BW_SESSION>.*)"$'
        ) {
          $env:BW_SESSION = $Matches['BW_SESSION']
        }
      }
      break
    }
    default {
      break
    }
  }
}
Set-Alias -Name Unlock-BwCli -Value _AuthenticateIntoBitwardenPasswordManagerCLI

function _CallISO8601TimeDateUTC {
  [string](Get-Date -Date $((Get-Date -AsUTC)) -Format "yyyy-MM-ddTHH:mm:ssZ")
}

function _GenerateCryptographicallySafePassword {
  param (
    [Parameter(Mandatory)]
    [ValidateRange(8,255)]
    [Alias('len')]
    [int32]
    $PasswordLength
  )
  
  $RandomObject = [System.Security.Cryptography.RandomNumberGenerator]::Create()

  $CharacterSet = -join ([char[]](0x30..0x39) + [char[]](0x41..0x5A) + [char[]](0x61..0x7A) + [char](0x21) + [char](0x40) + [char[]](0x23..0x26) + [char](0x5e) + [char](0x2a))

  $_Var_Name = 'string' 
  try {Clear-Variable -Name $_Var_Name -ErrorAction 'Stop'} catch {New-Variable -Name $_Var_Name -Value $null}  
  
  for ($i = 0; $i -lt $PasswordLength; $i++) {
    $bytes = New-Object byte[] 8
    $RandomObject.GetBytes($bytes)
    $string += $CharacterSet[[Int32](([BitConverter]::ToUInt32($bytes, 0)) % 69)]
  }
  return $string
  Remove-Variable -Name 'string'
}
Set-Alias -Name _genpwd -Value _GenerateCryptographicallySafePassword

function _PrerequisiteConditions {
  ## Save to variable the identity of all currently logged-on accounts
  ${query.exe session} = query.exe session

  ## Use named matches to capture username of account that owns the explorer.exe process
  for ($i = 0; $i -lt ${query.exe session}.Length; $i++) {
    if (${query.exe session}[$i] -match '^>console +(?<explorer_Owner>\S+)') {
      ${explorer Owner} = $Matches['explorer_Owner']
    }
  }

  ## Identify local SID of account that owns explorer.exe
  switch (Get-CimInstance -ClassName 'Win32_ComputerSystem' | Select-Object -ExpandProperty 'PartOfDomain') {
    $true {  
      $domain = Get-CimInstance -ClassName 'Win32_Process' -Filter "name = 'explorer.exe'" | Invoke-CimMethod -MethodName 'GetOwner' | Where-Object {$_.User -eq ${explorer Owner}} | Select-Object -ExpandProperty 'Domain' -First 1
      ${NTAccount of explorer.exe Owner} = New-Object System.Security.Principal.NTAccount("$domain\${explorer Owner}")
      ${Local SID of explorer.exe Owner} = ${NTAccount of explorer.exe Owner}.Translate([System.Security.Principal.SecurityIdentifier]) | Select-Object -ExpandProperty 'Value'  
    }
    $false {
      ${Local SID of explorer.exe Owner} = Get-LocalUser ${explorer Owner} | Select-Object -ExpandProperty 'sid' | Select-Object -ExpandProperty 'value'
    }
  }

  ## Capture username of account that owns this instance of pwsh.exe
  ${pwsh.exe Process ID} = (Get-CimInstance -ClassName Win32_Process -Filter "name = 'pwsh.exe'").Where({$_.ProcessId -eq $PID}) | Select-Object -First 1
  New-Variable -Name 'pwsh Owner' -Value (Invoke-CimMethod -InputObject ${pwsh.exe Process ID} -MethodName 'GetOwner' | Select-Object -ExpandProperty 'User')

  ## Confirm presence of x64 version of "Microsoft Visual C++ 2015 - 2022 Redistributable"  
  while (-not ((Get-CimInstance -ClassName 'Win32_Product').Where({$_.Name -match 'Microsoft Visual C\+\+ 2022 X(64|86) Minimum Runtime'}))) {
    Write-Host -ForegroundColor 'Magenta' -Object "`r`n`tBitwarden Secrets Manager CLI (bws.exe) requires the VCRUNTIME140.dll.`r`n`r`n`tPress Enter to allow PowerShell to download & install the Microsoft Visual C++ 2022 X64 Minimum Runtime`r`n"
    pause

    # Initialize new variable to stand as a session variable and ensure value is $null. 
    $_Var_Name = 'TempSessionVar'
    try {Clear-Variable -Name $_Var_Name -ErrorAction 'Stop'} catch {New-Variable -Name $_Var_Name -Value $null}

    # Download the C++ redistributable
    while (-not $TempSessionVar) {
      # Invoke-WebRequest bombs out the 1st time because of no DNS resource record on the DNS server.
      $RedirectedError = $(
        Invoke-WebRequest -Uri "https://aka.ms/vs/17/release/vc_redist.x64.exe" -SessionVariable 'TempSessionVar' -OutFile "$env:SystemDrive\Users\${explorer Owner}\Downloads\vc_redist.x64.exe"
      ) 2>&1
    }

    ## Silent installation of the C++ redistributable. 
    ## Credit for Invoke-ElevatedCommand goes to PowerShell CookBook (4th Ed.) by Lee Holmes. Visit https://www.leeholmes.com/tags/guide/ for more. 
    Invoke-ElevatedCommand -ScriptBlock {
      ## Save to variable the identity of all currently logged-on accounts
      ${query.exe session} = query.exe session

      ## Use named matches to capture username of account that owns the explorer.exe process
      for ($i = 0; $i -lt ${query.exe session}.Length; $i++) {
        if (${query.exe session}[$i] -match '^>console +(?<explorer_Owner>\S+)') {
          ${explorer Owner} = $Matches['explorer_Owner']
        }
      }

      ## Silently install the C++ redistributable. 
      Start-Process -FilePath "$env:SystemDrive\Users\${explorer Owner}\Downloads\vc_redist.x64.exe" -ArgumentList @("/quiet")
    }
  }


  ## Load each of the semicolon-separated directory paths that comprise the $env:Path variable into an array element. 
  ## If final element is the empty string of length-0 then eliminate that element from the array. 

  ## IMPORTANT: We cannot assume that the Owner of explorer.exe is also the Owner of pwsh.exe. For this reason, TWO 'pathFolders' variables are defined. 
  ${pathFolders-pwsh Owner} = $env:Path -split ';'
  if (${pathFolders-pwsh Owner}[${pathFolders-pwsh Owner}.length - 1] -notmatch [regex]::Escape("\")) {
    ${pathFolders-pwsh Owner} = ${pathFolders-pwsh Owner}[0..(${pathFolders-pwsh Owner}.Length - 2)]
  }

  ${System-scope Env} = "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Environment"
  ${System-scope %path%} = (Get-ItemPropertyValue -Path ${System-scope Env} -Name 'Path') -split ';'

  ${User-scope Env (explorer Owner)} = "HKU:\${Local SID of explorer.exe Owner}\Environment"
  ${User-scope %path% (explorer Owner)} = (Get-ItemPropertyValue -Path ${User-scope Env (explorer Owner)} -Name 'Path') -split ';'

  ${pathFolders-explorer Owner} = ${System-scope %path%} + ${User-scope %path% (explorer Owner)}
  if (${pathFolders-explorer Owner}[${pathFolders-explorer Owner}.length - 1] -notmatch [regex]::Escape("\")) {
    ${pathFolders-explorer Owner} = ${pathFolders-explorer Owner}[0..(${pathFolders-explorer Owner}.Length - 2)]
  }


  # Establish dependencies for the account that owns the pwsh.exe process: 

  ## Confirm presence of Bitwarden Password Manager CLI (bw.exe) in one or more of the $env:Path directories. 
  while (-not ((Test-Path -Path (Join-Path -Path ${pathFolders-pwsh Owner} -ChildPath "bw.exe") -ErrorAction 'SilentlyContinue') -contains $true)) {
    # Initialize new variable to stand as a session variable and ensure value is $null. 
    $_Var_Name = 'TempSessionVar'
    try {Clear-Variable -Name $_Var_Name -ErrorAction 'Stop'} catch {New-Variable -Name $_Var_Name -Value $null}

    # Download the Bitwarden Password Manager CLI
    while (-not $TempSessionVar) {
      # Invoke-WebRequest bombs out the 1st time because of no DNS resource record on the DNS server.
      $RedirectedError = $(
        Invoke-WebRequest -Uri "https://vault.bitwarden.com/download/?app=cli&platform=windows" -SessionVariable 'TempSessionVar' -OutFile "$env:SystemDrive\Users\${pwsh Owner}\Downloads\bw-windows.zip"
      ) 2>&1
    }

    # extract bw.exe to the first PATH folder in the user's profile
    Expand-Archive -Path "$env:SystemDrive\Users\${pwsh Owner}\Downloads\bw-windows.zip" -Destination ${pathFolders-pwsh Owner}.Where({$_ -match [regex]::Escape("$env:SystemDrive\Users\${pwsh Owner}")})[0]
  }

  ## Confirm presence of the jq JSON processor. Necessary for writing into the Bitwarden Password Manager via the Bitwarden CLI. 
  while (-not ((Test-Path -Path (Join-Path -Path ${pathFolders-pwsh Owner} -ChildPath "jq-windows-amd64.exe") -ErrorAction 'SilentlyContinue') -contains $true)) {
    # Initialize new variable to stand as a session variable and ensure value is $null. 
    $_Var_Name = 'TempSessionVar'
    try {Clear-Variable -Name $_Var_Name -ErrorAction 'Stop'} catch {New-Variable -Name $_Var_Name -Value $null}

    # Download the jq JSON processor
    while (-not $TempSessionVar) {
      # Invoke-WebRequest bombs out the 1st time because of no DNS resource record on the DNS server.
      $RedirectedError = $(
        Invoke-WebRequest -Uri "https://github.com/jqlang/jq/releases/download/jq-1.7.1/jq-windows-amd64.exe" -SessionVariable 'TempSessionVar' -OutFile "$env:SystemDrive\Users\${pwsh Owner}\Downloads\jq-windows-amd64.exe"
      ) 2>&1
    }

    # Copy jq to the first PATH folder in the user's profile
    Copy-Item -Path "$env:SystemDrive\Users\${pwsh Owner}\Downloads\jq-windows-amd64.exe" -Destination ${pathFolders-pwsh Owner}.Where({$_ -match [regex]::Escape("$env:SystemDrive\Users\${pwsh Owner}")})[0]
  }
  
  ## Confirm presence of Bitwarden Secrets Manager CLI (bws.exe) in a $env:Path directory. 
  while (-not ((Test-Path -Path (Join-Path -Path ${pathFolders-pwsh Owner} -ChildPath "bws.exe") -ErrorAction 'SilentlyContinue') -contains $true)) {
    # Initialize new variable to stand as a session variable and ensure value is $null. 
    $_Var_Name = 'TempSessionVar'
    try {Clear-Variable -Name $_Var_Name -ErrorAction 'Stop'} catch {New-Variable -Name $_Var_Name -Value $null}

    # Download the Bitwarden Secrets Manager CLI
    while (-not $TempSessionVar) {
      # Invoke-WebRequest bombs out the 1st time because of no DNS resource record on the DNS server.
      $RedirectedError = $(
        Invoke-WebRequest -Uri "https://github.com/bitwarden/sdk/releases/download/bws-v1.0.0/bws-x86_64-pc-windows-msvc-1.0.0.zip" -SessionVariable 'TempSessionVar' -OutFile "$env:SystemDrive\Users\${pwsh Owner}\Downloads\bws-windows.zip"
      ) 2>&1
    }

    # extract bws.exe to the first PATH folder in the user's profile
    Expand-Archive -Path "$env:SystemDrive\Users\${pwsh Owner}\Downloads\bws-windows.zip" -Destination ${pathFolders-pwsh Owner}.Where({$_ -match [regex]::Escape("$env:SystemDrive\Users\${pwsh Owner}")})[0]
  }


  # Establish dependencies for the account that owns the explorer.exe process: 

  ## Confirm presence of Bitwarden Password Manager CLI (bw.exe) in one or more of the $env:Path directories. 
  while (-not ((Test-Path -Path (Join-Path -Path ${pathFolders-explorer Owner} -ChildPath "bw.exe") -ErrorAction 'SilentlyContinue') -contains $true)) {
    # Initialize new variable to stand as a session variable and ensure value is $null. 
    $_Var_Name = 'TempSessionVar'
    try {Clear-Variable -Name $_Var_Name -ErrorAction 'Stop'} catch {New-Variable -Name $_Var_Name -Value $null}

    # Download the Bitwarden Password Manager CLI
    while (-not $TempSessionVar) {
      # Invoke-WebRequest bombs out the 1st time because of no DNS resource record on the DNS server.
      $RedirectedError = $(
        Invoke-WebRequest -Uri "https://vault.bitwarden.com/download/?app=cli&platform=windows" -SessionVariable 'TempSessionVar' -OutFile "$env:SystemDrive\Users\${explorer Owner}\Downloads\bw-windows.zip"
      ) 2>&1
    }

    # extract bw.exe to the first PATH folder in the user's profile
    Expand-Archive -Path "$env:SystemDrive\Users\${explorer Owner}\Downloads\bw-windows.zip" -Destination ${pathFolders-explorer Owner}.Where({$_ -match [regex]::Escape("$env:SystemDrive\Users\${explorer Owner}")})[0]
  }

  ## Confirm presence of the jq JSON processor. Necessary for writing into the Bitwarden Password Manager via the Bitwarden CLI. 
  while (-not ((Test-Path -Path (Join-Path -Path ${pathFolders-explorer Owner} -ChildPath "jq-windows-amd64.exe") -ErrorAction 'SilentlyContinue') -contains $true)) {
    # Initialize new variable to stand as a session variable and ensure value is $null. 
    $_Var_Name = 'TempSessionVar'
    try {Clear-Variable -Name $_Var_Name -ErrorAction 'Stop'} catch {New-Variable -Name $_Var_Name -Value $null}

    # Download the jq JSON processor
    while (-not $TempSessionVar) {
      # Invoke-WebRequest bombs out the 1st time because of no DNS resource record on the DNS server.
      $RedirectedError = $(
        Invoke-WebRequest -Uri "https://github.com/jqlang/jq/releases/download/jq-1.7.1/jq-windows-amd64.exe" -SessionVariable 'TempSessionVar' -OutFile "$env:SystemDrive\Users\${explorer Owner}\Downloads\jq-windows-amd64.exe"
      ) 2>&1
    }

    # Copy jq to the first PATH folder in the user's profile
    Copy-Item -Path "$env:SystemDrive\Users\${explorer Owner}\Downloads\jq-windows-amd64.exe" -Destination ${pathFolders-explorer Owner}.Where({$_ -match [regex]::Escape("$env:SystemDrive\Users\${explorer Owner}")})[0]
  }
  
  ## Confirm presence of Bitwarden Secrets Manager CLI (bws.exe) in a $env:Path directory. 
  while (-not ((Test-Path -Path (Join-Path -Path ${pathFolders-explorer Owner} -ChildPath "bws.exe") -ErrorAction 'SilentlyContinue') -contains $true)) {
    # Initialize new variable to stand as a session variable and ensure value is $null. 
    $_Var_Name = 'TempSessionVar'
    try {Clear-Variable -Name $_Var_Name -ErrorAction 'Stop'} catch {New-Variable -Name $_Var_Name -Value $null}

    # Download the Bitwarden Secrets Manager CLI
    while (-not $TempSessionVar) {
      # Invoke-WebRequest bombs out the 1st time because of no DNS resource record on the DNS server.
      $RedirectedError = $(
        Invoke-WebRequest -Uri "https://github.com/bitwarden/sdk/releases/download/bws-v1.0.0/bws-x86_64-pc-windows-msvc-1.0.0.zip" -SessionVariable 'TempSessionVar' -OutFile "$env:SystemDrive\Users\${explorer Owner}\Downloads\bws-windows.zip"
      ) 2>&1
    }

    # extract bws.exe to the first PATH folder in the user's profile
    Expand-Archive -Path "$env:SystemDrive\Users\${explorer Owner}\Downloads\bws-windows.zip" -Destination ${pathFolders-explorer Owner}.Where({$_ -match [regex]::Escape("$env:SystemDrive\Users\${explorer Owner}")})[0]
  }


  ## Code executed when PowerShell detects that a request to close the PowerShell host process has been submitted. 
  ${ScriptBlock to Run at PowerShell Engine Shutdown Event Here-String} = @'
## Save to variable the status of bw.exe
${Bitwarden CLI Authentication Status} = bw.exe status | ConvertFrom-Json | Select-Object -ExpandProperty 'status'

## Lock the Bitwarden Password Manager CLI if "bw.exe status" evaluates to 'unlocked'
switch (${Bitwarden CLI Authentication Status}) {
  'unauthenticated' {break}
  'locked'          {break}
  'unlocked'        {bw.exe lock > $null}
  default           {break}
}
'@
  ${ScriptBlock to Run at PowerShell Engine Shutdown Event} = [ScriptBlock]::Create(${ScriptBlock to Run at PowerShell Engine Shutdown Event Here-String})

  ## If the PowerShell Job associated with the Registered Event (i.e., a request to close the PowerShell host process) 
  ## doesn't exist, then register for the Event representing the PowerShell engine shutdown. 
  $IsJobAlreadyPresent = (Get-Job | Select-Object -ExpandProperty 'Command') -replace [char](0xd),'' | ForEach-Object {Compare-Object -ReferenceObject $_ -DifferenceObject ${ScriptBlock to Run at PowerShell Engine Shutdown Event Here-String}}

  if (-not $IsJobAlreadyPresent) {
    $HT = @{
      SourceIdentifier = ([System.Management.Automation.PsEngineEvent]::Exiting)
      Action = ${ScriptBlock to Run at PowerShell Engine Shutdown Event}
    }

    Register-EngineEvent @HT > $null
  }
}

$NetBiosNameOfActiveDirectoryDomain = 'KNet'
$BitwardenOrganizationName = "Kerberos Networks"
$BitwardenPwdManagerCollectionName = "Active Directory Domain Services" 
$BitwardenSecretsManagerProjectName = "Active Directory Domain Services"
$AccessTokenName = "AT 9f9ed09b-f9ca-4651-b912-cf4f29453a69"

$RedirectedError = $(
  $global:PSDefaultParameterValues.Add("Add-BitwardenPassword:BitwardenOrganizationName",$BitwardenOrganizationName)
  $global:PSDefaultParameterValues.Add("Add-BitwardenPassword:NetBiosNameOfActiveDirectoryDomain",$NetBiosNameOfActiveDirectoryDomain)
  $global:PSDefaultParameterValues.Add("Add-BitwardenPassword:BitwardenPwdManagerCollectionName",$BitwardenPwdManagerCollectionName)
  $global:PSDefaultParameterValues.Add("Add-BitwardenPassword:BitwardenSecretsManagerProjectName",$BitwardenSecretsManagerProjectName)
  $global:PSDefaultParameterValues.Add("Add-BitwardenPassword:AccessTokenName",$AccessTokenName)

  $global:PSDefaultParameterValues.Add("Get-BitwardenPassword:BitwardenOrganizationName",$BitwardenOrganizationName)
  $global:PSDefaultParameterValues.Add("Get-BitwardenPassword:NetBiosNameOfActiveDirectoryDomain",$NetBiosNameOfActiveDirectoryDomain)
  $global:PSDefaultParameterValues.Add("Get-BitwardenPassword:BitwardenPwdManagerCollectionName",$BitwardenPwdManagerCollectionName)
  $global:PSDefaultParameterValues.Add("Get-BitwardenPassword:BitwardenSecretsManagerProjectName",$BitwardenSecretsManagerProjectName)
  $global:PSDefaultParameterValues.Add("Get-BitwardenPassword:AccessTokenName",$AccessTokenName)

  $global:PSDefaultParameterValues.Add("Update-BitwardenPassword:BitwardenOrganizationName",$BitwardenOrganizationName)
  $global:PSDefaultParameterValues.Add("Update-BitwardenPassword:NetBiosNameOfActiveDirectoryDomain",$NetBiosNameOfActiveDirectoryDomain)
  $global:PSDefaultParameterValues.Add("Update-BitwardenPassword:BitwardenPwdManagerCollectionName",$BitwardenPwdManagerCollectionName)
  $global:PSDefaultParameterValues.Add("Update-BitwardenPassword:BitwardenSecretsManagerProjectName",$BitwardenSecretsManagerProjectName)
  $global:PSDefaultParameterValues.Add("Update-BitwardenPassword:AccessTokenName",$AccessTokenName)
) 2>&1

try {
  Get-PSDrive -Name 'HKU' -ErrorAction 'Stop' > $null
}
catch { 
  New-PSDrive -Name 'HKU' -PSProvider 'Registry' -Root 'HKEY_USERS' > $null
}

function Add-BitwardenPassword {
  [CmdletBinding(
    HelpURI = "https://github.com/CarlSimonIT/secure-automations-toolset",
    PositionalBinding = $true
  )]
  param (
    [Parameter(
      Mandatory = $true,
      HelpMessage = "SamAccountName of the Active Directory user account."
    )]
    [ValidatePattern(
      '^[^/\\\[\]\:;\|=,\+\*\?\<\>@"]{1,20}$'
    )]
    [Alias('un')]
    [string]$SamAccountName,

    [Parameter(
      HelpMessage = "Domain-level operations require an account with password length of 128 or less. Try adding a replica DC to the domain with a domain admin whose password is 129 characters-operation will fail. Joining a machine to the domain, however, will succeed."
    )]    
    [ValidateRange(8,255)]
    [int32]$len = 127,

    [Parameter(
      HelpMessage = "`r`n  OPTIONAL: Name of the Item in Bitwarden. Random GUID assigned if left blank.`r`n  Knowing the username of the AD account is enough.`r`n  Uniqueness is only requirement when titling an Item in Bitwarden Password Manager.`r`n"
    )]
    [Alias('item')]
    [string]$BitwardenItemName = (New-Guid).ToString(),

    [Parameter(
      Mandatory = $true,
      HelpMessage = "NetBIOS name of the Active Directory domain. This is different from the Domain Name System name of the Active Directory domain.`r`n`r`nReference from Microsoft Learn:`r`n  https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/plan/assigning-domain-names`r`n"
    )]
    [ValidatePattern(
      '^(?!-)(?!.*-$)(?!ANONYMOUS$)(?!BATCH$)(?!BUILTIN$)(?!DIALUP$)(?!DOMAIN$)(?!ENTERPRISE$)(?!INTERACTIVE$)(?!INTERNET$)(?!LOCAL$)(?!NETWORK$)(?!NULL$)(?!PROXY$)(?!RESTRICTED$)(?!SELF$)(?!SERVER$)(?!SERVICE$)(?!SYSTEM$)(?!USERS$)(?!WORLD$)[a-zA-Z0-9-]{1,15}$'
    )]
    [Alias('dom')]
    [string]$NetBiosNameOfActiveDirectoryDomain,

    [Parameter(
      Mandatory = $true,
      HelpMessage = "Name of the organization in Bitwarden."
    )]
    [Alias('org')]
    [string]$BitwardenOrganizationName,

    [Parameter(
      Mandatory = $true,
      HelpMessage = "Name of the collection in Bitwarden."
    )]
    [Alias('col')]
    [string]$BitwardenPwdManagerCollectionName,

    [Parameter(
      Mandatory = $true,
      HelpMessage = "Name of the project in Bitwarden Secrets Manager."
    )]
    [Alias('proj')]
    [string]$BitwardenSecretsManagerProjectName,
    
    [Parameter(
      Mandatory = $true,
      HelpMessage = "A machine account name and an access token value are stored in the 'username' and 'password' sub-properties of the 'login' property of an 'item' in Bitwarden Password Manager. The -AccessTokenName parameter accepts the NAME of the item object that corresponds to the machine account."
    )]
    [string]$AccessTokenName 
  )
  
  _PrerequisiteConditions

  # Save to variable the status of bw.exe
  $RedirectedErrors = $(
    ${Authentication Status of the Bitwarden CLI} = bw.exe status | ConvertFrom-Json | Select-Object -Expand 'status'
  ) 2>&1

  # Authenticate if status is anything aside from 'unlocked'
  if (${Authentication Status of the Bitwarden CLI} -ne 'unlocked') {
    _AuthenticateIntoBitwardenPasswordManagerCLI
  }

  # Verify whether the AD account already exists in the 'Active Directory Domain Services' collection of the Bitwarden organization
  
  # Initialize new variable for referencing Bitwarden Organization ID and ensure value is $null. 
  $_Var_Name = 'BitwardenOrganizationId' 
  try {Clear-Variable -Name $_Var_Name -ErrorAction 'Stop'} catch {New-Variable -Name $_Var_Name -Value $null}

  # Save to variable the Bitwarden Organization ID
  $BitwardenOrganizationId = bw.exe list organizations | ConvertFrom-Json | Where-Object {$_.name -eq $BitwardenOrganizationName} | Select-Object -ExpandProperty 'id'

  # exit function if no Bitwarden Organization ID produced
  if (-not $BitwardenOrganizationId) {
    Write-Error -Message "`r`n  Bitwarden organization name supplied did not resolve to a UUID.`r`n`r`n  Confirm correct spelling of the organization's name in your Bitwarden account`r`n"
    Pause
    break
  }

  # Initialize new variable for referencing the Collection ID in Bitwarden Password Manager and ensure value is $null. 
  $_Var_Name = 'CollectionId'
  try {Clear-Variable -Name $_Var_Name -ErrorAction 'Stop'} catch {New-Variable -Name $_Var_Name -Value $null}

  # Save to variable the Collection ID from Bitwarden Password Manager
  $CollectionId = bw.exe list --organizationid $BitwardenOrganizationId org-collections | ConvertFrom-Json | Where-Object {$_.name -eq $BitwardenPwdManagerCollectionName} | Select-Object -ExpandProperty 'id'

  # exit function if no collection ID produced
  if (-not $CollectionId) {
    Write-Error -Message "`r`n  Collection name supplied did not resolve to a UUID. `r`n  No collection in Bitwarden Password Manager matches that name. `r`n  Confirm correct spelling of the collection's name in your Bitwarden account.`r`n"
    Pause
    break
  }

  # Only execute the body if a name for the soon-to-be created Item has been defined. 
  if (-not $BitwardenItemName) {
    # Initialize new variable for referencing an Item in Bitwarden Password Manager and ensure value is $null. 
    $_Var_Name = 'ItemInBitwarden'; 
    try {Clear-Variable -Name $_Var_Name -ErrorAction 'Stop'} catch {New-Variable -Name $_Var_Name -Value $null}

    # Query the Bitwarden Organization for an Item of that name. Conceal 'Not Found.' error message emitted from bw.exe by redirecting error stream to variable
    $RedirectedErrors = $(
      $ItemInBitwarden = bw.exe get --organizationid $BitwardenOrganizationId item $BitwardenItemName
    ) 2>&1

    # Destroy variable & exit function if that item is already present
    if ($ItemInBitwarden) {
      Write-Error -Message "Bitwarden Password Manager reports that an Item already has that name.`r`n  Eliminate the '-BitwardenItemName' parameter-argument pair and reattempt."
      pause
      Remove-Variable 'ItemInBitwarden'
      break
    }
  }

  # Initialize new variable for referencing <domain>\<username> and ensure value is $null
  $_Var_Name = 'UsernameInBitwarden'
  try {Clear-Variable -Name $_Var_Name -ErrorAction 'Stop'} catch {New-Variable -Name $_Var_Name -Value $null}

  # Query the Bitwarden Organization for that <domain>\<username> value. Conceal 'Not Found.' error message emitted from bw.exe by redirecting error stream to variable
  $RedirectedErrors = $(
    $UsernameInBitwarden = bw.exe get --organizationid $BitwardenOrganizationId username "$NetBiosNameOfActiveDirectoryDomain\$SamAccountName"
  ) 2>&1

  # exit function if that username is already present
  if ($UsernameInBitwarden) {
    Write-Warning -Message "`r`n  Active Directory account with username '$UsernameInBitwarden' is already present. Attempt:`r`n`tConvertTo-SecureString -String `$(Get-BitwardenPassword -un '$SamAccountName') -AsPlainText -Force"
    break
  }

  # Can now confirm that Bitwarden Password Manager does not contain any credentials that match with the parameter-argument pairs supplied to the function

  # Calling the Bitwarden Secrets Manager CLI
  
  # Save to variable Project ID from Bitwarden Secrets Manager
  $BitwardenSecretsManagerProjectId = bws.exe project list --access-token $(bw.exe get password $AccessTokenName) | ConvertFrom-Json | Where-Object {$_.name -eq $BitwardenSecretsManagerProjectName} | Select-Object -ExpandProperty 'id'

  # Use bws.exe to define the secret value and save to variable the Secret ID from Bitwarden Secrets Manager
  $BitwardenSecretsManagerSecretId = bws.exe secret create --access-token $(bw.exe get password $AccessTokenName) $BitwardenItemName $(_genpwd $len) $BitwardenSecretsManagerProjectId | ConvertFrom-Json | Select-Object -ExpandProperty 'id'

  # ASPIRATION: Generating the secret value in the Bitwarden cloud would be ideal. The local machine should have knowledge of the secret after a query to Bitwarden and only after a query to Bitwarden. 

  # Save to separate variables the properties of the object that will eventually be used to define a new Item in Bitwarden Password Manager
  $EscapedUsername          = "$NetBiosNameOfActiveDirectoryDomain\$SamAccountName" -replace '\\','\\'
  ${bw item-name}           = '.name="%Bw_Item_Name%"' -replace '%Bw_Item_Name%',$BitwardenItemName
  ${bw item-login.username} = '.login.username="%Bw_Item_Login_Username%"' -replace '%Bw_Item_Login_Username%',$EscapedUsername
  ${bw item-login.password} = '.login.password="%Bw_Item_Login_Password%"' -replace '%Bw_Item_Login_Password%',$BitwardenSecretsManagerSecretId
  ${bw item-organizationId} = '.organizationId="%Id_of_Bw_Org%"' -replace '%Id_of_Bw_Org%',$BitwardenOrganizationId
  ${bw item-notes}          = '.notes="%Item_Notes%"' -replace '%Item_Notes%',""
  ${bw item-collectionId}   = '.collectionIds=["%id_of_Org_Collection%"]' -replace '%id_of_Org_Collection%',$CollectionId

  # Write into Bitwarden Password Manager (1) <dom>\<un> > 'username' sub-property, and (2) UUID of secret > 'password' sub-property. 
  bw.exe get template item | jq-windows-amd64.exe ${bw item-name} | jq-windows-amd64.exe ${bw item-login.username} | jq-windows-amd64.exe ${bw item-login.password} | jq-windows-amd64.exe ${bw item-organizationId} | jq-windows-amd64.exe ${bw item-notes} | jq-windows-amd64.exe ${bw item-collectionId} | bw.exe encode | bw.exe create item > $null
}

function Get-BitwardenPassword {
  [CmdletBinding(
    HelpURI = "https://github.com/CarlSimonIT/secure-automations-toolset",
    PositionalBinding = $true
  )]

  param (
    [Parameter(
      Mandatory = $true,
      HelpMessage = "SamAccountName of the Active Directory user account"
    )]
    [ValidatePattern(
      '^[^/\\\[\]\:;\|=,\+\*\?\<\>@"]{1,20}$'
    )]
    [Alias('un')]
    [string]
    $SamAccountName,

    [Alias('ct')]
    [switch]
    $ClearText,

    [Parameter(
      Mandatory = $true,
      HelpMessage = "NetBIOS name of the Active Directory domain. This is different from the Domain Name System name of the Active Directory domain.`r`n`r`nReference from Microsoft Learn:`r`n  https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/plan/assigning-domain-names"
    )]
    [ValidatePattern(
      '^(?!-)(?!.*-$)(?!ANONYMOUS$)(?!BATCH$)(?!BUILTIN$)(?!DIALUP$)(?!DOMAIN$)(?!ENTERPRISE$)(?!INTERACTIVE$)(?!INTERNET$)(?!LOCAL$)(?!NETWORK$)(?!NULL$)(?!PROXY$)(?!RESTRICTED$)(?!SELF$)(?!SERVER$)(?!SERVICE$)(?!SYSTEM$)(?!USERS$)(?!WORLD$)[a-zA-Z0-9-]{1,15}$'
    )]
    [Alias('dom')]
    [string]
    $NetBiosNameOfActiveDirectoryDomain,

    [Parameter(
      Mandatory = $true,
      HelpMessage = "Name of the organization in Bitwarden"
    )]
    [Alias('org')]
    [string]
    $BitwardenOrganizationName,

    [Parameter(
      Mandatory = $true,
      HelpMessage = "Name of the collection in Bitwarden"
    )]
    [Alias('col')]
    [string]
    $BitwardenPwdManagerCollectionName,

    [Parameter(
      Mandatory = $true,
      HelpMessage = "Name of the project in Bitwarden Secrets Manager"
    )]
    [Alias('proj')]
    [string]
    $BitwardenSecretsManagerProjectName,
    
    [Parameter(
      Mandatory = $true,
      HelpMessage = "A machine account name and an access token value are stored in the 'username' and 'password' sub-properties of the 'login' property of an 'item' in Bitwarden Password Manager. The -AccessTokenName parameter accepts the NAME of the item object that corresponds to the machine account."
    )]
    [string]$AccessTokenName
  )

  _PrerequisiteConditions

  # Save to variable the status of bw.exe
  $RedirectedErrors = $(
    ${Authentication Status of the Bitwarden CLI} = bw.exe status | ConvertFrom-Json | Select-Object -Expand 'status'
  ) 2>&1

  # Authenticate if status is anything aside from 'unlocked'
  if (${Authentication Status of the Bitwarden CLI} -ne 'unlocked') {
    _AuthenticateIntoBitwardenPasswordManagerCLI
  }

  # Initialize new variable for referencing Bitwarden Organization ID and ensure value is $null. 
  $_Var_Name = 'BitwardenOrganizationId' 
  try {Clear-Variable -Name $_Var_Name -ErrorAction 'Stop'} catch {New-Variable -Name $_Var_Name -Value $null}

  # Save to variable the Bitwarden Organization ID
  $BitwardenOrganizationId = bw.exe list organizations | ConvertFrom-Json | Where-Object {$_.name -eq $BitwardenOrganizationName} | Select-Object -ExpandProperty 'id'

  # exit function if no Bitwarden Organization ID produced
  if (-not $BitwardenOrganizationId) {
    Write-Error -Message "`r`n  Bitwarden organization name supplied did not resolve to a UUID.`r`n`r`n  Confirm correct spelling of the organization's name in your Bitwarden account`r`n"
    Pause
    break
  }

  # Initialize new variable for referencing the Collection ID in Bitwarden Password Manager and ensure value is $null. 
  $_Var_Name = 'CollectionId'
  try {Clear-Variable -Name $_Var_Name -ErrorAction 'Stop'} catch {New-Variable -Name $_Var_Name -Value $null}

  # Save to variable the Collection ID from Bitwarden Password Manager
  $CollectionId = bw.exe list --organizationid $BitwardenOrganizationId org-collections | ConvertFrom-Json | Where-Object {$_.name -eq $BitwardenPwdManagerCollectionName} | Select-Object -ExpandProperty 'id'

  # exit function if no collection ID produced
  if (-not $CollectionId) {
    Write-Error -Message "`r`n  Collection name supplied did not resolve to a UUID. `r`n  No collection in Bitwarden Password Manager matches that name. `r`n  Confirm correct spelling of the collection's name in your Bitwarden account.`r`n"
    Pause
    break
  }

  $BitwardenSecretsManagerSecretId = bw.exe list --collectionid $CollectionId items --search "$NetBIOSnameOfActiveDirectorydomain\$SamAccountName" | ConvertFrom-Json | Select-Object -ExpandProperty 'login' | Where-Object {$_.username -eq "$NetBIOSnameOfActiveDirectorydomain\$SamAccountName"} | Select-Object -ExpandProperty 'password'

  if (-not $BitwardenSecretsManagerSecretId) {
    Write-Error "Bitwarden does not contain an identity with those details or the local Bitwarden Password Manager CLI needs to undergo a synchronization. Execute the line below and reattempt the query:`r`n`tbw.exe sync"
    Pause
    break
  }

  #Write-Host -ForegroundColor 'Magenta' -Object "For what reason are we not automatically converting to a secure string?"
  switch ($ClearText) {
    $true {
      bws.exe secret get --access-token $(bw.exe get password $AccessTokenName) $BitwardenSecretsManagerSecretId | ConvertFrom-Json | Select-Object -ExpandProperty 'value'
    }
    $false {
      ConvertTo-SecureString -String "$(bws.exe secret get --access-token $(bw.exe get password $AccessTokenName) $BitwardenSecretsManagerSecretId | ConvertFrom-Json | Select-Object -ExpandProperty 'value')" -AsPlainText -Force
    }
  }
}

function Invoke-ElevatedCommand
{
    ##############################################################################
    ##
    ## Invoke-ElevatedCommand
    ##
    ## From Windows PowerShell Cookbook (O'Reilly)
    ## by Lee Holmes (http://www.leeholmes.com/guide)
    ##
    ##############################################################################
    
    <#
    
    .SYNOPSIS
    
    Runs the provided script block under an elevated instance of PowerShell as
    through it were a member of a regular pipeline.
    
    .EXAMPLE
    
    PS > Get-Process | Invoke-ElevatedCommand.ps1 {
        $input | Where-Object { $_.Handles -gt 500 } } | Sort Handles
    
    #>
    
    param(
        ## The script block to invoke elevated
        [Parameter(Mandatory = $true)]
        [ScriptBlock] $Scriptblock,
    
        ## Any input to give the elevated process
        [Parameter(ValueFromPipeline = $true)]
        $InputObject,
    
        ## Switch to enable the user profile
        [switch] $EnableProfile
    )
    
    begin
    {
        Set-StrictMode -Version 3
        $inputItems = New-Object System.Collections.ArrayList
    }
    
    process
    {
        $null = $inputItems.Add($inputObject)
    }
    
    end
    {
        ## Create some temporary files for streaming input and output
        $outputFile = [IO.Path]::GetTempFileName()
        $inputFile = [IO.Path]::GetTempFileName()
    
        ## Stream the input into the input file
        $inputItems.ToArray() | Export-CliXml -Depth 1 $inputFile
    
        ## Start creating the command line for the elevated PowerShell session
        $commandLine = ""
        if(-not $EnableProfile) { $commandLine += "-NoProfile " }
    
        ## Convert the command into an encoded command for PowerShell
        $commandString = "Set-Location '$($pwd.Path)'; " +
            "`$output = Import-CliXml '$inputFile' | " +
            "& {" + $scriptblock.ToString() + "} 2>&1; " +
            "`$output | Export-CliXml -Depth 1 '$outputFile'"
    
        $commandBytes = [System.Text.Encoding]::Unicode.GetBytes($commandString)
        $encodedCommand = [Convert]::ToBase64String($commandBytes)
        $commandLine += "-EncodedCommand $encodedCommand"
    
        ## Start the new PowerShell process
        $process = Start-Process -FilePath (Get-Command pwsh).Definition `
            -ArgumentList $commandLine -Verb RunAs `
            -WindowStyle Hidden `
            -Passthru
        $process.WaitForExit()
    
        ## Return the output to the user
        if((Get-Item $outputFile).Length -gt 0)
        {
            Import-CliXml $outputFile
        }
    
        ## Clean up
        [Console]::WriteLine($outputFile)
        # Remove-Item $outputFile
        Remove-Item $inputFile
    }
}


function Update-BitwardenPassword {
  [CmdletBinding(
    HelpURI = "https://github.com/CarlSimonIT/secure-automations-toolset",
    PositionalBinding = $true
  )]
  param (
    [Parameter(
      Mandatory = $true,
      HelpMessage = "SamAccountName of the Active Directory user account"
    )]
    [ValidatePattern(
      '^[^/\\\[\]\:;\|=,\+\*\?\<\>@"]{1,20}$'
    )]
    [Alias('un')]
    [string]$SamAccountName,

    [Parameter(
      HelpMessage = "Domain-level operations require an account with password length of 128 or less. Try adding a replica DC to the domain with a domain admin whose password is 129 characters-operation will fail. Joining a machine to the domain, however, will succeed."
    )]    
    [ValidateRange(8,255)]
    [int32]$len = 127,

    [Parameter(
      Mandatory = $true,
      HelpMessage = "NetBIOS name of the Active Directory domain. This is different from the Domain Name System name of the Active Directory domain.`r`n`r`nReference from Microsoft Learn:`r`n  https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/plan/assigning-domain-names"
    )]
    [ValidatePattern(
      '^(?!-)(?!.*-$)(?!ANONYMOUS$)(?!BATCH$)(?!BUILTIN$)(?!DIALUP$)(?!DOMAIN$)(?!ENTERPRISE$)(?!INTERACTIVE$)(?!INTERNET$)(?!LOCAL$)(?!NETWORK$)(?!NULL$)(?!PROXY$)(?!RESTRICTED$)(?!SELF$)(?!SERVER$)(?!SERVICE$)(?!SYSTEM$)(?!USERS$)(?!WORLD$)[a-zA-Z0-9-]{1,15}$'
    )]
    [Alias('dom')]
    [string]$NetBiosNameOfActiveDirectoryDomain,

    [Parameter(
      Mandatory = $true,
      HelpMessage = "Name of the organization in Bitwarden"
    )]
    [Alias('org')]
    [string]$BitwardenOrganizationName,

    [Parameter(
      Mandatory = $true,
      HelpMessage = "Name of the collection in Bitwarden"
    )]
    [Alias('col')]
    [string]$BitwardenPwdManagerCollectionName,

    [Parameter(
      Mandatory = $true,
      HelpMessage = "Name of the project in Bitwarden Secrets Manager"
    )]
    [Alias('proj')]
    [string]$BitwardenSecretsManagerProjectName,
    
    [Parameter(
      Mandatory = $true,
      HelpMessage = "A machine account name and an access token value are stored in the 'username' and 'password' sub-properties of the 'login' property of an 'item' in Bitwarden Password Manager. The -AccessTokenName parameter accepts the NAME of the item object that corresponds to the machine account."
    )]
    [string]$AccessTokenName
  )

  _PrerequisiteConditions

  # Save to variable the status of bw.exe
  $RedirectedErrors = $(
    ${Authentication Status of the Bitwarden CLI} = bw.exe status | ConvertFrom-Json | Select-Object -Expand 'status'
  ) 2>&1

  # Authenticate if status is anything aside from 'unlocked'
  if (${Authentication Status of the Bitwarden CLI} -ne 'unlocked') {
    _AuthenticateIntoBitwardenPasswordManagerCLI
  }

  # Verify whether the AD account already exists in the 'Active Directory Domain Services' collection of the Bitwarden organization
  
  # Initialize new variable for referencing Bitwarden Organization ID and ensure value is $null. 
  $_Var_Name = 'BitwardenOrganizationId' 
  try {Clear-Variable -Name $_Var_Name -ErrorAction 'Stop'} catch {New-Variable -Name $_Var_Name -Value $null}

  # Save to variable the Bitwarden Organization ID
  $BitwardenOrganizationId = bw.exe list organizations | ConvertFrom-Json | Where-Object {$_.name -eq $BitwardenOrganizationName} | Select-Object -ExpandProperty 'id'

  # exit function if no Bitwarden Organization ID produced
  if (-not $BitwardenOrganizationId) {
    Write-Error -Message "`r`n  Bitwarden organization name supplied did not resolve to a UUID.`r`n`r`n  Confirm correct spelling of the organization's name in your Bitwarden account`r`n"
    Pause
    break
  }

  # Initialize new variable for referencing the Collection ID in Bitwarden Password Manager and ensure value is $null. 
  $_Var_Name = 'CollectionId'
  try {Clear-Variable -Name $_Var_Name -ErrorAction 'Stop'} catch {New-Variable -Name $_Var_Name -Value $null}

  # Save to variable the Collection ID from Bitwarden Password Manager
  $CollectionId = bw.exe list --organizationid $BitwardenOrganizationId org-collections | ConvertFrom-Json | Where-Object {$_.name -eq $BitwardenPwdManagerCollectionName} | Select-Object -ExpandProperty 'id'

  # exit function if no collection ID produced
  if (-not $CollectionId) {
    Write-Error -Message "`r`n  Collection name supplied did not resolve to a UUID. `r`n  No collection in Bitwarden Password Manager matches that name. `r`n  Confirm correct spelling of the collection's name in your Bitwarden account.`r`n"
    Pause
    break
  }

  # Initialize new variable for referencing <domain>\<username> and ensure value is $null
  $_Var_Name = 'UsernameInBitwarden'
  try {Clear-Variable -Name $_Var_Name -ErrorAction 'Stop'} catch {New-Variable -Name $_Var_Name -Value $null}

  # Query the Bitwarden Organization for that <domain>\<username> value. Conceal 'Not Found.' error message emitted from bw.exe by redirecting error stream to variable
  $RedirectedErrors = $(
    $UsernameInBitwarden = bw.exe get --organizationid $BitwardenOrganizationId username "$NetBiosNameOfActiveDirectoryDomain\$SamAccountName"
  ) 2>&1

  # exit function if that username is not present
  if (-not $UsernameInBitwarden) {
    Write-Warning -Message "Active Directory account with username '$SamAccountName' is not present in Bitwarden. Execute the line below and reattempt the query:`r`n`tbw.exe sync"
    Pause
    break
  }

  # Can now confirm that Bitwarden Password Manager contains a credential that matches with the parameter-argument pairs supplied to the function

  # Calling the Bitwarden Secrets Manager CLI

  # Save to variable Project ID from Bitwarden Secrets Manager
  $BitwardenSecretsManagerSecretId = bw.exe list --collectionid $CollectionId items --search "$NetBIOSnameOfActiveDirectorydomain\$SamAccountName" | ConvertFrom-Json | Select-Object -ExpandProperty 'login' | Where-Object {$_.username -eq "$NetBIOSnameOfActiveDirectorydomain\$SamAccountName"} | Select-Object -ExpandProperty 'password'

  # Save to variable the properties of the object that will eventually contain the old Secret
  $newField = '.fields+=[{name:"%Field_Title%",value:"%Field_Value%",type:1}]' -replace '%Field_Title%',(_CallISO8601TimeDateUTC) -replace '%Field_Value%',$(bws.exe secret get --access-token $(bw.exe get password $AccessTokenName) $BitwardenSecretsManagerSecretId | ConvertFrom-Json | Select-Object -ExpandProperty 'value')

  # Save to variable an object representing the Bitwarden Item that corresponds to the Secret that's undergoing a value change. 
  $item = bw.exe list --collectionid $CollectionId items --search "$NetBIOSnameOfActiveDirectorydomain\$SamAccountName" | ConvertFrom-Json
  $item | ConvertTo-Json | jq-windows-amd64.exe $newField | bw.exe encode | bw.exe edit item $item.id > $null  

  # Change the value of the Secret
  bws.exe secret edit --access-token $(bw.exe get password $AccessTokenName) --value $(_genpwd $len) $BitwardenSecretsManagerSecretId > $null
}

