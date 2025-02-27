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
      $emailaddr = Read-Host -Prompt "Username of Bitwarden account" # -MaskInput
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

  ## Use named matches to capture username of account that owns the pwsh.exe process
  #$(whoami.exe) -match '^\w+\\(?<pwsh_Owner>\S+)' > $null
  #${pwsh Owner} = $Matches['pwsh_Owner']

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

  ## Use named matches to capture the well-known SID of the user account that owns the pwsh.exe process executing these commands. 
  $WhoAmI = whoami.exe /all
  for ($i = 0; $i -lt $WhoAmI.Length; $i++) {
    if (
      $WhoAmI[$i] -match '^Mandatory Label\\\D+Label\s+(?<Well_Known_SID>\S+)'
    ) {
      $Well_Known_SID = $Matches['Well_Known_SID']
    }
  }
  # Ah fuck we never needed this to begin with! 

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
  ${ScriptBlock to Run at PowerShell Engine Shutdown Event} = {
    ## Save to variable the status of bw.exe
    ${Bitwarden CLI Authentication Status} = bw.exe status | ConvertFrom-Json | Select-Object -ExpandProperty 'status'

    ## Lock the Bitwarden Password Manager CLI if "bw.exe status" evaluates to 'unlocked'
    switch (${Bitwarden CLI Authentication Status}) {
      'unauthenticated' {break}
      'locked'          {break}
      'unlocked'        {bw.exe lock > $null}
      default           {break}
    }
  }

  ## If the PowerShell Job associated with the Registered Event (i.e., a request to close the PowerShell host process) 
  ## doesn't exist, then register for the Event representing the PowerShell engine shutdown. 
  
  ## A savvy user may have already registered >1 PowerShell Engine Shutdown event. 
  ## Start brainstorming a way to distinguish this PowerShell.Exiting event from others.
  ## Intuition suggests that this should be fairly simple. 
  if ((Get-Job | Select-Object -ExpandProperty 'Name') -notcontains 'PowerShell.Exiting') {
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




function New-Server2025viaPwshRemoting {
  [CmdletBinding(
    DefaultParameterSetName = 'Member Server',
    ConfirmImpact = 'low',
    HelpURI = 'https://www.altaro.com/hyper-v/customize-vm-powershell/'
  )]
  
  [OutputType('Forest Root Domain Controller')]
  [OutputType('Replica Domain Controller')]
  [OutputType('Member Server')]
  [OutputType('Member Server-Static IP Cfg')]

  param (
    [Parameter(
      Mandatory,
      HelpMessage = "Yes, even if work is being performed while locally logged into a node of a Hyper-V cluster, a PowerShell Remoting session is still required."
    )]
    [Alias('sess')]
    [System.Management.Automation.Runspaces.PSSession]
    $PowerShellRemotingSession,

    [Parameter(
      Mandatory,
      ParameterSetName = 'Forest Root Domain Controller'
    )]
    [Alias('aap')]
    [string]
    $AdministratorAccountPassword,
    
    [Parameter(
      Mandatory,
      ParameterSetName = 'Forest Root Domain Controller'
    )]
    [Parameter(
      Mandatory,
      ParameterSetName = 'Replica Domain Controller'
    )]
    [Parameter(
      Mandatory,
      ParameterSetName = 'Member Server-Static IP Cfg'
    )]
    [ValidatePattern(
      '^(?:(?:1\d\d|2[0-5][0-5]|2[0-4]\d|0?[1-9]\d|0?0?\d)\.){3}(?:1\d\d|2[0-5][0-5]|2[0-4]\d|0?[1-9]\d|0?0?\d)/(?:\d|[12]\d|3[012])$'
    )]
    [string]
    $ip,

    [Parameter(
      Mandatory,
      ParameterSetName = 'Forest Root Domain Controller'
    )]
    [Parameter(
      Mandatory,
      ParameterSetName = 'Replica Domain Controller'
    )]
    [Parameter(
      Mandatory,
      ParameterSetName = 'Member Server-Static IP Cfg'
    )]
    [ValidatePattern(
      '^(?:(?:1\d\d|2[0-5][0-5]|2[0-4]\d|0?[1-9]\d|0?0?\d)\.){3}(?:1\d\d|2[0-5][0-5]|2[0-4]\d|0?[1-9]\d|0?0?\d)$'
    )]
    [string]
    $gw,

    [Parameter(
      Mandatory,
      ParameterSetName = 'Forest Root Domain Controller'
    )]
    [Parameter(
      Mandatory,
      ParameterSetName = 'Replica Domain Controller'
    )]
    [Parameter(
      Mandatory,
      ParameterSetName = 'Member Server-Static IP Cfg'
    )]
    [ValidatePattern(
      '^(?:(?:1\d\d|2[0-5][0-5]|2[0-4]\d|0?[1-9]\d|0?0?\d)\.){3}(?:1\d\d|2[0-5][0-5]|2[0-4]\d|0?[1-9]\d|0?0?\d)$'
    )]
    [string]
    $dns,

    [Parameter(
      Mandatory,
      ParameterSetName = 'Replica Domain Controller'
    )]
    [Parameter(
      Mandatory,
      ParameterSetName = 'Member Server',
      HelpMessage = "The days of joining a computer to the domain without specifying an OU are over.`r`nAcceptable inputs are the Organizational Unit's DistinguishedName or ObjectGUID.`r`nDistinguishedName of OUs in AD will match this regular expression:`r`n`t^OU=[^,]+(?:,OU=[^,]+)*,DC=[^,]+(?:,DC=[^,]+)*$`r`nGUIDs (aka UUIDs) will match this regular expression:`r`n`t^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`r`n`r`nCopy and paste these examples into PowerShell:`r`n`t'OU=Demonstration,OU=Of,DC=Regex,DC=Pattern,DC=Matching' -match '^OU=[^,]+(?:,OU=[^,]+)*,DC=[^,]+(?:,DC=[^,]+)*$'`r`n`t(New-Guid).ToString() -match '^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$'"
    )]
    [Parameter(
      Mandatory,
      ParameterSetName = 'Member Server-Static IP Cfg',
      HelpMessage = "The ValidateScript parameter validation attribute might be better than ValidatePattern. Binding an ObjectGUID to -OU and then converting to DistinguishedName should be possible with [ValidateScript()]"
    )]
    [ValidatePattern(
      '^OU=[^,]+(?:,OU=[^,]+)*,DC=[^,]+(?:,DC=[^,]+)*$|^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$'
    )]
    [string]
    $OU,

    [Parameter(
      ParameterSetName = 'Replica Domain Controller'
    )]
    [Parameter(
      Mandatory,
      ParameterSetName = 'Member Server',
      HelpMessage = "Verify group membership with ValidateScript PVA"
    )]
    [Parameter(
      Mandatory,
      ParameterSetName = 'Member Server-Static IP Cfg',
      HelpMessage = "Perfect opportunity to write dynamic parameters into the function definition. 'Join2Domain0_Tier0' should _NOT_ be an option if the OU's DistinguishedName property is a match for the Tier1 servers OU"
    )]
    [ValidateSet(
      'Join2Domain0_Tier0',
      'Join2Domain0_Tier1'
    )]
    [string]
    $DomainJoinAccount,

    [Parameter(
      Mandatory,
      ParameterSetName = 'Replica Domain Controller'
    )]
    [Parameter(
      Mandatory,
      ParameterSetName = 'Member Server'
    )]
    [Parameter(
      Mandatory,
      ParameterSetName = 'Member Server-Static IP Cfg'
    )]
    [Alias('djap')]
    [string]
    $DomainJoinAccountPassword,

    [Parameter(
      ParameterSetName = 'Replica Domain Controller'
    )]
    [Parameter(
      Mandatory,
      ParameterSetName = 'Member Server',
      HelpMessage = "Perfect opportunity to write dynamic parameters into the function definition. '_dcPrepLocalAdmin1' should _NOT_ be an option if the OU's DistinguishedName property is a match for the Tier1 servers OU"
    )]
    [Parameter(
      Mandatory,
      ParameterSetName = 'Member Server-Static IP Cfg',
      HelpMessage = "Verify group membership with ValidateScript PVA"
    )]
    [string]
    $AutoLogonAccount,

    [Parameter(
      Mandatory,
      ParameterSetName = 'Forest Root Domain Controller'
    )]
    [Parameter(
      Mandatory,
      ParameterSetName = 'Replica Domain Controller'
    )]
    [Parameter(
      Mandatory,
      ParameterSetName = 'Member Server'
    )]
    [Parameter(
      Mandatory,
      ParameterSetName = 'Member Server-Static IP Cfg'
    )]
    [Alias('alap')]
    [string]
    $AutoLogonAccountPassword,

    [string]
    $BurnerAccountPassword,

    [Parameter(
      HelpMessage = "Name of the virtual machine, which does NOT need to match the name of the guest OS!"
    )]
    [string]
    $Name0fVM = ('WIN-' + ([System.IO.Path]::GetRandomFileName()) -replace '\.','' -join '').ToUpper(),

    [Parameter(
      HelpMessage = "Primary differences between Datacenter and Standard is that Standard does not support Storage Spaces Direct, the Hyper-V Host Guardian, the Network Controller, or running more than 2 VMs.`r`nVM deployments of Datacenter and bare-metal deployments of Standard will be rare.`r`nComprehensive feature reference:`r`n`thttps://learn.microsoft.com/en-us/windows-server/get-started/editions-comparison?pivots=windows-server-2025"
    )]
    [ValidateSet(
      'Standard','StandardDesktopExperience','Datacenter','DatacenterDesktopExperience'
    )]
    [string]
    $Edition = 'Standard',

    [Parameter(
      HelpMessage = "Supply name of an AD Computer object. Remember that domain controllers are ALSO AD Computer objects! Stated differently, the ObjectClass of a DC also 'computer'."
    )]
    [ValidateLength(1,15)]
    [ValidatePattern(
      '^(?!(\d{1,15}|ANONYMOUS|BATCH|BUILTIN|DIALUP|DOMAIN|ENTERPRISE|INTERACTIVE|INTERNET|LOCAL|NETWORK|NULL|PROXY|RESTRICTED|SELF|SERVER|SERVICE|SYSTEM|USERS|WORLD)$)[A-Za-z0-9][A-Za-z0-9-]{1,13}[A-Za-z0-9]$'
    )]
    [string]
    $Name0fGuestOS = ('WIN-' + ([System.IO.Path]::GetRandomFileName()) -replace '\.','' -join '').ToUpper(),

    [Parameter(
      ParameterSetName = 'Member Server'
    )]
    [Parameter(
      ParameterSetName = 'Member Server-Static IP Cfg'
    )]
    [boolean]
    $IsVirtualHyperVHost = $false,

    [Parameter(
      HelpMessage = "Two virtual CPUs should be enough"
    )]
    [Int32]
    $cpu = 2,

    [Parameter(
      HelpMessage = "Default quantity of RAM assigned to the VM is 1/8 total physical RAM, so install the maximum amount on your Hyper-V hosts!"
    )]
    [int64]
    $ram = [math]::Round(${Computer Info Lite}.RAM/(8*1024*1024)/2,0)*2MB,
    
    [Parameter(
      HelpMessage = "I suspect that uniquely naming Hyper-V virtual switches (on a per-host basis) isn't necessary or desirable... and maybe it's not even practical!"
    )]
    [ValidateSet(
      'SET-enabled External vSwitch','vSwitchNAT','VLAN-enabled External vSwitch','Isolated vSwitch'
    )]
    [string]
    $net = "SET-enabled External vSwitch",

    [Parameter(
      HelpMessage = "Make sure the Hyper-V host has tons of RAM"
    )]
    [ValidateSet(
      'StartIfRunning','Start','Nothing'
    )]
    [string]
    $ActionWhenBareMetalHostBoots = 'Start',
    
    [Parameter(
      HelpMessage = "No need to right-click each row in Hyper-V Manager and select Shut Down."
    )]
    [ValidateSet(
      'Save','TurnOff','Shutdown'
    )]
    [string]
    $ActionOnBareMetalHostShutdown = 'Shutdown',
    
    [Parameter(
      Mandatory,
      HelpMessage = "I should've started using unattend.xml and autounattend.xml a long, long time ago...`r`nNote for later: Come up with a PVA that matches on a regular expression for this variable.`r`nMaybe try importing the XML file and if error results, fail the function"
    )]
    [string]
    $xml,

    [ValidateRange(1,100)]
    [Int32]
    $Buffer = 20,

    [Parameter(
      Mandatory,
      ParameterSetName = 'Member Server',
      HelpMessage = "Checkpoints and domain controllers do not mix"
    )]
    [Parameter(
      Mandatory,
      ParameterSetName = 'Member Server-Static IP Cfg',
      HelpMessage = "Checkpoints and domain controllers do not mix"
    )]
    [ValidateSet(
      'Disabled','Production','ProductionOnly','Standard'
    )]
    [string]
    $CheckpointType = 'Standard',

    [ValidateSet(
      'Pause','None'
    )]
    [string]
    $StorageDisconnectedAction = 'Pause',

    [int32]
    $HwThreadCountPerCore = '1',

    [Parameter(
      HelpMessage = "Migration between AMD & Intel doesn't appear to be supported!"
    )]
    [Alias('LivMigCompat')]
    [boolean]
    $IsVmCompatibleAcrossDifferentProcessorSKUsOfASingleCompany = $false,

    [Parameter(
      HelpMessage = "Connect to VLAN for Workloads by default. Connecting a vNIC to the Migration (14) or Storage (16) networks doesn't make any sense."
    )]
    [ValidateSet(
      10,12
    )]
    [int32]
    $VlanID = 12,

    [Parameter(
      Mandatory,
      HelpMessage = "New policy going forward: A note is required for each VM.`r`nFor more information, visit`r`n  https://www.altaro.com/hyper-v/vm-notes-powershell/"
    )]
    [string]
    $Notes
  )

  ${AD DNS} = 'ad.kerberosnetworks.com' # <-- Shit coding that I'm going to TEMPORARILY tolerate 
  
  #${Instance %HostName%} = 

  Invoke-Command -Session $PowerShellRemotingSession -ScriptBlock {
    # Installing from the PSGalaxy hosted on a network share and then importing would work better
    Import-Module "$((Get-VMHost).VirtualMachinePath)\Secure-Automations-Toolset.psm1"

    $RedirectedError = $(
      ${Does This VM Already Exist?} = Get-VM -Name $using:Name0fVM
    ) 2>&1
    if (${Does This VM Already Exist?}) {
      Write-Host -ForegroundColor 'DarkRed' -Object "A virtual machine of that name already exists"
      break
    }
  
    $message00 = "Prerequisite .vhdx file doesn't yet exist.`r`n  Creating now..."
    $message01 = ".vhdx file is confirmed to be in place."
    switch ($using:Edition) {
      'Standard' {
        ${Base VHD Path} = "$((Get-VMHost).VirtualHardDiskPath)\Server 2025 Standard ${Latest Server 2025}.vhdx"
        if (!(Test-Path -Path ${Base VHD Path})) {
          Write-Host -ForegroundColor 'Magenta' -Object $message00
          New-Server2025ReferenceVHDXviaPowerShellRemoting -Edition $using:Edition
          $_Var_Name = 'VHD File-system Object'; try {Clear-Variable -Name $_Var_Name -ErrorAction 'Stop'} catch {New-Variable -Name $_Var_Name}
          while (!(${VHD File-system Object})) {${VHD File-system Object} = Get-Item -Path ${Base VHD Path}; Start-Sleep 5}
          Remove-Variable 'VHD File-system Object'
          Write-Host -ForegroundColor 'Yellow' -Object $message01
        }
        break
      }
      'StandardDesktopExperience' {
        ${Base VHD Path} = "$((Get-VMHost).VirtualHardDiskPath)\Server 2025 Standard with Desktop Experience ${Latest Server 2025}.vhdx"
        if (!(Test-Path -Path ${Base VHD Path})) {
          Write-Host -ForegroundColor 'Magenta' -Object $message00
          New-Server2025ReferenceVHDXviaPowerShellRemoting -Edition $using:Edition
          $_Var_Name = 'VHD File-system Object'; try {Clear-Variable -Name $_Var_Name -ErrorAction 'Stop'} catch {New-Variable -Name $_Var_Name}
          while (!(${VHD File-system Object})) {${VHD File-system Object} = Get-Item -Path ${Base VHD Path}; Start-Sleep 5}
          Remove-Variable 'VHD File-system Object'
          Write-Host -ForegroundColor 'Yellow' -Object $message01
        }
        break      
      }
      'Datacenter' {
        ${Base VHD Path} = "$((Get-VMHost).VirtualHardDiskPath)\Server 2025 Datacenter ${Latest Server 2025}.vhdx"
        if (!(Test-Path -Path ${Base VHD Path})) {
          Write-Host -ForegroundColor 'Magenta' -Object $message00
          New-Server2025ReferenceVHDXviaPowerShellRemoting -Edition $using:Edition
          $_Var_Name = 'VHD File-system Object'; try {Clear-Variable -Name $_Var_Name -ErrorAction 'Stop'} catch {New-Variable -Name $_Var_Name}
          while (!(${VHD File-system Object})) {${VHD File-system Object} = Get-Item -Path ${Base VHD Path}; Start-Sleep 5}
          Remove-Variable 'VHD File-system Object'
          Write-Host -ForegroundColor 'Yellow' -Object $message01
        }
        break      
      }
      'DatacenterDesktopExperience' {
        ${Base VHD Path} = "$((Get-VMHost).VirtualHardDiskPath)\Server 2025 Datacenter with Desktop Experience ${Latest Server 2025}.vhdx"
        if (!(Test-Path -Path ${Base VHD Path})) {
          Write-Host -ForegroundColor 'Magenta' -Object $message00
          New-Server2025ReferenceVHDXviaPowerShellRemoting -Edition $using:Edition
          $_Var_Name = 'VHD File-system Object'; try {Clear-Variable -Name $_Var_Name -ErrorAction 'Stop'} catch {New-Variable -Name $_Var_Name}
          while (!(${VHD File-system Object})) {${VHD File-system Object} = Get-Item -Path ${Base VHD Path}; Start-Sleep 5}
          Remove-Variable 'VHD File-system Object'
          Write-Host -ForegroundColor 'Yellow' -Object $message01
        }
        break      
      }
    }
  
    ${Current VM Version} = [double[]](Get-VMHost).SupportedVmVersions | Sort-Object | Select-Object -Last 1
    ${Current VM Version} = (Get-VMHost).SupportedVmVersions | Where-Object {$_ -match ${Current VM Version}}
    
    $HT = @{
      Name               = $using:Name0fVM
      ComputerName       = $env:ComputerName
      Generation         = 2
      MemoryStartupBytes = $using:ram
      Version            = ${Current VM Version}
    }
    try {
      ${New VM} = Get-VM -Name $HT.Name -ErrorAction 'Stop'
    } 
    catch {
      ${New VM} = New-VM @HT
    }
  
    # Create a copy of the .vhdx file located at ${Base VHD Path}. Filename begins with name of VM and then the VM id. 
    ${Guest OS Disk Path} = "$((Get-VMHost).VirtualHardDiskPath)\$(${New VM}.Name) $(${New VM}.Id).vhdx"
    Copy-Item -Path ${Base VHD Path} -Destination ${Guest OS Disk Path}
  
    # Attach VHD containing Guest OS to VM |
    $HT = @{
      VMName             = $using:Name0fVM
      Path               = ${Guest OS Disk Path}
      ControllerType     = 'SCSI'
      ControllerLocation = '0'
      ControllerNumber   = '0'
    }
    Add-VMHardDiskDrive @HT

    $HT = @{
      VMName = $using:Name0fVM
      ControllerType     = 'SCSI'
      ControllerLocation = '0'
      ControllerNumber   = '0'
    }
    ${Guest OS Disk} = Get-VMHardDiskDrive @HT
    
    $dir = "$((Get-VMHost).VirtualHardDiskPath)\$(${New VM}.Name) $(${New VM}.Id)_$((New-Guid).ToString()).vhdx"
    try {
      ${Storage1 VHDX} = Get-VHD -Path $dir -ErrorAction 'Stop'
    } 
    catch {
      ${Storage1 VHDX} = New-VHD -Path $dir -SizeBytes 500GB -Dynamic
    }
  
    $dir = "$((Get-VMHost).VirtualHardDiskPath)\$(${New VM}.Name) $(${New VM}.Id)_$((New-Guid).ToString()).vhdx"
    try {
      ${Storage2 VHDX} = Get-VHD -Path $dir -ErrorAction 'Stop'
    } 
    catch {
      ${Storage2 VHDX} = New-VHD -Path $dir -SizeBytes 500GB -Dynamic
    }

    switch ($using:PSCmdlet.ParameterSetName) {
      {($_ -eq 'Forest Root Domain Controller') -or ($_ -eq 'Replica Domain Controller')} {
        ${Mounted Storage VHDX Disk #} = Mount-DiskImage -ImagePath ${Storage1 VHDX}.Path | Select-Object -ExpandProperty 'ImagePath' | Get-DiskImage | Select-Object -ExpandProperty 'Number'
        Set-Disk -Number ${Mounted Storage VHDX Disk #} -IsOffline $false
        Set-Disk -Number ${Mounted Storage VHDX Disk #} -IsReadOnly $false
        Initialize-Disk -Number ${Mounted Storage VHDX Disk #} -PartitionStyle 'GPT'
        New-Partition -DiskNumber ${Mounted Storage VHDX Disk #} -DriveLetter 'O' -UseMaximumSize | Format-Volume -FileSystem 'NTFS' -NewFileSystemLabel "AD DS Vol" > $null
        Dismount-DiskImage -ImagePath ${Storage1 VHDX}.Path > $null
      
        ${Mounted Storage VHDX Disk #} = Mount-DiskImage -ImagePath ${Storage2 VHDX}.Path | Select-Object -ExpandProperty 'ImagePath' | Get-DiskImage | Select-Object -ExpandProperty 'Number'
        Set-Disk -Number ${Mounted Storage VHDX Disk #} -IsOffline $false
        Set-Disk -Number ${Mounted Storage VHDX Disk #} -IsReadOnly $false
        Initialize-Disk -Number ${Mounted Storage VHDX Disk #} -PartitionStyle 'GPT'
        New-Partition -DiskNumber ${Mounted Storage VHDX Disk #} -DriveLetter 'P' -UseMaximumSize | Format-Volume -FileSystem 'NTFS' -NewFileSystemLabel "Info Disk 00" > $null
        Dismount-DiskImage -ImagePath ${Storage2 VHDX}.Path > $null

        break
      }
      {($_ -eq 'Member Server') -or ($_ -eq 'Member Server-Static IP Cfg')} {
        ${Mounted Storage VHDX Disk #} = Mount-DiskImage -ImagePath ${Storage1 VHDX}.Path | Select-Object -ExpandProperty 'ImagePath' | Get-DiskImage | Select-Object -ExpandProperty 'Number'
        Set-Disk -Number ${Mounted Storage VHDX Disk #} -IsOffline $false
        Set-Disk -Number ${Mounted Storage VHDX Disk #} -IsReadOnly $false
        Initialize-Disk -Number ${Mounted Storage VHDX Disk #} -PartitionStyle 'GPT'
        New-Partition -DiskNumber ${Mounted Storage VHDX Disk #} -AssignDriveLetter -UseMaximumSize | Format-Volume -FileSystem 'NTFS' -NewFileSystemLabel "Info Disk 00" > $null
        Dismount-DiskImage -ImagePath ${Storage1 VHDX}.Path > $null
    
        ${Mounted Storage VHDX Disk #} = Mount-DiskImage -ImagePath ${Storage2 VHDX}.Path | Select-Object -ExpandProperty 'ImagePath' | Get-DiskImage | Select-Object -ExpandProperty 'Number'
        Set-Disk -Number ${Mounted Storage VHDX Disk #} -IsOffline $false
        Set-Disk -Number ${Mounted Storage VHDX Disk #} -IsReadOnly $false
        Initialize-Disk -Number ${Mounted Storage VHDX Disk #} -PartitionStyle 'GPT'
        New-Partition -DiskNumber ${Mounted Storage VHDX Disk #} -AssignDriveLetter -UseMaximumSize | Format-Volume -FileSystem 'NTFS' -NewFileSystemLabel "Info Disk 01" > $null
        Dismount-DiskImage -ImagePath ${Storage2 VHDX}.Path > $null           
        
        break
      }
      default {write "avoiding the 'default' keyword in the final pattern of the switch statement because we'll probably end up further tailoring disk deployments"}
    }

    $HT = @{ # Create new VHD for storage and attach to VM | 'Storage1 VHDX' |
      VMName             = $using:Name0fVM
      Path               = ${Storage1 VHDX}.Path
      ControllerType     = 'SCSI'
      ControllerNumber   = '0'
      ControllerLocation = '1'
    }
    Add-VMHardDiskDrive @HT

    $HT = @{ # Create new VHD for storage and attach to VM | 'Storage2 VHDX' |
      VMName             = $using:Name0fVM
      Path               = ${Storage2 VHDX}.Path
      ControllerType     = 'SCSI'
      ControllerNumber   = '0'
      ControllerLocation = '2'
    }
    Add-VMHardDiskDrive @HT

    $HT = @{ # Set memory quantity & behavior of VM |
      VMName               = $using:Name0fVM
      DynamicMemoryEnabled = $True
      MinimumBytes         = 256MB
      MaximumBytes         = $using:ram
      Buffer               = $using:Buffer
    }
    Set-VMMemory @HT

    $HT = @{ # VM priority when auto-launching at Hyper-V Host boot if cumulative assigned memory exhausts total physical memory |
      VMName   = $using:Name0fVM
      Priority = '50'
    }
    Set-VMMemory @HT
  
    Enable-VMIntegrationService -VMName $using:Name0fVM -Name 'Guest Service Interface'
    Enable-VMIntegrationService -VMName $using:Name0fVM -Name 'Heartbeat'
    Enable-VMIntegrationService -VMName $using:Name0fVM -Name 'Key-Value Pair Exchange'
    Enable-VMIntegrationService -VMName $using:Name0fVM -Name 'Shutdown'
    # Member servers in a domain should sync with a DC that does not host the PDC Emulator, and non-PDCe DCs should sync with the DC that hosts the PDC Emulator.
    Disable-VMIntegrationService -VMName $using:Name0fVM -Name 'Time Synchronization'
    Enable-VMIntegrationService -VMName $using:Name0fVM -Name 'VSS'
  
    $HT = @{ # Expose virtualization extensions if the VM is to be a virtualized Hyper-V host |
      VMName = $using:Name0fVM
      ExposeVirtualizationExtensions = $using:IsVirtualHyperVHost
    }
    Set-VMProcessor @HT

    $HT = @{ # Quantity of vCPUs |
      VMName = $using:Name0fVM
      Count  = $using:cpu
    }
    Set-VMProcessor @HT

    $HT = @{ # Constrain physical CPU resources available to a VM's virtual processors |
      VMName  = $using:Name0fVM
      Reserve = '0'
      Maximum = '100'
    }
    Set-VMProcessor @HT  

    $HT = @{ # Prioritize access to physical CPU resources across VMs | Default value is 100. Since urgency is measured by "weight" and not "priority", a greater number reflects greater importance. |
      VMName         = $using:Name0fVM
      RelativeWeight = '100'
    }
    Set-VMProcessor @HT  

    $HT = @{ # 'Enable Auto-Throttle on a VM’s CPU Access' # Allegedly, Microsoft does not fully document what this controls |
      VMName                       = $using:Name0fVM
      EnableHostResourceProtection = $True
    }
    Set-VMProcessor @HT  

    $HT = @{ # | code "$knet\#scripts#\NuS25W11VMs\NuS25W11VMs.psm1" | Search for 'CompatibilityForMigrationEnabled' for why we set the value to false | UPDATE 2024-12-27: Migration between AMD & Intel isn't allowed by default! |
      VMName                           = $using:Name0fVM
      CompatibilityForMigrationEnabled = $using:IsVmCompatibleAcrossDifferentProcessorSKUsOfASingleCompany
    }
    Set-VMProcessor @HT  

    $HT = @{ # I think that HwThreadCountPerCore = 1 means that NUMA is not enabled _FOR THE VM_ | NUMA can still be enabled at they Hyper-V host level | HwThreadCountPerCore = 0 means to inherit the host's settings for 'hardware threads per core'
      VMName               = $using:Name0fVM
      HwThreadCountPerCore = $using:HwThreadCountPerCore
    }
    Set-VMProcessor @HT  

    $HT = @{ # Automatic Start Action | Automatic Start Delay | Automatic Stop Action |
      Name                 = $using:Name0fVM
      AutomaticStartAction = $using:ActionWhenBareMetalHostBoots
      AutomaticStopAction  = $using:ActionOnBareMetalHostShutdown
      AutomaticStartDelay  = $(60 * ((Get-VM).Count - 1))
    }
    Set-VM @HT  

    $HT = @{ # Firmware settings |
      VMName             = $using:Name0fVM
      FirstBootDevice    = ${Guest OS Disk}
      SecureBootTemplate = 'MicrosoftWindows'
      EnableSecureBoot   = 'On'
    }
    Set-VMFirmware @HT
  
    # VM Checkpoints and domain controllers don't mix |
    (($using:PSCmdlet.ParameterSetName -eq 'Forest Root Domain Controller') -or ($using:PSCmdlet.ParameterSetName -eq 'Replica Domain Controller')) ? 
    (Set-VM -Name $using:Name0fVM -AutomaticCheckpointsEnabled $false) : 
    (& {
      Set-VM -Name $using:Name0fVM -AutomaticCheckpointsEnabled $True
      Set-VM -Name $using:Name0fVM -CheckpointType $using:CheckpointType
    })
  
    Set-VM -VMName $using:Name0fVM -AutomaticCriticalErrorAction $using:StorageDisconnectedAction -AutomaticCriticalErrorActionTimeout 120

    Set-VM -VMName $using:Name0fVM -Notes $using:Notes

    ((Get-VMSwitch $using:net).EmbeddedTeamingEnabled) ? 
    (& {
      Get-VMNetworkAdapter -Name "Network Adapter" -VMName $using:Name0fVM | Rename-VMNetworkAdapter -NewName "Network Adapter-SET"
      $global:vNIC = Get-VMNetworkAdapter -Name "Network Adapter-SET" -VMName $using:Name0fVM
    }) : ($global:vNIC = Get-VMNetworkAdapter -Name "Network Adapter" -VMName $using:Name0fVM)

    Connect-VMNetworkAdapter -Name $vNIC.Name -VMName $using:Name0fVM -SwitchName $using:net
    Set-VMNetworkAdapter -Name $vNIC.Name -VMName $using:Name0fVM -MacAddressSpoofing 'On'
    Set-VMNetworkAdapterVlan -VMName $using:Name0fVM -VMNetworkAdapterName $vNIC.Name -Access -VlanId $using:VlanID

    # Bandwidth Management? 

    Set-VMKeyProtector -VMName $using:Name0fVM -NewLocalKeyProtector

    Enable-VMTPM -VMName $using:Name0fVM

    ${Mounted Storage VHDX Disk #} = Mount-DiskImage -ImagePath ${Guest OS Disk Path} | Select-Object -ExpandProperty 'ImagePath' | Get-DiskImage | Select-Object -ExpandProperty 'Number'
    $VHDDisk = Get-DiskImage -ImagePath ${Guest OS Disk Path} | Get-Disk
    $VHDPart = Get-Partition -DiskNumber $VHDDisk.Number | Select-Object -First 1
    $VHDVolume = ([string]$VHDPart.DriveLetter).trim() + ":"

    $dir = "$VHDVolume\Installs"; try {Get-Item -Path $dir -ErrorAction 'Stop' | Out-Null} catch {New-Item -ItemType 'Directory' -Path $dir | Out-Null}

    #Write-Host -ForegroundColor $(rFc) -Object "$($using:PSCmdlet.ParameterSetName)"

    $xml = $using:xml

    switch ($using:PSCmdlet.ParameterSetName) {
      'Forest Root Domain Controller' {
        # Import XML document into an object instance of type XmlDocument
        ($XmlDocument = [xml]'<root></root>').Load($xml)

        ($XmlDocument.unattend.settings).Where({$_.Pass -eq 'specialize'}).component | Where-Object {$_.Name -eq "Microsoft-Windows-Shell-Setup"} | ForEach-Object {$_.ComputerName = $using:Name0fGuestOS}
        ($XmlDocument.unattend.settings).Where({$_.Pass -eq 'specialize'}).component | Where-Object {$_.Name -eq "Microsoft-Windows-Shell-Setup"} | ForEach-Object {$_.RegisteredOrganization = ${using:Public DNS Domain}}
        ($XmlDocument.unattend.settings).Where({$_.Pass -eq 'specialize'}).component | Where-Object {$_.Name -eq "Microsoft-Windows-Shell-Setup"} | ForEach-Object {$_.RegisteredOwner = $using:BitwardenOrganizationName}
        ($XmlDocument.unattend.settings).Where({$_.Pass -eq 'specialize'}).component | Where-Object {$_.Name -eq "Microsoft-Windows-Shell-Setup"} | ForEach-Object {$_.TimeZone = $(Get-TimeZone | Select-Object -ExpandProperty 'StandardName')}

        ($XmlDocument.unattend.settings).Where({$_.Pass -eq 'specialize'}).component | Where-Object {$_.Name -eq "Microsoft-Windows-TCPIP"} | ForEach-Object {$_.Interfaces.Interface.UnicastIpAddresses.IpAddress.InnerText = $using:ip}
        ($XmlDocument.unattend.settings).Where({$_.Pass -eq 'specialize'}).component | Where-Object {$_.Name -eq "Microsoft-Windows-TCPIP"} | ForEach-Object {$_.Interfaces.Interface.Routes.Route.Identifier = "0"}
        ($XmlDocument.unattend.settings).Where({$_.Pass -eq 'specialize'}).component | Where-Object {$_.Name -eq "Microsoft-Windows-TCPIP"} | ForEach-Object {$_.Interfaces.Interface.Routes.Route.Prefix = "0.0.0.0/0"}
        ($XmlDocument.unattend.settings).Where({$_.Pass -eq 'specialize'}).component | Where-Object {$_.Name -eq "Microsoft-Windows-TCPIP"} | ForEach-Object {$_.Interfaces.Interface.Routes.Route.NextHopAddress = $using:gw}
        ($XmlDocument.unattend.settings).Where({$_.Pass -eq 'specialize'}).component | Where-Object {$_.Name -eq "Microsoft-Windows-DNS-Client"} | ForEach-Object {$_.Interfaces.Interface.DNSServerSearchOrder.IpAddress.InnerText = $using:dns}

        # Password Injection: Autologon of 'PrimaryAdmin'
        #($XmlDocument.unattend.settings).Where({$_.Pass -eq 'oobeSystem'}).component | Where-Object {$_.Name -eq "Microsoft-Windows-Shell-Setup"} | ForEach-Object {$_.Autologon.Password.PlainText = $false}
        #($XmlDocument.unattend.settings).Where({$_.Pass -eq 'oobeSystem'}).component | Where-Object {$_.Name -eq "Microsoft-Windows-Shell-Setup"} | ForEach-Object {$_.Autologon.Password.Value = [System.Convert]::ToBase64String([System.Text.Encoding]::Unicode.GetBytes($((Get-BitwardenPassword 'PrimaryAdmin') + "Password")))}
        #($XmlDocument.unattend.settings).Where({$_.Pass -eq 'oobeSystem'}).component | Where-Object {$_.Name -eq "Microsoft-Windows-Shell-Setup"} | ForEach-Object {$_.Autologon.Password.Value = [System.Convert]::ToBase64String([System.Text.Encoding]::Unicode.GetBytes($($using:AutoLogonAccountPassword + "Password")))}

        # Password Injection: 'Administrator'
        ($XmlDocument.unattend.settings).Where({$_.Pass -eq 'oobeSystem'}).component | Where-Object {$_.Name -eq "Microsoft-Windows-Shell-Setup"} | ForEach-Object {$_.UserAccounts.AdministratorPassword.PlainText = $false}
        #($XmlDocument.unattend.settings).Where({$_.Pass -eq 'oobeSystem'}).component | Where-Object {$_.Name -eq "Microsoft-Windows-Shell-Setup"} | ForEach-Object {$_.UserAccounts.AdministratorPassword.Value = [System.Convert]::ToBase64String([System.Text.Encoding]::Unicode.GetBytes($((Get-BitwardenPassword 'Administrator') + "AdministratorPassword")))}
        ($XmlDocument.unattend.settings).Where({$_.Pass -eq 'oobeSystem'}).component | Where-Object {$_.Name -eq "Microsoft-Windows-Shell-Setup"} | ForEach-Object {$_.UserAccounts.AdministratorPassword.Value = [System.Convert]::ToBase64String([System.Text.Encoding]::Unicode.GetBytes($($using:AdministratorAccountPassword + "AdministratorPassword")))}

        # Password Injection: 'PrimaryAdmin'
        ($XmlDocument.unattend.settings).Where({$_.Pass -eq 'oobeSystem'}).component | Where-Object {$_.Name -eq "Microsoft-Windows-Shell-Setup"} | ForEach-Object {$_.UserAccounts.LocalAccounts.LocalAccount.Password.PlainText = $false}
        #($XmlDocument.unattend.settings).Where({$_.Pass -eq 'oobeSystem'}).component | Where-Object {$_.Name -eq "Microsoft-Windows-Shell-Setup"} | ForEach-Object {$_.UserAccounts.LocalAccounts.LocalAccount.Password.Value = [System.Convert]::ToBase64String([System.Text.Encoding]::Unicode.GetBytes($((Get-BitwardenPassword 'PrimaryAdmin') + "Password")))}
        ($XmlDocument.unattend.settings).Where({$_.Pass -eq 'oobeSystem'}).component | Where-Object {$_.Name -eq "Microsoft-Windows-Shell-Setup"} | ForEach-Object {$_.UserAccounts.LocalAccounts.LocalAccount.Password.Value = [System.Convert]::ToBase64String([System.Text.Encoding]::Unicode.GetBytes($($using:AutoLogonAccountPassword + "Password")))}

        # Other items under the 'oobeSystem' using:pass
        ($XmlDocument.unattend.settings).Where({$_.Pass -eq 'oobeSystem'}).component | Where-Object {$_.Name -eq "Microsoft-Windows-Shell-Setup"} | ForEach-Object {$_.RegisteredOrganization = ${using:Public DNS Domain}}
        ($XmlDocument.unattend.settings).Where({$_.Pass -eq 'oobeSystem'}).component | Where-Object {$_.Name -eq "Microsoft-Windows-Shell-Setup"} | ForEach-Object {$_.RegisteredOwner = $using:BitwardenOrganizationName}
        ($XmlDocument.unattend.settings).Where({$_.Pass -eq 'oobeSystem'}).component | Where-Object {$_.Name -eq "Microsoft-Windows-Shell-Setup"} | ForEach-Object {$_.TimeZone = $(Get-TimeZone | Select-Object -ExpandProperty 'StandardName')}

        <# Investigations |
          $AltPath = "$ns\xml\unattend $(Call-DateVar).xml"
          $XmlDocument.Save($AltPath)
          code $AltPath

          $AltPath | Set-ClipBoard
          Remove-Variable 'XmlDocument'
        #>
        $XmlDocument.Save("$VHDVolume\unattend.xml")
        break
      }
      'Replica Domain Controller' {
        ($XmlDocument = [xml]'<root></root>').Load("$((Get-VMHost).VirtualMachinePath)\$xml")

        ($XmlDocument.unattend.settings).Where({$_.Pass -eq 'specialize'}).component | Where-Object {$_.Name -eq "Microsoft-Windows-Shell-Setup"} | ForEach-Object {$_.ComputerName = $using:Name0fGuestOS}
        ($XmlDocument.unattend.settings).Where({$_.Pass -eq 'specialize'}).component | Where-Object {$_.Name -eq "Microsoft-Windows-Shell-Setup"} | ForEach-Object {$_.RegisteredOrganization = ${using:Public DNS Domain}}
        ($XmlDocument.unattend.settings).Where({$_.Pass -eq 'specialize'}).component | Where-Object {$_.Name -eq "Microsoft-Windows-Shell-Setup"} | ForEach-Object {$_.RegisteredOwner = $using:BitwardenOrganizationName}
        
        ($XmlDocument.unattend.settings).Where({$_.Pass -eq 'specialize'}).component | Where-Object {$_.Name -eq "Microsoft-Windows-TCPIP"} | ForEach-Object {$_.Interfaces.Interface.UnicastIpAddresses.IpAddress.InnerText = $using:ip}
        ($XmlDocument.unattend.settings).Where({$_.Pass -eq 'specialize'}).component | Where-Object {$_.Name -eq "Microsoft-Windows-TCPIP"} | ForEach-Object {$_.Interfaces.Interface.Routes.Route.Identifier = "0"}
        ($XmlDocument.unattend.settings).Where({$_.Pass -eq 'specialize'}).component | Where-Object {$_.Name -eq "Microsoft-Windows-TCPIP"} | ForEach-Object {$_.Interfaces.Interface.Routes.Route.Prefix = "0.0.0.0/0"}
        ($XmlDocument.unattend.settings).Where({$_.Pass -eq 'specialize'}).component | Where-Object {$_.Name -eq "Microsoft-Windows-TCPIP"} | ForEach-Object {$_.Interfaces.Interface.Routes.Route.NextHopAddress = $using:gw}        
        ($XmlDocument.unattend.settings).Where({$_.Pass -eq 'specialize'}).component | Where-Object {$_.Name -eq "Microsoft-Windows-DNS-Client"} | ForEach-Object {$_.Interfaces.Interface.DNSServerSearchOrder.IpAddress.InnerText = $using:dns}
        
        #($XmlDocument.unattend.settings).Where({$_.Pass -eq 'specialize'}).component | Where-Object {$_.Name -eq "Microsoft-Windows-UnattendedJoin"} | ForEach-Object {$_.Identification.Credentials.Domain = $(Get-ADDomain | Select-Object -ExpandProperty 'DnsRoot')} # You should be capable of figuring out how to get this to work. 
        ($XmlDocument.unattend.settings).Where({$_.Pass -eq 'specialize'}).component | Where-Object {$_.Name -eq "Microsoft-Windows-UnattendedJoin"} | ForEach-Object {$_.Identification.Credentials.Domain = ${using:AD DNS}}
        ($XmlDocument.unattend.settings).Where({$_.Pass -eq 'specialize'}).component | Where-Object {$_.Name -eq "Microsoft-Windows-UnattendedJoin"} | ForEach-Object {$_.Identification.Credentials.Username = $using:DomainJoinAccount}
        ($XmlDocument.unattend.settings).Where({$_.Pass -eq 'specialize'}).component | Where-Object {$_.Name -eq "Microsoft-Windows-UnattendedJoin"} | ForEach-Object {$_.Identification.Credentials.Password = $using:DomainJoinAccountPassword}        
        #($XmlDocument.unattend.settings).Where({$_.Pass -eq 'specialize'}).component | Where-Object {$_.Name -eq "Microsoft-Windows-UnattendedJoin"} | ForEach-Object {$_.Identification.JoinDomain = $(Get-ADDomain | Select-Object -ExpandProperty 'DnsRoot')} # You should be capable of figuring out how to get this to work. 
        ($XmlDocument.unattend.settings).Where({$_.Pass -eq 'specialize'}).component | Where-Object {$_.Name -eq "Microsoft-Windows-UnattendedJoin"} | ForEach-Object {$_.Identification.JoinDomain = ${using:AD DNS}}
        ($XmlDocument.unattend.settings).Where({$_.Pass -eq 'specialize'}).component | Where-Object {$_.Name -eq "Microsoft-Windows-UnattendedJoin"} | ForEach-Object {$_.Identification.MachineObjectOU = $using:OU}
        
        ($XmlDocument.unattend.settings).Where({$_.Pass -eq 'oobeSystem'}).component | Where-Object {$_.Name -eq "Microsoft-Windows-Shell-Setup"} | ForEach-Object {$_.AutoLogon.Password.Value = [System.Convert]::ToBase64String([System.Text.Encoding]::Unicode.GetBytes($(($using:AutoLogonAccountPassword) + "Password")))}
        ($XmlDocument.unattend.settings).Where({$_.Pass -eq 'oobeSystem'}).component | Where-Object {$_.Name -eq "Microsoft-Windows-Shell-Setup"} | ForEach-Object {$_.AutoLogon.Username = $using:AutoLogonAccount}
        ($XmlDocument.unattend.settings).Where({$_.Pass -eq 'oobeSystem'}).component | Where-Object {$_.Name -eq "Microsoft-Windows-Shell-Setup"} | ForEach-Object {$_.AutoLogon.Domain = $using:NetBiosNameOfActiveDirectoryDomain}      
        ($XmlDocument.unattend.settings).Where({$_.Pass -eq 'oobeSystem'}).component | Where-Object {$_.Name -eq "Microsoft-Windows-Shell-Setup"} | ForEach-Object {$_.UserAccounts.AdministratorPassword.Value = [System.Convert]::ToBase64String([System.Text.Encoding]::Unicode.GetBytes($(($using:BurnerAccountPassword) + "AdministratorPassword")))}
        ($XmlDocument.unattend.settings).Where({$_.Pass -eq 'oobeSystem'}).component | Where-Object {$_.Name -eq "Microsoft-Windows-Shell-Setup"} | ForEach-Object {$_.UserAccounts.DomainAccounts.DomainAccountList.DomainAccount.Name = $using:AutoLogonAccount}
        ($XmlDocument.unattend.settings).Where({$_.Pass -eq 'oobeSystem'}).component | Where-Object {$_.Name -eq "Microsoft-Windows-Shell-Setup"} | ForEach-Object {$_.UserAccounts.DomainAccounts.DomainAccountList.DomainAccount.Group = 'Administrators'}
        ($XmlDocument.unattend.settings).Where({$_.Pass -eq 'oobeSystem'}).component | Where-Object {$_.Name -eq "Microsoft-Windows-Shell-Setup"} | ForEach-Object {$_.UserAccounts.DomainAccounts.DomainAccountList.Domain = $using:NetBiosNameOfActiveDirectoryDomain}        
       
        $XmlDocument.Save("$VHDVolume\unattend.xml")
      
        break
      }
      'Member Server' {
        ($XmlDocument = [xml]'<root></root>').Load("$((Get-VMHost).VirtualMachinePath)\$xml")

        ($XmlDocument.unattend.settings).Where({$_.Pass -eq 'specialize'}).component | Where-Object {$_.Name -eq "Microsoft-Windows-Shell-Setup"} | ForEach-Object {$_.ComputerName = $using:Name0fGuestOS}
        ($XmlDocument.unattend.settings).Where({$_.Pass -eq 'specialize'}).component | Where-Object {$_.Name -eq "Microsoft-Windows-Shell-Setup"} | ForEach-Object {$_.RegisteredOrganization = ${using:Public DNS Domain}}
        ($XmlDocument.unattend.settings).Where({$_.Pass -eq 'specialize'}).component | Where-Object {$_.Name -eq "Microsoft-Windows-Shell-Setup"} | ForEach-Object {$_.RegisteredOwner = $using:BitwardenOrganizationName}
        #($XmlDocument.unattend.settings).Where({$_.Pass -eq 'specialize'}).component | Where-Object {$_.Name -eq "Microsoft-Windows-UnattendedJoin"} | ForEach-Object {$_.Identification.Credentials.Domain = $(Get-ADDomain | Select-Object -ExpandProperty 'DnsRoot')} # You should be capable of figuring out how to get this to work. 
        ($XmlDocument.unattend.settings).Where({$_.Pass -eq 'specialize'}).component | Where-Object {$_.Name -eq "Microsoft-Windows-UnattendedJoin"} | ForEach-Object {$_.Identification.Credentials.Domain = ${using:AD DNS}}
        ($XmlDocument.unattend.settings).Where({$_.Pass -eq 'specialize'}).component | Where-Object {$_.Name -eq "Microsoft-Windows-UnattendedJoin"} | ForEach-Object {$_.Identification.Credentials.Username = $using:DomainJoinAccount}
        ($XmlDocument.unattend.settings).Where({$_.Pass -eq 'specialize'}).component | Where-Object {$_.Name -eq "Microsoft-Windows-UnattendedJoin"} | ForEach-Object {$_.Identification.Credentials.Password = $using:DomainJoinAccountPassword}
        #($XmlDocument.unattend.settings).Where({$_.Pass -eq 'specialize'}).component | Where-Object {$_.Name -eq "Microsoft-Windows-UnattendedJoin"} | ForEach-Object {$_.Identification.JoinDomain = $(Get-ADDomain | Select-Object -ExpandProperty 'DnsRoot')} # You should be capable of figuring out how to get this to work. 
        ($XmlDocument.unattend.settings).Where({$_.Pass -eq 'specialize'}).component | Where-Object {$_.Name -eq "Microsoft-Windows-UnattendedJoin"} | ForEach-Object {$_.Identification.JoinDomain = ${using:AD DNS}}
        ($XmlDocument.unattend.settings).Where({$_.Pass -eq 'specialize'}).component | Where-Object {$_.Name -eq "Microsoft-Windows-UnattendedJoin"} | ForEach-Object {$_.Identification.MachineObjectOU = $using:OU}
        
        ($XmlDocument.unattend.settings).Where({$_.Pass -eq 'oobeSystem'}).component | Where-Object {$_.Name -eq "Microsoft-Windows-Shell-Setup"} | ForEach-Object {$_.AutoLogon.Password.Value = [System.Convert]::ToBase64String([System.Text.Encoding]::Unicode.GetBytes($(($using:AutoLogonAccountPassword) + "Password")))}
        ($XmlDocument.unattend.settings).Where({$_.Pass -eq 'oobeSystem'}).component | Where-Object {$_.Name -eq "Microsoft-Windows-Shell-Setup"} | ForEach-Object {$_.AutoLogon.Username = $using:AutoLogonAccount}
        ($XmlDocument.unattend.settings).Where({$_.Pass -eq 'oobeSystem'}).component | Where-Object {$_.Name -eq "Microsoft-Windows-Shell-Setup"} | ForEach-Object {$_.AutoLogon.Domain = $using:NetBiosNameOfActiveDirectoryDomain}      
        ($XmlDocument.unattend.settings).Where({$_.Pass -eq 'oobeSystem'}).component | Where-Object {$_.Name -eq "Microsoft-Windows-Shell-Setup"} | ForEach-Object {$_.UserAccounts.AdministratorPassword.Value = [System.Convert]::ToBase64String([System.Text.Encoding]::Unicode.GetBytes($(($using:BurnerAccountPassword) + "AdministratorPassword")))}
        ($XmlDocument.unattend.settings).Where({$_.Pass -eq 'oobeSystem'}).component | Where-Object {$_.Name -eq "Microsoft-Windows-Shell-Setup"} | ForEach-Object {$_.UserAccounts.DomainAccounts.DomainAccountList.DomainAccount.Name = $using:AutoLogonAccount}
        ($XmlDocument.unattend.settings).Where({$_.Pass -eq 'oobeSystem'}).component | Where-Object {$_.Name -eq "Microsoft-Windows-Shell-Setup"} | ForEach-Object {$_.UserAccounts.DomainAccounts.DomainAccountList.DomainAccount.Group = 'Administrators'}
        ($XmlDocument.unattend.settings).Where({$_.Pass -eq 'oobeSystem'}).component | Where-Object {$_.Name -eq "Microsoft-Windows-Shell-Setup"} | ForEach-Object {$_.UserAccounts.DomainAccounts.DomainAccountList.Domain = $using:NetBiosNameOfActiveDirectoryDomain}        
       
        $XmlDocument.Save("$VHDVolume\unattend.xml")
      
        break
      }
      'Member Server-Static IP Cfg' {
        ($XmlDocument = [xml]'<root></root>').Load("$((Get-VMHost).VirtualMachinePath)\$xml")

        ($XmlDocument.unattend.settings).Where({$_.Pass -eq 'specialize'}).component | Where-Object {$_.Name -eq "Microsoft-Windows-Shell-Setup"} | ForEach-Object {$_.ComputerName = $using:Name0fGuestOS}
        ($XmlDocument.unattend.settings).Where({$_.Pass -eq 'specialize'}).component | Where-Object {$_.Name -eq "Microsoft-Windows-Shell-Setup"} | ForEach-Object {$_.RegisteredOrganization = ${using:Public DNS Domain}}
        ($XmlDocument.unattend.settings).Where({$_.Pass -eq 'specialize'}).component | Where-Object {$_.Name -eq "Microsoft-Windows-Shell-Setup"} | ForEach-Object {$_.RegisteredOwner = $using:BitwardenOrganizationName}
        
        ($XmlDocument.unattend.settings).Where({$_.Pass -eq 'specialize'}).component | Where-Object {$_.Name -eq "Microsoft-Windows-TCPIP"} | ForEach-Object {$_.Interfaces.Interface.UnicastIpAddresses.IpAddress.InnerText = $using:ip}
        ($XmlDocument.unattend.settings).Where({$_.Pass -eq 'specialize'}).component | Where-Object {$_.Name -eq "Microsoft-Windows-TCPIP"} | ForEach-Object {$_.Interfaces.Interface.Routes.Route.Identifier = "0"}
        ($XmlDocument.unattend.settings).Where({$_.Pass -eq 'specialize'}).component | Where-Object {$_.Name -eq "Microsoft-Windows-TCPIP"} | ForEach-Object {$_.Interfaces.Interface.Routes.Route.Prefix = "0.0.0.0/0"}
        ($XmlDocument.unattend.settings).Where({$_.Pass -eq 'specialize'}).component | Where-Object {$_.Name -eq "Microsoft-Windows-TCPIP"} | ForEach-Object {$_.Interfaces.Interface.Routes.Route.NextHopAddress = $using:gw}        
        ($XmlDocument.unattend.settings).Where({$_.Pass -eq 'specialize'}).component | Where-Object {$_.Name -eq "Microsoft-Windows-DNS-Client"} | ForEach-Object {$_.Interfaces.Interface.DNSServerSearchOrder.IpAddress.InnerText = $using:dns}

        #($XmlDocument.unattend.settings).Where({$_.Pass -eq 'specialize'}).component | Where-Object {$_.Name -eq "Microsoft-Windows-UnattendedJoin"} | ForEach-Object {$_.Identification.Credentials.Domain = $(Get-ADDomain | Select-Object -ExpandProperty 'DnsRoot')}
        ($XmlDocument.unattend.settings).Where({$_.Pass -eq 'specialize'}).component | Where-Object {$_.Name -eq "Microsoft-Windows-UnattendedJoin"} | ForEach-Object {$_.Identification.Credentials.Domain = ${using:AD DNS}}
        ($XmlDocument.unattend.settings).Where({$_.Pass -eq 'specialize'}).component | Where-Object {$_.Name -eq "Microsoft-Windows-UnattendedJoin"} | ForEach-Object {$_.Identification.Credentials.Username = $using:DomainJoinAccount}
        ($XmlDocument.unattend.settings).Where({$_.Pass -eq 'specialize'}).component | Where-Object {$_.Name -eq "Microsoft-Windows-UnattendedJoin"} | ForEach-Object {$_.Identification.Credentials.Password = $using:DomainJoinAccountPassword}        
        #($XmlDocument.unattend.settings).Where({$_.Pass -eq 'specialize'}).component | Where-Object {$_.Name -eq "Microsoft-Windows-UnattendedJoin"} | ForEach-Object {$_.Identification.JoinDomain = $(Get-ADDomain | Select-Object -ExpandProperty 'DnsRoot')}
        ($XmlDocument.unattend.settings).Where({$_.Pass -eq 'specialize'}).component | Where-Object {$_.Name -eq "Microsoft-Windows-UnattendedJoin"} | ForEach-Object {$_.Identification.JoinDomain = ${using:AD DNS}}
        ($XmlDocument.unattend.settings).Where({$_.Pass -eq 'specialize'}).component | Where-Object {$_.Name -eq "Microsoft-Windows-UnattendedJoin"} | ForEach-Object {$_.Identification.MachineObjectOU = $using:OU}
        
        ($XmlDocument.unattend.settings).Where({$_.Pass -eq 'oobeSystem'}).component | Where-Object {$_.Name -eq "Microsoft-Windows-Shell-Setup"} | ForEach-Object {$_.AutoLogon.Password.Value = [System.Convert]::ToBase64String([System.Text.Encoding]::Unicode.GetBytes($(($using:AutoLogonAccountPassword) + "Password")))}
        ($XmlDocument.unattend.settings).Where({$_.Pass -eq 'oobeSystem'}).component | Where-Object {$_.Name -eq "Microsoft-Windows-Shell-Setup"} | ForEach-Object {$_.AutoLogon.Username = $using:AutoLogonAccount}
        ($XmlDocument.unattend.settings).Where({$_.Pass -eq 'oobeSystem'}).component | Where-Object {$_.Name -eq "Microsoft-Windows-Shell-Setup"} | ForEach-Object {$_.AutoLogon.Domain = $using:NetBiosNameOfActiveDirectoryDomain}      
        ($XmlDocument.unattend.settings).Where({$_.Pass -eq 'oobeSystem'}).component | Where-Object {$_.Name -eq "Microsoft-Windows-Shell-Setup"} | ForEach-Object {$_.UserAccounts.AdministratorPassword.Value = [System.Convert]::ToBase64String([System.Text.Encoding]::Unicode.GetBytes($(($using:BurnerAccountPassword) + "AdministratorPassword")))}
        ($XmlDocument.unattend.settings).Where({$_.Pass -eq 'oobeSystem'}).component | Where-Object {$_.Name -eq "Microsoft-Windows-Shell-Setup"} | ForEach-Object {$_.UserAccounts.DomainAccounts.DomainAccountList.DomainAccount.Name = $using:AutoLogonAccount}
        ($XmlDocument.unattend.settings).Where({$_.Pass -eq 'oobeSystem'}).component | Where-Object {$_.Name -eq "Microsoft-Windows-Shell-Setup"} | ForEach-Object {$_.UserAccounts.DomainAccounts.DomainAccountList.DomainAccount.Group = 'Administrators'}
        ($XmlDocument.unattend.settings).Where({$_.Pass -eq 'oobeSystem'}).component | Where-Object {$_.Name -eq "Microsoft-Windows-Shell-Setup"} | ForEach-Object {$_.UserAccounts.DomainAccounts.DomainAccountList.Domain = $using:NetBiosNameOfActiveDirectoryDomain}        
       
        $XmlDocument.Save("$VHDVolume\unattend.xml")
      
        break
      }
      default {write "Keeping the possibility of more parameter sets open"}
    }

    if ($using:PSCmdlet.ParameterSetName -eq 'Forest Root Domain Controller') {
      $dir = "$VHDVolume\Installs"; try {Get-Item -Path $dir -ErrorAction 'Stop' | Out-Null} catch {New-Item -ItemType 'Directory' -Path $dir | Out-Null}
      $dir = "$dir\PowerShell 7"; try {Get-Item -Path $dir -ErrorAction 'Stop' | Out-Null} catch {New-Item -ItemType 'Directory' -Path $dir | Out-Null}
      $pwsh7MSI = Get-ChildItem -Path "$env:SystemDrive\Installs\PowerShell 7" -Filter "PowerShell*x64.msi" -Recurse | Sort-Object LastWriteTime | Select-Object -Last 1
      Copy-Item -Path "$pwsh7MSI" -Destination "$dir" -Force
    
      $dir = "$VHDVolume\Installs\OneDrive"; try {Get-Item -Path $dir -ErrorAction 'Stop' | Out-Null} catch {New-Item -ItemType 'Directory' -Path $dir | Out-Null}
      $OneDriveEXE = Get-Item -Path "$env:SystemDrive\Installs\OneDrive\OneDriveSetup.exe"
      Copy-Item -Path "$OneDriveEXE" -Destination "$dir"
    
      $dir = "$VHDVolume\Installs\VS Code"; try {Get-Item -Path $dir -ErrorAction 'Stop' | Out-Null} catch {New-Item -ItemType 'Directory' -Path $dir | Out-Null}
      $VSCodeEXE = Get-Item -Path "$env:SystemDrive\Installs\VSCodeSetup-x64-*.exe"
      Copy-Item -Path "$VSCodeEXE" -Destination "$dir"
    
      # I am aware that this is here twice. 
      $dir = "$VHDVolume\Installs"; try {Get-Item -Path $dir -ErrorAction 'Stop' | Out-Null} catch {New-Item -ItemType 'Directory' -Path $dir | Out-Null}
      $dir = "$dir\PowerShell 7"; try {Get-Item -Path $dir -ErrorAction 'Stop' | Out-Null} catch {New-Item -ItemType 'Directory' -Path $dir | Out-Null}
      $pwsh7MSI = Get-ChildItem -Path "$env:SystemDrive\Installs\PowerShell 7" -Filter "PowerShell*x64.msi" -Recurse | Sort-Object LastWriteTime | Select-Object -Last 1
      Copy-Item -Path "$pwsh7MSI" -Destination "$dir" -Force    
    }
  
    Dismount-DiskImage -ImagePath ${Guest OS Disk Path} | Out-Null
    Start-VM -Name $using:Name0fVM | Out-Null
    return $using:Name0fGuestOS
  }

  #return ${Instance %HostName%} #  $WhyDoesntThisFuckingWork
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


function New-Server2025ReferenceVHDXviaPowerShellRemoting { # Constructs a reference VHDX file of Windows Server 2025 |
  [CmdletBinding()]
  param (
    [Parameter(
      HelpMessage = "Supply 1 of the 4 editions of Windows Server: Datacenter, DatacenterDesktopExperience, Standard, or StandardDesktopExperience",
      Position = 0, 
      ValueFromPipelineByPropertyName = $False
    )]
    [ValidateSet('Standard','StandardDesktopExperience','Datacenter','DatacenterDesktopExperience')]
    [string]
    $Edition = 'Standard'
  )

  <# Trials |
    $Edition = 'Standard'
    $Edition = 'StandardDesktopExperience'
    $Edition = 'Datacenter'
    $Edition = 'DatacenterDesktopExperience'
  #>
  
  $StartTime = Get-Date

  <# There's no point to defining such a directory |
        @(
          "$((Get-VMHost).VirtualHardDiskPath)\Images",
          "$((Get-VMHost).VirtualHardDiskPath)\Images\Windows Server 2025"
        ) | ForEach-Object {
            $dir = $_ # Try replacing the $dir inside the try-catch blocks with $_... errors result. Wasted appx 2 hours on this. 
              try {
                Get-Item -Path $dir -ErrorAction 'Stop' > $null
              }
              catch {
                New-Item -Path $dir -ItemType 'Directory'
              }
            }
  #>

  <# Aspirations |
    Write a logical tree that crawls through persistent storage, removable media, and 
    network shares in search of .iso file. Dont use filenames. 
    Calculate the .iso file's SHA-256 hash. 
    If found, copy to $hvVol
    And if not found, the code should download Server 2025 from the web. 
    - How to query from Microsoft the SHA-256 has of the latest version of an OS?
    - We might have to consider Cultures outside of en-us. 

    My weak 1st attempt at the above: 
    #try {
    #  ${Iso File Path} = Get-Item -Path "$((Get-VMHost).VirtualHardDiskPath)\${Latest Server 2025}.iso" -ErrorAction 'Stop' | Select-Object -ExpandProperty 'FullName'
    #}
    #catch {
    #  try {
    #    $smb = Get-PSDrive -Name 'OS' -PSProvider 'FileSystem' -ErrorAction 'Stop'
    #  }
    #  catch {
    #    Write-Output "`r`n  Supply username & password of this PowerShell Remoting session to temporarily create the new PSDrive and download the .iso file:`r`n"
    #    $smb = New-PSDrive -Name 'OS' -PsProvider 'FileSystem' -Root "\\UcFC\OS" -Credential (Get-Credential)
    #  }
    #  Copy-Item -Path "\\UcFC\OS\${Latest Server 2025}.iso" -Destination "$((Get-VMHost).VirtualHardDiskPath)" -Force
    #  ${Iso File Path} = Get-Item -Path "$((Get-VMHost).VirtualHardDiskPath)\${Latest Server 2025}.iso" | Select-Object -ExpandProperty 'FullName'
    #}  
  #>
 
  ${Iso File Path} = Get-Item -Path "$((Get-VMHost).VirtualHardDiskPath)\${Latest Server 2025}.iso" | Select-Object -ExpandProperty 'FullName'

  switch ($Edition) {
    'Standard' {
      ${Reference VHDX Path} = "$((Get-VMHost).VirtualHardDiskPath)\Server 2025 Standard ${Latest Server 2025}.vhdx"
      break
    }
    'StandardDesktopExperience' {
      ${Reference VHDX Path} = "$((Get-VMHost).VirtualHardDiskPath)\Server 2025 Standard with Desktop Experience ${Latest Server 2025}.vhdx"
      break
    }
    'Datacenter' {
      ${Reference VHDX Path} = "$((Get-VMHost).VirtualHardDiskPath)\Server 2025 Datacenter ${Latest Server 2025}.vhdx"
      break
    }
    'DatacenterDesktopExperience' {
      ${Reference VHDX Path} = "$((Get-VMHost).VirtualHardDiskPath)\Server 2025 Datacenter with Desktop Experience ${Latest Server 2025}.vhdx"
      break
    }
    default {'This should never appear because the ValidateSet PVA already guards against rogue input'}
  }

  if (
    Test-Path -Path $env:WinDir\System32\MBR2GPT.exe
  ) {
    ${Mounted Image Letter} = (Mount-DiskImage -ImagePath ${Iso File Path} | Get-DiskImage | Get-Volume | Select-Object -ExpandProperty 'DriveLetter') + ':'
    #${Mounted Image Letter} = $(Mount-DiskImage -ImagePath ${Iso File Path} | Get-DiskImage | Get-Volume | Select-Object -ExpandProperty 'DriveLetter') + ':'
    # Small size deliberately chosen because _THE C: SHOULD ONLY CARRY SYSTEM FILES!!_
    New-VHD -Path ${Reference VHDX Path} -SizeBytes 50GB -Dynamic > $null
    # Would you fucking believe that the shit bombs out if you write something like 73.2GB?! 
    ${Mounted Ref VHDX Disk #} = Mount-DiskImage -ImagePath ${Reference VHDX Path} | Get-DiskImage | Get-Disk | Select-Object -ExpandProperty 'Number'
    Initialize-Disk -Number ${Mounted Ref VHDX Disk #} -PartitionStyle 'MBR'
    ${Mounted Ref VHDX Letter} = (New-Partition -DiskNumber ${Mounted Ref VHDX Disk #} -AssignDriveLetter -UseMaximumSize -IsActive | Format-Volume -FileSystem 'NTFS' -Confirm:$False | Select-Object -ExpandProperty 'DriveLetter') + ':'
  
    switch ($Edition) {
      'Standard'                    {
        Dism.exe /apply-Image /ImageFile:"${Mounted Image Letter}\Sources\install.wim" /Index:1 /ApplyDir:"${Mounted Ref VHDX Letter}\"     # > $null
        break
      }
      'StandardDesktopExperience'   {
        Dism.exe /apply-Image /ImageFile:"${Mounted Image Letter}\Sources\install.wim" /Index:2 /ApplyDir:"$(${Mounted Ref VHDX Letter})\"    # > $null
        break
      }
      'Datacenter'                  {
        Dism.exe /apply-Image /ImageFile:"${Mounted Image Letter}\Sources\install.wim" /Index:3 /ApplyDir:"${Mounted Ref VHDX Letter}\"     # > $null
        break
      }
      'DatacenterDesktopExperience' {
        Dism.exe /apply-Image /ImageFile:"${Mounted Image Letter}\Sources\install.wim" /Index:4 /ApplyDir:"$(${Mounted Ref VHDX Letter})\"    # > $null
        break
      }
      default                       {'This should never appear because the ValidateSet PVA already guards against rogue input'}
    }
  
    bcdboot.exe ${Mounted Ref VHDX Letter}\Windows /s ${Mounted Ref VHDX Letter} /f BIOS
    MBR2GPT.EXE /Convert /Disk:${Mounted Ref VHDX Disk #} /allowFullOs  
    Dismount-DiskImage -ImagePath ${Iso File Path} | Out-Null
    Dismount-DiskImage -ImagePath ${Reference VHDX Path} | Out-Null  
  } 
  #else {
  #  try {
  #    $smb = Get-PSDrive -Name 'OS' -PSProvider 'FileSystem' -ErrorAction 'Stop'
  #  }
  #  catch {
  #    Write-Output "`r`n  Supply username & password of this PowerShell Remoting session to temporarily create the new PSDrive and download the .vhdx file:`r`n"
  #    $smb = New-PSDrive -Name 'OS' -PsProvider 'FileSystem' -Root "\\UcFC\OS" -Credential (Get-Credential)
  #  }
  #  ${Reference VHDX} = New-Item -ItemType 'File' -Path ${Reference VHDX Path}
  #  Copy-Item -Path "\\UcFC\OS\$(${Reference VHDX}.Name)" -Destination (Get-VMHost).VirtualHardDiskPath -Force
  #}

  $EndTime = Get-Date
  write "Duration: $(($EndTime - $StartTime).Minutes)m$(($EndTime - $StartTime).Seconds)s"
}

function Resolve-ADComputer {
  [OutputType('Microsoft.ActiveDirectory.Management.ADComputer')]

  param (
    [Parameter(Mandatory)]
    [string]
    $cname
  )

  ${Resolved Cname} = Resolve-DnsName -Name $cname -Type 'cname' | Select-Object -ExpandProperty 'NameHost'

  # I hate resorting to regular expressions to isolate the %ComputerName%, but I don't see any way to get the DnsNameHost attribute of an AD Computer object from the corresponding cname 
  ${regex DNS Name of Windows Host} = [System.Text.RegularExpressions.Regex]"^(?<Host_Name>(?!(\d{1,15}|w11|w11Pro|w11Pro4WS|s22|s22desk|s22std|s22stddt|ANONYMOUS|BATCH|BUILTIN|DIALUP|DOMAIN|ENTERPRISE|INTERACTIVE|INTERNET|LOCAL|NETWORK|NULL|PROXY|RESTRICTED|SELF|SERVER|SERVICE|SYSTEM|USERS|WORLD)$)[A-Za-z0-9][A-Za-z0-9-]{1,13}[A-Za-z0-9])\.(?<AD_DNS>.+)$"
  ${Resolved Cname} -match ${regex DNS Name of Windows Host} > $null
  Get-ADComputer -Identity $Matches['Host_Name']
}

function New-LinuxVM {
  param (
    [Parameter(
      Mandatory,
      HelpMessage = "Yes, even if work is being performed while locally logged into a node of a Hyper-V cluster, a PowerShell Remoting session is still required."
    )]
    [Alias('sess')]
    [System.Management.Automation.Runspaces.PSSession]
    $PowerShellRemotingSession,

    [Parameter(
      ValueFromPipelineByPropertyName = $true
    )]
    [ValidateSet(
      'Kali','Ubuntu','SELinux'
    )]
    [string]
    $Distro = 'Kali',

    [Parameter(
      HelpMessage = "Name of the virtual machine, which does NOT need to match the name of the guest OS!"
    )]
    [string]
    $Name0fVM = ('Hyper-V VM ' + ([System.IO.Path]::GetRandomFileName()) -replace '\.','' -join '').ToUpper(),

    [Parameter(
      HelpMessage = "Two virtual CPUs should be enough"
    )]
    [Int32]
    $cpu = 2,

    [Parameter(
      HelpMessage = "Set Metasploitable Linux as a Generation 1 VM"
    )]
    [Int32]
    $gen = 2,

    [Parameter(
      HelpMessage = "Default quantity of RAM assigned to the VM is 1/8 total physical RAM, so install the maximum amount on your Hyper-V hosts!"
    )]
    [int64]
    $ram = [math]::Round(${Computer Info Lite}.RAM/(8*1024*1024)/2,0)*2MB,
    
    [Parameter(
      HelpMessage = "I suspect that uniquely naming Hyper-V virtual switches (on a per-host basis) isn't necessary or desirable... and maybe it's not even practical!"
    )]
    [ValidateSet(
      'SET-enabled External vSwitch','vSwitchNAT','VLAN-enabled External vSwitch','Isolated vSwitch'
    )]
    [string]
    $net = "SET-enabled External vSwitch",

    [Parameter(
      HelpMessage = "Make sure the Hyper-V host has tons of RAM"
    )]
    [ValidateSet(
      'StartIfRunning','Start','Nothing'
    )]
    [string]
    $ActionWhenBareMetalHostBoots = 'Nothing',
    
    [Parameter(
      HelpMessage = "No need to right-click each row in Hyper-V Manager and select Shut Down."
    )]
    [ValidateSet(
      'Save','TurnOff','Shutdown'
    )]
    [string]
    $ActionOnBareMetalHostShutdown = 'Shutdown',
    
    [ValidateRange(1,100)]
    [Int32]
    $Buffer = 20,
    
    [ValidateSet(
      'Disabled','Production','ProductionOnly','Standard'
    )]
    [string]
    $CheckpointType = 'Disabled',

    [ValidateSet(
      'Pause','None'
    )]
    [string]
    $StorageDisconnectedAction = 'Pause',

    [int32]
    $HwThreadCountPerCore = '1',

    [Parameter(
      HelpMessage = "Migration between AMD & Intel doesn't appear to be supported!"
    )]
    [Alias('LivMigCompat')]
    [boolean]
    $IsVmCompatibleAcrossDifferentProcessorSKUsOfASingleCompany = $false,

    [Parameter(
      HelpMessage = "Connect to VLAN for Workloads by default. Connecting a vNIC to the Migration (14) or Storage (16) networks doesn't make any sense."
    )]
    [ValidateSet(
      10,12
    )]
    [int32]
    $VlanID = 12,

    [Parameter(
      Mandatory,
      HelpMessage = "New policy going forward: A note is required for each VM.`r`nFor more information, visit`r`n  https://www.altaro.com/hyper-v/vm-notes-powershell/"
    )]
    [string]
    $Notes
  )

  Invoke-Command -Session $PowerShellRemotingSession -ScriptBlock {
    $RedirectedError = $(
      ${Does This VM Already Exist?} = Get-VM -Name $using:Name0fVM
    ) 2>&1
    if (${Does This VM Already Exist?}) {
      Write-Host -ForegroundColor 'DarkRed' -Object "A virtual machine of that name already exists"
      break
    }

    switch ($using:Distro) {
      'Kali' {break}
      'Ubuntu' {write-host 'Uncover how to prepare a linux vhdx file'; break}
      'SELinux' {write-host 'Uncover how to prepare a linux vhdx file'; break}
      default {exit}
    }
      
    ${Current VM Version} = [double[]](Get-VMHost).SupportedVmVersions | Sort-Object | Select-Object -Last 1
    ${Current VM Version} = (Get-VMHost).SupportedVmVersions | Where-Object {$_ -match ${Current VM Version}}
    
    $HT = @{
      Name               = $using:Name0fVM
      ComputerName       = $env:ComputerName
      Generation         = 2
      MemoryStartupBytes = $using:ram
      Version            = ${Current VM Version}
    }
    try {${New VM} = Get-VM -Name $HT.Name -ErrorAction 'Stop'} catch {${New VM} = New-VM @HT}
  
    # Create a copy of the .vhdx file located at ${Base VHD Path}. Filename begins with name of VM and then the VM id. 
    ${Base VHDX Path} = "$((Get-VMHost).VirtualHardDiskPath)\kali-linux-2024.4-hyperv-amd64.vhdx"
    ${Guest OS Disk Path} = "$((Get-VMHost).VirtualHardDiskPath)\$(${New VM}.Name) $(${New VM}.Id).vhdx"
    Copy-Item -Path ${Base VHDX Path} -Destination ${Guest OS Disk Path}

    # Attach VHD containing Guest OS to VM |
    $HT = @{
      VMName             = $using:Name0fVM
      Path               = ${Guest OS Disk Path}
      ControllerType     = 'SCSI'
      ControllerLocation = '0'
      ControllerNumber   = '0'
    }
    Add-VMHardDiskDrive @HT

    $HT = @{
      VMName = $using:Name0fVM
      ControllerType     = 'SCSI'
      ControllerLocation = '0'
      ControllerNumber   = '0'
    }
    ${Hyper-V HDD-Guest OS} = Get-VMHardDiskDrive @HT

    $HT = @{ # Set memory quantity & behavior of VM |
      VMName               = $using:Name0fVM
      DynamicMemoryEnabled = $True
      MinimumBytes         = 256MB
      MaximumBytes         = $using:ram
      Buffer               = $using:Buffer
    }
    Set-VMMemory @HT

    Set-VM -Name $using:Name0fVM -EnhancedSessionTransportType 'HVSocket'
    Enable-VMIntegrationService -VMName $using:Name0fVM -Name 'Guest Service Interface'
    Disable-VMIntegrationService -VMName $using:Name0fVM -Name 'Heartbeat'
    Disable-VMIntegrationService -VMName $using:Name0fVM -Name 'Key-Value Pair Exchange'
    Disable-VMIntegrationService -VMName $using:Name0fVM -Name 'Shutdown'
    Disable-VMIntegrationService -VMName $using:Name0fVM -Name 'Time Synchronization'
    Disable-VMIntegrationService -VMName $using:Name0fVM -Name 'VSS'
    
    $HT = @{ # Quantity of vCPUs |
      VMName = $using:Name0fVM
      Count  = $using:cpu
    }
    Set-VMProcessor @HT

    $HT = @{ # Constrain physical CPU resources available to a VM's virtual processors |
      VMName  = $using:Name0fVM
      Reserve = '0'
      Maximum = '100'
    }
    Set-VMProcessor @HT  

    $HT = @{ # Prioritize access to physical CPU resources across VMs | Default value is 100. Since urgency is measured by "weight" and not "priority", a greater number reflects greater importance. |
      VMName         = $using:Name0fVM
      RelativeWeight = '100'
    }
    Set-VMProcessor @HT  

    $HT = @{ # 'Enable Auto-Throttle on a VM’s CPU Access' # Allegedly, Microsoft does not fully document what this controls |
      VMName                       = $using:Name0fVM
      EnableHostResourceProtection = $True
    }
    Set-VMProcessor @HT  

    $HT = @{ # | code "$knet\#scripts#\NuS25W11VMs\NuS25W11VMs.psm1" | Search for 'CompatibilityForMigrationEnabled' for why we set the value to false | UPDATE 2024-12-27: Migration between AMD & Intel isn't allowed by default! |
      VMName                           = $using:Name0fVM
      CompatibilityForMigrationEnabled = $using:IsVmCompatibleAcrossDifferentProcessorSKUsOfASingleCompany
    }
    Set-VMProcessor @HT  

    $HT = @{ # I think that HwThreadCountPerCore = 1 means that NUMA is not enabled _FOR THE VM_ | NUMA can still be enabled at they Hyper-V host level | HwThreadCountPerCore = 0 means to inherit the host's settings for 'hardware threads per core'
      VMName               = $using:Name0fVM
      HwThreadCountPerCore = $using:HwThreadCountPerCore
    }
    Set-VMProcessor @HT  

    $HT = @{ # Automatic Start Action | Automatic Start Delay | Automatic Stop Action |
      Name                 = $using:Name0fVM
      AutomaticStartAction = $using:ActionWhenBareMetalHostBoots
      AutomaticStopAction  = $using:ActionOnBareMetalHostShutdown
      AutomaticStartDelay  = $(60 * ((Get-VM).Count - 1))
    }
    Set-VM @HT

    $HT = @{ # Firmware settings |
      VMName           = $using:Name0fVM
      FirstBootDevice  = ${Hyper-V HDD-Guest OS}
      EnableSecureBoot = 'Off'
    }
    Set-VMFirmware @HT
  
    if ($using:CheckpointType -ne 'Disabled') {
      Set-VM -Name $using:Name0fVM -AutomaticCheckpointsEnabled $true
      Set-VM -Name $using:Name0fVM -CheckpointType $using:CheckpointType
    } 
    else {
      Set-VM -Name $using:Name0fVM -AutomaticCheckpointsEnabled $false
      Set-VM -Name $using:Name0fVM -CheckpointType $using:CheckpointType
    }
    
    Set-VM -VMName $using:Name0fVM -AutomaticCriticalErrorAction $using:StorageDisconnectedAction -AutomaticCriticalErrorActionTimeout 120

    Set-VM -VMName $using:Name0fVM -Notes $using:Notes

    ((Get-VMSwitch $using:net).EmbeddedTeamingEnabled) ? 
    (& {
      Get-VMNetworkAdapter -Name "Network Adapter" -VMName $using:Name0fVM | Rename-VMNetworkAdapter -NewName "Network Adapter-SET"
      $global:vNIC = Get-VMNetworkAdapter -Name "Network Adapter-SET" -VMName $using:Name0fVM
    }) : ($global:vNIC = Get-VMNetworkAdapter -Name "Network Adapter" -VMName $using:Name0fVM)

    Connect-VMNetworkAdapter -Name $vNIC.Name -VMName $using:Name0fVM -SwitchName $using:net
    Set-VMNetworkAdapter -Name $vNIC.Name -VMName $using:Name0fVM -MacAddressSpoofing 'On'
    Set-VMNetworkAdapterVlan -VMName $using:Name0fVM -VMNetworkAdapterName $vNIC.Name -Access -VlanId $using:VlanID

    Start-VM -Name $using:Name0fVM | Out-Null
  }
}

function Safeguard-OneDrive {
  [CmdletBinding()]
  param ()

  # 256 GB Samsung FIT flash drive: 

  $SamsungFITdisk = Get-Disk | Select-Object * | ? {($_.FriendlyName -eq "Samsung Flash Drive FIT") -and ($_.UniqueId -match 'USBSTOR\\DISK&VEN_SAMSUNG&PROD_FLASH_DRIVE_FIT&REV_1100\\0330123070003679&0') -and ($_.SerialNumber -eq 'AA00000000000489')}

  if(!($SamsungFITdisk -eq $null)) {$SamsungFITpart = Get-Partition -DiskNumber $SamsungFITdisk.Number | Select-Object -First 1; $FIT = [string]$SamsungFITpart.DriveLetter + ":"}

  $dir = New-Item -ItemType Directory -Path "$FIT\od\$(Call-DateVar2)"
  
  Copy-Item -Path "$env:SystemDrive\Users\${explorer.exe Owner}\OneDrive\iddqd" -Destination "$dir" -Recurse
  Copy-Item -Path "$env:SystemDrive\Users\${explorer.exe Owner}\OneDrive\IT" -Destination "$dir" -Recurse
  Copy-Item -Path "$env:SystemDrive\Users\${explorer.exe Owner}\OneDrive\IT1" -Destination "$dir" -Recurse
  Copy-Item -Path "$env:SystemDrive\Users\${explorer.exe Owner}\OneDrive\knet" -Destination "$dir" -Recurse
}



