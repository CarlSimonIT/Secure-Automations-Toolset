function New-BitwardenVaultFolder {
  [CmdletBinding()]
  param (
    [Parameter(
      Mandatory = $true,
      Position = 0,
      ValueFromPipelineByPropertyName = $true,
      HelpMessage = "Fully qualified folder name in Bitwarden. `n`tstart msedge.exe 'https://bitwarden.com/help/folders/#tab-cli-4YoIIiIv67T68BdhWdAwOM'"
    )]
    [ValidateNotNullOrEmpty()]
    [System.String]
    $Name,

    [Parameter(
      Mandatory = $false, 
      Position = 1,
      HelpMessage = "Email address of Bitwarden account. TIP: Use the `$PSDefaultParameterValues automatic variable to avoid repetitive input"
    )]
    [Alias('email')]
    [ValidatePattern(
      '^[a-z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{2,}$'
    )]
    [System.String]
    $EmailAddressOfBitwardenAccount,
    
    [Parameter()]
    [Alias('Check')]
    [System.Management.Automation.SwitchParameter]
    $CheckAuthenticationStatus,

    [Parameter(
      Mandatory = $false, 
      HelpMessage = "Set `$VerboseAuthenticationChecking = `$true to see logic behind decision tree that for confirming that 'status' = 'unlocked'."
    )]
    [System.Boolean]
    [Alias('va')]
    $VerboseAuthenticationChecking = $false
  )

  $time_Begin = Get-Date

  Write-Verbose -Message "Jumping into Set-PrerequisiteConditions from $($PSCmdlet.MyInvocation.InvocationName)"
  #${explorer.exe Owner} = Import-CliXml -Path "$PSScriptRoot\..\..\.CommonItems\explorer.exe Owner.clixml"
  ${explorer.exe Owner} = Import-CliXml -Path "${env:.CommonItems}\explorer.exe Owner.clixml"
  #Set-PrerequisiteConditions -Verbose
  $HT = @{
    'explorer.exe Owner' = ${explorer.exe Owner}
    Verbose              = $true
  }
  Set-PrerequisiteConditions @HT
  Write-Verbose -Message "Returning from Set-PrerequisiteConditions into $($PSCmdlet.MyInvocation.InvocationName)"

  if ($CheckAuthenticationStatus) {
    $HT = @{
      email   = $EmailAddressOfBitwardenAccount
      Verbose = $VerboseAuthenticationChecking
    }
    _CheckBitwardenVaultAuthenticationStatus
  }

  #region | Verification of Folder object in the Bitwarden vault |
  Write-Verbose -Message "Verification of Folder object in the Bitwarden vault"
  $_Var_Name = 'IsFolderPresent'
  try {Clear-Variable -Name $_Var_Name -ErrorAction 'Stop'} catch {New-Variable -Name $_Var_Name -Value $null}

  $EscapedName = [System.Text.RegularExpressions.Regex]::Escape($Name)
  $AnchoredEscapedName = '^' + $EscapedName + '$'

  ${Bitwarden Folders JSON} = bw.exe list folders
  ${Bitwarden Folders} = ${Bitwarden Folders JSON} | ConvertFrom-Json
  ${Bitwarden Folder} = ${Bitwarden Folders} | Where-Object -FilterScript {$_.Name -match $AnchoredEscapedName}

  switch (${Bitwarden Folder}.Count) {
    {$_ -eq 0} {$IsFolderPresent = $false}
    {$_ -eq 1} {$IsFolderPresent = $true}
    {$_ -ge 2} {
      $time_End = Get-Date
      Write-Error -Message "`n`tThis is bad.`n`tTwo or more folders share the exact same case-insensitive name $Name.`n`t  Log into your Bitwarden Vault and delete all but one of these folders.`n`tVerification duration:`n`t  $(($time_End - $time_Begin).TotalSeconds.ToString('n3')) Seconds`n"
      pause
      exit
    }
  }
  #endregion

  #region | exit if $IsFolderPresent = $true |
  if ($IsFolderPresent) {
    Write-Verbose -Message "exiting because `$IsFolderPresent = `$true"
    $time_End = Get-Date

    Write-Information -Message "`n`tBitwarden Folder with`n`t  Name = $([System.Char]39)$Name$([System.Char]39)`n`tis already present.`n`tVerification duration:`n`t  $(($time_End - $time_Begin).TotalSeconds.ToString('n3')) Seconds`n"

    return ${Bitwarden Folder}.id
    
    break
  }
  #endregion

  #region | Define Bitwarden Folder object if $IsFolderPresent = $false |
  Write-Verbose -Message "Initialize new variable for referencing the Name attribute a Folder object in the Bitwarden Vault"
  $_Var_Name = 'Bitwarden Vault Folder-Name'
  try {Clear-Variable -Name $_Var_Name -ErrorAction 'Stop'} catch {New-Variable -Name $_Var_Name -Value $null}
  
  Write-Verbose -Message "Save to variable the property of the object that will eventually be used to define a new Folder in Bitwarden Password Manager"
  #region | Folder Name |
  ${Bitwarden Vault Folder-Name} = $Name
  ${bw folder-name}              = '.name="%Bw_folder_Name%"' -replace '%Bw_folder_Name%', ${Bitwarden Vault Folder-Name}
  #endregion

  Write-Verbose -Message "With the attributes of the Folder now saved to variable, write that Folder into the Bitwarden Vault."
  bw.exe get template folder | jq.exe ${bw folder-name} | bw.exe encode | bw.exe create folder | ConvertFrom-Json | Select-Object -ExpandProperty 'id'
  Write-Verbose -Message "Write Operation Complete"

  $time_End = Get-Date
  Write-Verbose -Message "Wait time on creation of folder $Name`:`n`t`t$(($time_End - $time_Begin).TotalSeconds.ToString('n3')) Seconds`n"
  #endregion
}
