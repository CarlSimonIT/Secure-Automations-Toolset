function New-PasswordForNonAccounts {
  [CmdletBinding()]
  param (
    [Parameter(
      Mandatory = $true,
      Position = 0,
      ValueFromPipelineByPropertyName = $true,
      HelpMessage = "The Title of the non-account password or secret."
    )]
    [System.String]
    [Alias('ot')]
    $ObjectTitle,
    
    [Parameter(
      Mandatory = $true,
      Position = 1,
      ValueFromPipelineByPropertyName = $true,
      HelpMessage = "FolderId of Item object in Bitwarden Vault. While Bitwarden allows an Item to sit in the 'No Folder' container, this project requires that all Bitwarden Items occupy a Bitwarden Folder."
    )]
    [ValidatePattern(
      '^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$'
    )]
    [ValidateNotNullOrEmpty()]
    [System.String]
    [Alias('fid')]
    $FolderId,

    [Parameter(
      Mandatory = $false, 
      HelpMessage = "`r`nThe length of the non-account password or secret."
    )]    
    [ValidateRange(32,96)]
    [System.UInt32]
    [Alias('len')]
    $PasswordLength = 64,

    [Parameter(
      Mandatory = $false, 
      HelpMessage = "Email address of Bitwarden account. TIP: Use the `$PSDefaultParameterValues automatic variable to avoid repetitive input"
    )]
    [ValidatePattern(
      '^[a-z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{2,}$'
    )]
    [System.String]
    [Alias('email')]
    $EmailAddressOfBitwardenAccount,

    [Parameter(
      Mandatory = $false, 
      HelpMessage = "Insert the -CheckAuthenticationStatus switch parameter (aliased to -Check) to verify Bitwarden CLI is still authenticated into Bitwarden Account."
    )]
    [System.Management.Automation.SwitchParameter]
    [Alias('Check')]
    $CheckAuthenticationStatus, 

    [Parameter(
      Mandatory = $false, 
      HelpMessage = "Set `$VerboseAuthenticationChecking = `$true to see logic behind decision tree that for confirming that 'status' = 'unlocked'."
    )]
    [System.Boolean]
    [Alias('va')]
    $VerboseAuthenticationChecking = $false, 

    [Parameter(
      Mandatory = $false, 
      HelpMessage = "Set `$VerboseVerification = `$true to see logic behind decision tree that validates user input."
    )]
    [System.Boolean]
    [Alias('vv')]
    $VerboseVerification = $false,

    [Parameter(
      Mandatory = $false, 
      HelpMessage = "Misc notes you can write about this Item into the Bitwarden Account."
    )]
    [AllowEmptyString()]
    [ValidateNotNull()]
    [System.String]
    $Notes = ""
  )

  Write-Host -Object "<>|<>|<>|<>|Start $($PSCmdlet.MyInvocation.InvocationName) for '$ObjectTitle'|<>|<>|<>|<>" -ForegroundColor ([System.ConsoleColor]::Magenta)
  $time_Begin = Get-Date

  Write-Verbose -Message "Jumping into Set-PrerequisiteConditions from $($PSCmdlet.MyInvocation.InvocationName)"
  Set-PrerequisiteConditions
  Write-Verbose -Message "Returning from Set-PrerequisiteConditions into $($PSCmdlet.MyInvocation.InvocationName)"

  if ($CheckAuthenticationStatus) {
    $HT = @{
      email   = $EmailAddressOfBitwardenAccount
      Verbose = $VerboseAuthenticationChecking
    }
    _CheckBitwardenVaultAuthenticationStatus
  }
  $HT = @{
    ItemLoginUsername = $ObjectTitle
    FolderId          = $FolderId
    Verbose           = $VerboseVerification
  }
  $IsPresent = _VerifyExactBitwardenItemExistence @HT

  #region | Exit function if $IsPresent = $true |
  $time_End = Get-Date
  if ($IsPresent) {
    Write-Warning -Message "`nExiting function $($PSCmdlet.MyInvocation.InvocationName) because Bitwarden Item with`n  Login.Username = $([System.Char]39)$ObjectTitle$([System.Char]39)`nand `$FolderId = $([System.Char]39)$FolderId$([System.Char]39) is already present.`n`tVerification duration:`n`t  $(($time_End - $time_Begin).TotalSeconds.ToString('n3')) Seconds`n"
    #break
  } 
  else {
    Write-Verbose -Message "Verification duration:  $(($time_End - $time_Begin).TotalSeconds.ToString('n3')) Seconds`n"
    #region | Item creation after confirmation that $IsPresent = $false |
    Write-Verbose -Message "New Bitwarden object where Item.Login.Username = $([System.Char]39)$ObjectTitle$([System.Char]39)`nin Bitwarden Folder with id = $FolderID`:"
    #region | Calculate value of Name attribute for the Bitwarden Item |
    Write-Verbose -Message "Initialize new variable for referencing the Name attribute of an Item object in the Bitwarden Vault"
    $_Var_Name = 'Bitwarden Vault Item-Name'
    try {Clear-Variable -Name $_Var_Name -ErrorAction 'Stop'} catch {New-Variable -Name $_Var_Name -Value $null}

    Write-Verbose -Message "Calcualte the first 52 numbers & letters of the SHA-512 hash of `$ObjectTitle. Convert to lowercase and assign as the Value of this PowerShell variable."
    ${Bytes UTF8}    = [System.Text.Encoding]::UTF8.GetBytes($ObjectTitle.ToLower())
    ${Bytes SHA512}  = [System.Security.Cryptography.SHA512CryptoServiceProvider]::New().ComputeHash(${Bytes UTF8})
    $Base64String    = [System.Convert]::ToBase64String(${Bytes SHA512}).ToLower() -replace '\W',''
    Set-Variable -Name $_Var_Name -Value ($Base64String.SubString(0,52))
    #endregion

    Write-Verbose -Message "Initialize new variable for referencing the Username attribute of the Login attribute of an Item object in the Bitwarden Vault"
    $_Var_Name = 'Bitwarden Vault Item-Login.Username'
    try {Clear-Variable -Name $_Var_Name -ErrorAction 'Stop'} catch {New-Variable -Name $_Var_Name -Value $null}

    Write-Verbose -Message "Set that variable value equal to the $ObjectTitle that the user supplied."
    Set-Variable -Name $_Var_Name -Value ($ObjectTitle)
    
    Write-Verbose -Message "Generate a password in clear text"
    $_Var_Name = 'Bitwarden Vault Item-Login.Password In Clear-Text'
    try {Clear-Variable -Name $_Var_Name -ErrorAction 'Stop'} catch {New-Variable -Name $_Var_Name -Value $null}
    Set-Variable -Name $_Var_Name -Value ($(bw.exe generate -lusn --length $PasswordLength))

    $_Var_Name = 'Bitwarden Vault Item-Notes'
    try {Clear-Variable -Name $_Var_Name -ErrorAction 'Stop'} catch {New-Variable -Name $_Var_Name -Value $null}
    Set-Variable -Name $_Var_Name -Value ($Notes)
    
    # Save to separate variables the properties of the object that will eventually be used to define a new Item in Bitwarden Password Manager
    #region | Item Name |
    ${bw item-name}             = '.name="%Bw_Item_Name%"' -replace '%Bw_Item_Name%',${Bitwarden Vault Item-Name}
    #endregion
    #region | Item Login |
    ${bw item-login.username}   = '.login.username="%Bw_Item_Login_Username%"' -replace '%Bw_Item_Login_Username%',${Bitwarden Vault Item-Login.Username}
    ${bw item-login.password}   = '.login.password="%Bw_Item_Login_Password%"' -replace '%Bw_Item_Login_Password%',${Bitwarden Vault Item-Login.Password In Clear-Text}
    #endregion
    #region | Item Notes |
    if (${Bitwarden Vault Item-Notes}.Length -eq 0) {
      ${bw item-notes} = '.notes="%Item_Notes%"' -replace '%Item_Notes%',""
    }
    else {
      ${bw item-notes} = '.notes="%Item_Notes%"' -replace '%Item_Notes%',${Bitwarden Vault Item-Notes}
    }
    #endregion
    #region | Item FolderID |
    ${bw item-folderId} = '.folderId="%Item_FolderId%"' -replace '%Item_FolderId%',$FolderId
    #endregion  

    Write-Verbose -Message "With the attributes of the Item now saved to variable, write that Item into the Bitwarden Vault."
    bw.exe get template item | jq.exe ${bw item-name} | jq.exe ${bw item-login.username} | jq.exe ${bw item-login.password} | jq.exe ${bw item-notes} | jq.exe ${bw item-folderId} | bw.exe encode | bw.exe create item > $null
    Write-Verbose -Message "Write Operation Complete"

    $time_End = Get-Date
    Write-Verbose -Message "Wait time on object $ObjectTitle`:`n`t`t$(($time_End - $time_Begin).TotalSeconds.ToString('n3')) Seconds`n"
    #endregion
  }
  #endregion

  Write-Host -Object "<>|<>|<>|<>|End $($PSCmdlet.MyInvocation.InvocationName) for '$ObjectTitle'|<>|<>|<>|<>" -ForegroundColor ([System.ConsoleColor]::Magenta)
}