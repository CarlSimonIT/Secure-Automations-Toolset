function _VerifyExactBitwardenItemExistence {
  [CmdletBinding()]
  param (
    [Parameter(
      Mandatory = $true,
      Position = 0,
      HelpMessage = "Value of the Login.Username attribute for the Item object in the Bitwarden Vault."
    )]
    [System.String]
    [Alias('ilu')]
    $ItemLoginUsername,
    
    [Parameter(
      Mandatory = $true,
      Position = 1,
      HelpMessage = "FolderId of Item object in Bitwarden Vault. Leave blank to indicate No Folder, which corresponds to `$FolderId = `$null."
    )]
    [ValidatePattern(
      '^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$'
    )]
    [System.String]
    [Alias('fid')]
    $FolderId
  )

  ${time_Begin _VerifyExactBitwardenItemExistence} = [System.DateTime]::Now

  Write-Verbose -Message "Verification of Item objects in the Bitwarden vault"
  Write-Verbose -Message "Initialize `$IsBitWardenItemPresent variable."
  $_Var_Name = 'IsBitWardenItemPresent'
  #try {Clear-Variable -Name $_Var_Name -ErrorAction 'Stop'} catch {New-Variable -Name $_Var_Name -Value $null}
  try {
    Clear-Variable -Name $_Var_Name -ErrorAction 'Stop'
  } 
  catch {
    New-Variable -Name $_Var_Name -Value $null -Scope 'Script'
  }

  <#
    $ItemLoginUsername = 'Global Cert Signer'
    $ItemLoginUsername = 'Global Cert Signer side-project-0'
    $ItemLoginUsername = 'Global Cert Signer side-project-1'
    $ItemLoginUsername = "PFX file password for CA certificate exported from Nowhere"
    $ItemLoginUsername = 'Global Cert Signer side-project-2'
    $ItemLoginUsername = 'Global Cert Signer'
    $ObjectTitle = 'Global Cert Signer'
    $VerboseVerification = $false

    $ItemLoginUsername = 'names-no-longer-matter 544'
    $FolderId = 'a0c0ef1d-4975-42f1-ac42-b43d012bf3fb'
    $FolderId = '08aa9793-8005-4921-9b86-b43b014e3604'
  #>

  $_Var_Name = 'zzzDeleteThis'
  try {
    Clear-Variable -Name $_Var_Name -ErrorAction 'Stop'
  } 
  catch {
    New-Variable -Name $_Var_Name -Value $null -Scope 'Script'
  }
  Set-Variable -Name $_Var_Name -Value ('yyyDeleteThis')



  #region | Find FolderFQN (Folder Fully Qualififed Name) from $FolderId |
  ${Folder Query-Start} = [System.DateTime]::Now
  $FolderFQN = bw.exe get folder $FolderId | ConvertFrom-Json | Select-Object -ExpandProperty 'name'
  ${Folder Query-End} = [System.DateTime]::Now
  Write-Verbose -Message "Folder Verification Duration inside $($PSCmdlet.MyInvocation.InvocationName) function:`n`t  $((${Folder Query-End} - ${Folder Query-Start}).TotalSeconds.ToString('n3')) Seconds`n`n"
  #endregion
  #region | Perform an anchorless match for the Login.Username of the Bitwarden Item of focus |
  ${Anchorless Match-Start} = [System.DateTime]::Now
  ${Bitwarden Items-Anchorless Match} = bw.exe list items --folderid $FolderId --search $ItemLoginUsername | ConvertFrom-Json
  ${Anchorless Match-End} = [System.DateTime]::Now
  Write-Verbose -Message "Anchorless Match Duration inside $($PSCmdlet.MyInvocation.InvocationName) function:`n`t  $((${Anchorless Match-End} - ${Anchorless Match-Start}).TotalSeconds.ToString('n3')) Seconds`n`n"

  ${Bitwarden Items} = ${Bitwarden Items-Anchorless Match} | Where-Object -FilterScript {$_.Login.Username -match "^$ItemLoginUsername`$"}
  #endregion

  switch ($true) {
    {${Bitwarden Items}.Count -eq 0} {      
      Write-Verbose -Message "Bitwarden object where`n  Item.Login.Username = $ItemLoginUsername`nnot detected in Folder $([System.Char]39)$FolderFQN$([System.Char]39).`n"
      $IsBitWardenItemPresent = $false
      ${time_End _VerifyExactBitwardenItemExistence} = [System.DateTime]::Now
      Write-Verbose -Message "Wait time on $($PSCmdlet.MyInvocation.InvocationName) function:`n`t`t$((${time_End _VerifyExactBitwardenItemExistence} - ${time_Begin _VerifyExactBitwardenItemExistence}).TotalSeconds.ToString('n3')) Seconds`n"
      break
    }
    {${Bitwarden Items} -is [System.Object[]]} {
      $time_End = Get-Date
      ${time_End _VerifyExactBitwardenItemExistence} = [System.DateTime]::Now
      Write-Verbose -Message "Wait time on $($PSCmdlet.MyInvocation.InvocationName) function:`n`t`t$((${time_End _VerifyExactBitwardenItemExistence} - ${time_Begin _VerifyExactBitwardenItemExistence}).TotalSeconds.ToString('n3')) Seconds`n"
      Write-Error -Message "`n`tThis is bad.`n`tTwo or more Bitwarden Items share the exact same case-insensitive value for Login.Username in Folder $([System.Char]39)$FolderFQN$([System.Char]39).`n`t(1) Navigate to 'https://vault.bitwarden.com/#/login' and log into your Bitwarden Account.`n`t(2) Open the Bitwarden Folder with fully qualified name $FolderFQN.`n`t(3) Delete all but one of the Items in the Folder where Login.Username = $ItemLoginUsername.`n`t(4) Restart PowerShell 7, unlock the Bitwarden CLI, and resynchronize local cache with Bitwarden Account by executing`n`t  bw.exe sync`n`n`tVerification duration:`n`t  $(($time_End - $time_Begin).TotalSeconds.ToString('n3')) Seconds`n`n`tExiting PowerShell 7 host process..."
      pause
      exit
    }
    {${Bitwarden Items}.Count -eq 1} {
      $IsBitWardenItemPresent = $true
      ${time_End _VerifyExactBitwardenItemExistence} = [System.DateTime]::Now
      Write-Verbose -Message "Wait time on $($PSCmdlet.MyInvocation.InvocationName) function:`n`t`t$((${time_End _VerifyExactBitwardenItemExistence} - ${time_Begin _VerifyExactBitwardenItemExistence}).TotalSeconds.ToString('n3')) Seconds`n"
      #Write-Warning -Message "`nBitwarden object where`n  Item.Login.Username = $ItemLoginUsername`n is present in Folder $([System.Char]39)$FolderFQN$([System.Char]39).`n"
      Write-Verbose -Message "`nBitwarden object where`n  Item.Login.Username = $ItemLoginUsername`n is present in Folder $([System.Char]39)$FolderFQN$([System.Char]39).`n"
      break
    }
  }

  return $IsBitWardenItemPresent
}