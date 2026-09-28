#Requires -Version 7.4
#Requires -PSEdition Core

param (
  $ModuleName,
  $ModuleVersion
)

${Files Exposed to User} = Get-ChildItem -Path "$PSScriptRoot\Functions" -File | Where-Object -FilterScript {$_.Name -match '^.+-.+\.ps1$'}
${Helper Files} = Get-ChildItem -Path "$PSScriptRoot\Functions" -File | Where-Object -FilterScript {$_.Name -notmatch '^.+-.+\.ps1$'}
${All Files} = ${Helper Files} + ${Files Exposed to User}

$OriginalAliasSet = Get-Alias
Get-ChildItem -Path "$PSScriptRoot\Functions" -File | ForEach-Object -Process {. $_.FullName}
$UpdatedAliasSet = Get-Alias

${Aliases to Export} = Compare-Object -ReferenceObject $OriginalAliasSet -DifferenceObject $UpdatedAliasSet `
| Select-Object -ExpandProperty 'InputObject' `
| Select-Object -ExpandProperty 'Name'

${Functions to Export} = ${Files Exposed to User} | Select-Object -ExpandProperty 'BaseName'

$ModuleFilePath = "$PSScriptRoot\output\builtModule\$ModuleName\$ModuleVersion\$ModuleName.psm1"
$IsModuleFilePresent = Test-Path -Path $ModuleFilePath
if ($IsModuleFilePresent) {
  Remove-Item -Path $ModuleFilePath
}
$ModuleFile = try {
  Get-Item -Path $ModuleFilePath -ErrorAction 'Stop'
} 
catch {
  New-Item -Path $ModuleFilePath -ItemType 'File' -Force
}

${All Files} | ForEach-Object -Process {
  Get-Content -Path $_.FullName
  ""
} | Out-File -FilePath "$ModuleFile"


# Define a new Module Manifest
Push-Location -Path "$PSScriptRoot\output\builtModule\$ModuleName\$ModuleVersion"

$newModuleManifestHT = @{
  RootModule            = "$ModuleName.psm1"
  Path                  = "$PSScriptRoot\output\builtModule\$ModuleName\$ModuleVersion\$ModuleName.psd1"
  ModuleVersion         = $ModuleVersion
  CompatiblePSEditions  = 'Core'
  GUID                  = 'e3dc0b2a-a991-4588-9426-b6101900a5e7'
  PowerShellVersion     = '7.4'
  Description           = "PowerShell functions for securely generating Folder and Item objects in a Bitwarden Vault."
  Author                = "CarlSimonIT"
  Company               = "CarlSimonIT"
  Copyright             = '2026 Carl Simon (MIT License)'
  FunctionsToExport     = ${Functions to Export}
  CmdletsToExport       = '*'
  VariablesToExport     = '*'
  AliasesToExport       = ${Aliases to Export}
  ProcessorArchitecture = 'Amd64'
  PrivateData = @{
    #   PSData = @{
    #     # Set to a prerelease string value if the release should be a prerelease.
    #     Prerelease   = ''
    #     # Tags applied to this module. These help with module discovery in online galleries.
    #     Tags         = @('DesiredStateConfiguration', 'DSC', 'DSCResource', 'WSMan','QRCode', 'powershell.one')
    #     # A URL to the license for this module.
    #     LicenseUri   = 'https://en.wikipedia.org/wiki/MIT_License'
    #     # A URL to the main website for this project.
    #     ProjectUri   = 'https://github.com/CarlSimonIT/Secure-Automations-Toolset'
    #     # A URL to an icon representing this module.
    #     IconUri      = 'https://dsccommunity.org/images/DSC_Logo_300p.png'
    #     # ReleaseNotes of this module
    #     ReleaseNotes = 'Here are some release notz'
    #   }
  }
  Verbose              = $false
}
New-ModuleManifest @newModuleManifestHT

<#
  $PSModuleInfo = Test-ModuleManifest -Path $newModuleManifestHT.Path
  $PSModuleInfo | Format-Table -AutoSize
  $PSModuleInfo | Format-List -Property *
  $PSModuleInfo.ExportedCommands
#>


Pop-Location



