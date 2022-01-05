<#
.SYNOPSIS
    This script can be used to generate passwords and add it to an Azure Key Vault. It uses the Password Wolf api for generating passwords.
    More info: https://passwordwolf.com
.DESCRIPTION
    This script can be used to generate passwords and add it directly to a Azure Key Vault in a DevOps pipeline, PowerShell session (Azure Context) and/or ARM Deployment Script.
.EXAMPLE
    PS C:\> .\Add-AzKeyVaultSecrets.ps1 -KeyVaultSecrets VirtualMachineLocalAdmin -KeyVaultName kev-we-lz-d-01
    Generate a secret and add it to the provided key vault with the provided secret name. It will not create a new secret if it already exists.
.EXAMPLE
    PS C:\> .\Add-AzKeyVaultSecrets.ps1 -KeyVaultSecrets VirtualMachineLocalAdmin, AzureSQLAdminPassword -KeyVaultName kev-we-lz-d-01
    Generate a two secrets and add it to the provided key vault with the provided secret names. It will not create a new secret if it already exists.
.EXAMPLE
    PS C:\> .\Add-AzKeyVaultSecrets.ps1 -KeyVaultSecrets VirtualMachineLocalAdmin -KeyVaultName kev-we-lz-d-01 -AddNewSecretIfAlreadyExists
    Generate a secret and add it to the provided key vault with the provided secret name. It will generate a new secret version if the secret already exists.
.EXAMPLE
    PS C:\> .\Add-AzKeyVaultSecrets.ps1 -KeyVaultSecrets VirtualMachineLocalAdmin -KeyVaultName kev-we-lz-d-01 -AddNewSecretIfAlreadyExists -PasswordLength 7
    Generate a secret with a length of 7 characters  and add it to the provided key vault with the provided secret name. It will generate a new secret version if the secret already exists.
.EXAMPLE
    PS C:\> .\Add-AzKeyVaultSecrets.ps1 -KeyVaultSecrets VirtualMachineLocalAdmin -KeyVaultName kev-we-lz-d-01 -AddNewSecretIfAlreadyExists -PasswordLength 7 -ExcludedCharacters ",-!"
    Generate a secret with a length of 7 characters, without the provided characters and add it to the provided key vault with the provided secret name. It will generate a new secret version if the secret already exists.
.NOTES

#>


[CmdletBinding()]
param (
    # Specify secret names in comma seperated fashion. (ie. SQLPassword, VmAdminPassword etc)
    [Parameter(Mandatory = $True)]
    [string[]]
    $KeyVaultSecrets,

    # Name of the Key Vault to add or check the secrets
    [Parameter(Mandatory = $True)]
    [string]
    $KeyVaultName,

    # If you want to add a new version of the secret run it with this parameter
    [Parameter(Mandatory = $False)]
    [switch]
    $AddNewSecretIfAlreadyExists,

    # Specify the length of the password
    [Parameter(Mandatory = $False)]
    [int]
    $PasswordLength = 15,

    # Specify the characters to exclude from the password
    [Parameter(Mandatory = $False)]
    [string]
    $ExcludedCharacters = "/}``"
)


Function GeneratePasswordandAddToKeyVault ($KeyVaultName, $Secret) {

    Write-Verbose "Generating password..."

    $GeneratedPassword = Invoke-RestMethod `
        -Uri ("https://passwordwolf.com/api/?length={0}&exclude={1}&repeat=1" -f $PasswordLength, $ExcludedCharacters )

    $localIp = (Invoke-RestMethod http://ipinfo.io/json | Select-Object -exp ip)
    $localIp

    Update-AzKeyVaultNetworkRuleSet -VaultName 'kevmcwopshubs01' -ResourceGroupName "rg-mcw-ops-hub-s" -Bypass AzureServices -IpAddressRange "$localIp" -PassThru

    try {    
        Set-AzKeyVaultSecret `
            -VaultName $KeyVaultName `
            -Name $Secret `
            -SecretValue (ConvertTo-SecureString -AsPlainText $GeneratedPassword[0].password -Force) `
            -ErrorAction Stop
        | Out-Null
        Write-Verbose "Successfully added $Secret to KeyVault"
    }
    catch {
        Write-Error $($error[0].exception.message)
    }
}

Foreach ($Secret in $KeyVaultSecrets) {

    Write-Verbose "Checking if $Secret is already in $KeyVaultName"

    Try {
        $KeyVaultPassword = Get-AzKeyVaultSecret `
            -VaultName $KeyVaultName `
            -Name $Secret `
            -ErrorAction Stop
    }
    catch {
        Write-Error $($error[0].exception.message)
    }

    if ($KeyVaultPassword) {
        Write-Verbose "$Secret is already available in $KeyVaultName"

        if ($AddNewSecretIfAlreadyExists) {

            Write-Verbose "Adding new secret for $Secret because the -AddNewSecretIfAlreadyExists parameter was supplied"

            GeneratePasswordandAddToKeyVault -KeyVaultName $KeyVaultName -Secret $Secret
        }

    }
    else {
        Write-Verbose "Generating new password for $Secret via Password Wolf API"

        GeneratePasswordandAddToKeyVault -KeyVaultName $KeyVaultName -Secret $Secret

    }
}
Write-Verbose "Script completed."
