$resources = Get-AzResource
$resources | Export-Csv -Path "C:\AzureResources.csv"