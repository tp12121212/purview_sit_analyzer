
# PowerShell code to create Purview SIT
$definition = Get-Content -Raw -Path 'out_sit.json' | ConvertFrom-Json
New-AzPurviewSensitiveInformationType -Name $definition.name -PrimaryElement $definition.primaryElement -SupportingElements $definition.supportingElements
