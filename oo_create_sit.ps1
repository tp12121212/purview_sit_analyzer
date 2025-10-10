
# PowerShell code to create Microsoft 365 DLP SIT
Connect-IPPSession
$xml = Get-Content -Raw -Path 'oo_sit.xml'
New-DlpSensitiveInformationType -Name "$(Split-Path 'oo_sit.xml' -Leaf)" -Xml $xml
