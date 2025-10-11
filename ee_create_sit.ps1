
# PowerShell code to create Microsoft 365 DLP SIT
Connect-IPPSession
$xml = Get-Content -Raw -Path 'ee_sit.xml'
New-DlpSensitiveInformationType -Name "$(Split-Path 'ee_sit.xml' -Leaf)" -Xml $xml
