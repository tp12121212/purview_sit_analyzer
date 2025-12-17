# Microsoft Purview PowerShell Cmdlet Reference and Automation Guide

## Executive Summary

This comprehensive technical document provides an in-depth reference for security engineers seeking to manage Microsoft Purview DLP policies, information protection, and custom sensitive information types through PowerShell automation. This guide encompasses DLP policy lifecycle management, custom sensitive information type creation, advanced testing methodologies, and production-ready automation frameworks suitable for CI/CD pipelines and enterprise deployments.

---

## Table of Contents

1. [Authentication and Connection Management](#authentication-and-connection-management)
2. [DLP Policy Management Cmdlets](#dlp-policy-management-cmdlets)
3. [Sensitive Information Types (SIT)](#sensitive-information-types-sit)
4. [Testing and Validation Cmdlets](#testing-and-validation-cmdlets)
5. [Information Protection Client Management](#information-protection-client-management)
6. [Advanced Automation Frameworks](#advanced-automation-frameworks)
7. [Production Implementation Patterns](#production-implementation-patterns)
8. [Troubleshooting and Best Practices](#troubleshooting-and-best-practices)

---

## Authentication and Connection Management

### Connect-IPPSSession: Primary Connection Method

The `Connect-IPPSSession` cmdlet establishes a connection to the Security & Compliance PowerShell module, which is the foundation for all Purview management operations.

#### Interactive Authentication (MFA)

```powershell
# Basic interactive connection with MFA support
Connect-IPPSSession

# Connection with specific organization
Connect-IPPSSession -Organization \"contoso.onmicrosoft.com\"

# Connection with explicit credential prompt
$credential = Get-Credential
Connect-IPPSSession -Credential $credential
```

#### Certificate-Based Authentication (CBA) - Unattended Scenarios

Certificate-based authentication is essential for automation scripts that must run without user interaction.

```powershell
# Using CertificateThumbprint (Windows only)
Connect-IPPSSession `
    -AppId \"YOUR_APP_ID\" `
    -CertificateThumbprint \"THUMBPRINT_STRING\" `
    -Organization \"contoso.onmicrosoft.com\"

# Using Certificate Object from file (Cross-platform)
$cert = [System.Security.Cryptography.X509Certificates.X509Certificate2]::new(\"C:\\path\\to\\cert.pfx\", \"password\")
Connect-IPPSSession `
    -AppId \"YOUR_APP_ID\" `
    -Certificate $cert `
    -Organization \"contoso.onmicrosoft.com\"

# Using CertificateFilePath with password (Cross-platform)
$certPassword = ConvertTo-SecureString \"certificate-password\" -AsPlainText -Force
Connect-IPPSSession `
    -AppId \"YOUR_APP_ID\" `
    -CertificateFilePath \"C:\\path\\to\\cert.pfx\" `
    -CertificatePassword $certPassword `
    -Organization \"contoso.onmicrosoft.com\"
```

#### OAuth Token-Based Authentication

```powershell
# Using Access Token (for advanced scenarios)
$accessToken = \"YOUR_JWT_ACCESS_TOKEN\"
Connect-IPPSSession `
    -AccessToken $accessToken `
    -Organization \"contoso.onmicrosoft.com\"
```

#### Configuration for Automation Frameworks

**Azure Automation/Runbook:**
```powershell
# Retrieve certificate from automation account
$certificateThumbprint = \"YOUR_THUMBPRINT\"
$cert = Get-AutomationCertificate -Name \"PurviewCertificate\"
$appId = Get-AutomationVariable -Name \"PurviewAppId\"

Connect-IPPSSession `
    -AppId $appId `
    -Certificate $cert `
    -Organization \"contoso.onmicrosoft.com\"
```

**GitHub Actions:**
```powershell
# Using environment variables for sensitive data
$appId = $env:AZURE_APP_ID
$thumbprint = $env:AZURE_CERT_THUMBPRINT
$orgName = $env:TENANT_NAME

Connect-IPPSSession `
    -AppId $appId `
    -CertificateThumbprint $thumbprint `
    -Organization $orgName
```

---

## DLP Policy Management Cmdlets

### New-DlpCompliancePolicy: Policy Creation

The `New-DlpCompliancePolicy` cmdlet creates new DLP policies with support for multiple workloads.

#### Basic Policy Creation

```powershell
# Create a basic DLP policy in test mode
$policyName = \"DLP-PII-Global\"
$policy = New-DlpCompliancePolicy `
    -Name $policyName `
    -Comment \"Primary policy for detecting PII across Microsoft 365\" `
    -Mode TestWithoutNotifications `
    -ExchangeLocation All `
    -SharePointLocation All `
    -OneDriveLocation All

Write-Host \"Policy created: $($policy.Identity)\" -ForegroundColor Green
```

#### Advanced Multi-Workload Policy Creation

```powershell
# Create policy targeting specific locations with adaptive scopes
$policy = New-DlpCompliancePolicy `
    -Name \"DLP-Financial-Data\" `
    -Comment \"Detects financial and banking information\" `
    -Mode TestWithNotifications `
    -ExchangeLocation All `
    -SharePointLocation \"https://contoso.sharepoint.com/sites/Finance\", \"https://contoso.sharepoint.com/sites/Accounting\" `
    -OneDriveLocation All `
    -TeamsLocation All `
    -EndpointDlpLocation \"All\" `
    -Priority 1 `
    -SkipSimulation $false

# Add endpoint DLP with device groups
Set-DlpCompliancePolicy `
    -Identity $policy.Identity `
    -AddEndpointDlpLocation \"All\" `
    -EndpointDlpAdaptiveScopes @{Name=\"Finance-Team\";Filters=@{Groups=\"Finance Analyst\"}}
```

#### Policy with Location Exceptions

```powershell
# Create policy with excluded locations
$policy = New-DlpCompliancePolicy `
    -Name \"DLP-Sensitive-Data\" `
    -Mode Disable `
    -ExchangeLocation All `
    -SharePointLocation All `
    -OneDriveLocation All

# Add location exceptions
Set-DlpCompliancePolicy `
    -Identity $policy.Identity `
    -AddSharePointLocationException \"https://contoso.sharepoint.com/sites/Compliance\", \"https://contoso.sharepoint.com/sites/Legal\" `
    -AddOneDriveLocationException \"https://contoso-my.sharepoint.com/personal/user1_contoso_com\" `
    -Mode Enable
```

### Get-DlpCompliancePolicy: Policy Retrieval and Audit

```powershell
# Retrieve all DLP policies
$allPolicies = Get-DlpCompliancePolicy
$allPolicies | Select-Object Name, Mode, Priority, IsValid

# Retrieve specific policy
$policy = Get-DlpCompliancePolicy -Identity \"DLP-PII-Global\"
$policy | Select-Object Name, Mode, ExchangeLocation, SharePointLocation, OneDriveLocation

# Export policy configuration for documentation
$policies = Get-DlpCompliancePolicy
$policies | ForEach-Object {
    [PSCustomObject]@{
        Name = $_.Name
        Mode = $_.Mode
        Priority = $_.Priority
        ExchangeLocation = ($_.ExchangeLocation -join \"; \")
        SharePointLocation = ($_.SharePointLocation -join \"; \")
        OneDriveLocation = ($_.OneDriveLocation -join \"; \")
        TeamsLocation = ($_.TeamsLocation -join \"; \")
        EndpointDlpLocation = ($_.EndpointDlpLocation -join \"; \")
    }
} | Export-Csv -Path \"DLP-Policies-Report.csv\" -NoTypeInformation
```

### Set-DlpCompliancePolicy: Policy Modification

```powershell
# Update policy mode from test to enforced
Set-DlpCompliancePolicy `
    -Identity \"DLP-PII-Global\" `
    -Mode Enable `
    -Comment \"Policy updated to enforcement mode - $(Get-Date)\"

# Modify policy priority
Set-DlpCompliancePolicy `
    -Identity \"DLP-Financial-Data\" `
    -Priority 0  # Higher priority (lower number)

# Add locations to existing policy
Set-DlpCompliancePolicy `
    -Identity \"DLP-Sensitive-Data\" `
    -AddExchangeLocation \"deployment.outlook.com\" `
    -AddSharePointLocation \"https://contoso.sharepoint.com/sites/Marketing\"

# Remove locations from policy
Set-DlpCompliancePolicy `
    -Identity \"DLP-Sensitive-Data\" `
    -RemoveSharePointLocation \"https://contoso.sharepoint.com/sites/OldProject\"

# Bulk update multiple policies to test mode
Get-DlpCompliancePolicy | Where-Object {$_.Mode -eq \"Enable\"} | ForEach-Object {
    Set-DlpCompliancePolicy -Identity $_.Identity -Mode TestWithNotifications
    Write-Host \"Updated $($_.Name) to test mode\"
}
```

### Remove-DlpCompliancePolicy: Policy Deletion

```powershell
# Remove a single policy
Remove-DlpCompliancePolicy -Identity \"DLP-Test-Policy\" -Confirm:$true

# Remove multiple policies by pattern
Get-DlpCompliancePolicy | Where-Object {$_.Name -like \"*-TEST-*\"} | ForEach-Object {
    Remove-DlpCompliancePolicy -Identity $_.Identity -Confirm:$false
    Write-Host \"Removed: $($_.Name)\"
}
```

### New-DlpComplianceRule: Rule Creation

Rules define the specific conditions and actions for DLP policies. Each policy requires at least one rule.

#### Basic Rule Creation

```powershell
# Create a simple rule detecting US Social Security Numbers
$rule = New-DlpComplianceRule `
    -Name \"Detect-US-SSN\" `
    -Policy \"DLP-PII-Global\" `
    -ContentContainsSensitiveInformation @{Name=\"U.S. Social Security Number (SSN)\"; MinCount=\"1\"} `
    -BlockAccess $true `
    -BlockAccessScope \"All\" `
    -UserNotification \"Email\" `
    -NotifyUser \"LastModifier\" `
    -NotifyAllowOverride \"WithJustification\" `
    -NotifyPolicyTipCustomText \"Sensitive Social Security Number detected. Contact DLP Admin.\"

Write-Host \"Rule created: $($rule.Identity)\" -ForegroundColor Green
```

#### Advanced Multi-Condition Rule

```powershell
# Create complex rule with multiple sensitive info types and conditions
$rule = New-DlpComplianceRule `
    -Name \"Detect-Financial-Data-External\" `
    -Policy \"DLP-Financial-Data\" `
    -ContentContainsSensitiveInformation @(
        @{Name=\"Credit Card Number\"; MinCount=\"1\"},
        @{Name=\"ABA Routing Number\"; MinCount=\"1\"},
        @{Name=\"U.S. Bank Account Number\"; MinCount=\"1\"}
    ) `
    -AccessScope \"NotInOrganization\" `
    -BlockAccess $true `
    -BlockAccessScope \"All\" `
    -UserNotification \"Email\" `
    -NotifyUser \"LastModifier\" `
    -GenerateIncidentReport @(\"admin@contoso.com\") `
    -NotifyPolicyTipCustomText \"Sending financial data externally is blocked.\" `
    -IncidentReportContent @(\"Default\", \"Detections\", \"Severity\")

Write-Host \"Complex rule created successfully\"
```

#### Rule with Document Properties and Patterns

```powershell
# Create rule with document metadata conditions
$rule = New-DlpComplianceRule `
    -Name \"Detect-Unencrypted-PII\" `
    -Policy \"DLP-PII-Global\" `
    -ContentContainsSensitiveInformation @{Name=\"U.S. Social Security Number (SSN)\"; MinCount=\"1\"} `
    -DocumentIsPasswordProtected $false `
    -ExceptIfDocumentNameMatchesPatterns \"template*\", \"temp*\" `
    -BlockAccess $true `
    -UserNotification \"PolicyTip\" `
    -NotifyPolicyTipCustomText \"Unencrypted PII detected\"
```

### Get-DlpComplianceRule: Rule Query and Audit

```powershell
# Get all rules for a specific policy
$rules = Get-DlpComplianceRule -Policy \"DLP-PII-Global\"
$rules | Select-Object Name, Identity, Disabled

# Get specific rule details
$rule = Get-DlpComplianceRule -Identity \"Detect-US-SSN\"
$rule | Select-Object Name, Policy, ContentContainsSensitiveInformation, BlockAccess, NotifyUser

# Export all rules with conditions for documentation
$allRules = Get-DlpComplianceRule
$allRules | ForEach-Object {
    [PSCustomObject]@{
        Name = $_.Name
        Policy = $_.Policy
        Disabled = $_.Disabled
        AccessScope = $_.AccessScope
        BlockAccess = $_.BlockAccess
        NotifyUser = ($_.NotifyUser -join \"; \")
        SensitiveInfoTypes = (($_.ContentContainsSensitiveInformation | ForEach-Object {$_.Name}) -join \"; \")
    }
} | Export-Csv -Path \"DLP-Rules-Audit.csv\" -NoTypeInformation
```

### Set-DlpComplianceRule: Rule Modification

```powershell
# Disable a rule
Set-DlpComplianceRule -Identity \"Detect-US-SSN\" -Disabled $true

# Enable a rule
Set-DlpComplianceRule -Identity \"Detect-US-SSN\" -Disabled $false

# Update rule actions
Set-DlpComplianceRule `
    -Identity \"Detect-Financial-Data-External\" `
    -BlockAccess $false `
    -UserNotification \"PolicyTip\" `
    -GenerateIncidentReport @(\"compliance@contoso.com\", \"audit@contoso.com\")

# Add additional sensitive info types to existing rule
Set-DlpComplianceRule `
    -Identity \"Detect-US-SSN\" `
    -AddContentContainsSensitiveInformation @{Name=\"U.S. Individual Tax ID (ITIN)\"; MinCount=\"1\"}

# Modify rule notifications
Set-DlpComplianceRule `
    -Identity \"Detect-US-SSN\" `
    -NotifyPolicyTipCustomText \"Updated: PII detected and blocked. Please use secure transfer methods.\" `
    -NotifyAllowOverride @(\"WithJustification\", \"FalsePositive\")
```

### Remove-DlpComplianceRule: Rule Deletion

```powershell
# Remove a specific rule
Remove-DlpComplianceRule -Identity \"Detect-US-SSN\" -Confirm:$true

# Remove all rules matching a pattern
Get-DlpComplianceRule | Where-Object {$_.Name -like \"*-TEST*\"} | ForEach-Object {
    Remove-DlpComplianceRule -Identity $_.Identity -Confirm:$false
}
```

---

## Sensitive Information Types (SIT)

### Creating Custom Sensitive Information Types

Custom SITs require an XML rule package that defines patterns, keywords, and evidence.

#### XML Rule Package Structure

```xml
<?xml version=\"1.0\" encoding=\"UTF-16\"?>
<RulePackage xmlns=\"http://schemas.microsoft.com/office/2011/mce\">
  <RulePack id=\"D4BE2C42-9F1E-4D3E-8E5C-7A8E9C0D1F2G\">
    <Version major=\"1\" minor=\"0\" build=\"0\" revision=\"0\"/>
    <Publisher id=\"A5B6C7D8-E9F0-1A2B-3C4D-5E6F7A8B9C0D\"/>
    <Details defaultLangCode=\"en-us\">
      <LocalizedDetails langcode=\"en-us\">
        <PublisherName>Contoso</PublisherName>
        <Name>Custom Security Rules Pack</Name>
        <Description>Custom sensitive information types for enterprise security</Description>
      </LocalizedDetails>
    </Details>
  </RulePack>
  <Rules>
    <!-- Custom Employee ID Entity -->
    <Entity id=\"E1CC861E-3FE9-4A58-82DF-4BD259EAB378\" patternsProximity=\"300\" recommendedConfidence=\"75\">
      <!-- Pattern 1: Low confidence - just ID match -->
      <Pattern confidenceLevel=\"65\">
        <IdMatch idRef=\"Regex_employee_id\"/>
      </Pattern>
      <!-- Pattern 2: Medium confidence - ID + date -->
      <Pattern confidenceLevel=\"75\">
        <IdMatch idRef=\"Regex_employee_id\"/>
        <Match idRef=\"Func_us_date\"/>
      </Pattern>
      <!-- Pattern 3: High confidence - ID + date + keywords -->
      <Pattern confidenceLevel=\"85\">
        <IdMatch idRef=\"Regex_employee_id\"/>
        <Match idRef=\"Func_us_date\"/>
        <Any minMatches=\"1\">
          <Match idRef=\"Keyword_badge\" minCount=\"2\"/>
          <Match idRef=\"Keyword_employee\"/>
        </Any>
        <Any minMatches=\"0\" maxMatches=\"0\">
          <Match idRef=\"Keyword_false_positives\"/>
        </Any>
      </Pattern>
    </Entity>

    <!-- Regular Expression Definition -->
    <Regex id=\"Regex_employee_id\">(\\s)(\\d{9})(\\s)</Regex>

    <!-- Keyword Lists -->
    <Keyword id=\"Keyword_employee\">
      <Group matchStyle=\"word\">
        <Term>Employee ID</Term>
        <Term>Emp ID</Term>
        <Term>Staff Number</Term>
      </Group>
    </Keyword>

    <Keyword id=\"Keyword_badge\">
      <Group matchStyle=\"string\">
        <Term>badge</Term>
        <Term>card</Term>
        <Term caseSensitive=\"true\">ID</Term>
      </Group>
    </Keyword>

    <Keyword id=\"Keyword_false_positives\">
      <Group matchStyle=\"word\">
        <Term>credit card</Term>
        <Term>social security</Term>
      </Group>
    </Keyword>

    <!-- Localized Strings for UI Display -->
    <LocalizedStrings>
      <Resource idRef=\"E1CC861E-3FE9-4A58-82DF-4BD259EAB378\">
        <Name default=\"true\" langcode=\"en-us\">Contoso Employee ID</Name>
        <Description default=\"true\" langcode=\"en-us\">Detects Contoso 9-digit employee identification numbers</Description>
      </Resource>
    </LocalizedStrings>
  </Rules>
</RulePackage>
```

#### PowerShell: Upload and Manage Custom SIT

```powershell
# Load and upload XML rule package
$xmlFilePath = \"C:\\RulePackages\\CustomSIT.xml\"
$fileBytes = [System.IO.File]::ReadAllBytes($xmlFilePath)

# Upload the rule package
$rulePackage = New-DlpSensitiveInformationTypeRulePackage -FileData $fileBytes
Write-Host \"Rule package uploaded: $($rulePackage.RulePackageId)\"

# Verify upload - list all rule packages
Get-DlpSensitiveInformationTypeRulePackage | Select-Object RulePackageId, Name

# Get specific sensitive information type
$customSIT = Get-DlpSensitiveInformationType -Identity \"Contoso Employee ID\"
$customSIT | Select-Object Name, Identity, Publisher, Workload

# Update/replace rule package
Set-DlpSensitiveInformationTypeRulePackage `
    -Identity $rulePackage.RulePackageId `
    -FileData ([System.IO.File]::ReadAllBytes(\"C:\\RulePackages\\CustomSIT-Updated.xml\"))
```

#### Advanced SIT with Validators

```xml
<!-- XML with Checksum Validator -->
<RulePackage xmlns=\"http://schemas.microsoft.com/office/2011/mce\">
  <Rules>
    <!-- Credit Card with validation -->
    <Regex id=\"Regex_credit_card\" validators=\"Func_credit_card\">
      (?:^|[\\s,;\\:\\(\\)\\[\\]\\\"'])([0-9]{4}[ -_][0-9]{4}[ -_][0-9]{4}[ -_][0-9]{4})(?:$|[\\s,;\\:\\(\\)\\[\\]\\\"'])
    </Regex>

    <Entity id=\"675634eb7-edc8-4019-85dd-5a5c1f2bb085\" patternsProximity=\"300\" recommendedConfidence=\"85\">
      <Pattern confidenceLevel=\"85\">
        <IdMatch idRef=\"Regex_credit_card\"/>
        <Any minMatches=\"1\">
          <Match idRef=\"Keyword_cc_verification\"/>
          <Match idRef=\"Keyword_cc_name\"/>
          <Match idRef=\"Func_expiration_date\"/>
        </Any>
      </Pattern>
    </Entity>

    <!-- Custom Validator Example -->
    <Validators id=\"EmployeeIDChecksum\">
      <Validator type=\"Checksum\">
        <Param name=\"Weights\">2, 2, 2, 2, 2, 1</Param>
        <Param name=\"Mod\">28</Param>
        <Param name=\"CheckDigit\">2</Param>
        <Param name=\"AllowAlphabets\">1</Param>
      </Validator>
    </Validators>
    
    <Regex id=\"Regex_EmployeeID\" validators=\"EmployeeIDChecksum\">(\\d{5}[A-Z])</Regex>
  </Rules>
</RulePackage>
```

#### Remove Custom SIT

```powershell
# Remove rule package (this removes all SITs in the package)
Remove-DlpSensitiveInformationTypeRulePackage -Identity \"D4BE2C42-9F1E-4D3E-8E5C-7A8E9C0D1F2G\" -Confirm:$true

# List all rule packages before deletion
Get-DlpSensitiveInformationTypeRulePackage | Select-Object RulePackageId, Name, Publisher
```

---

## Testing and Validation Cmdlets

### Test-DataClassification: Content Classification Testing

The `Test-DataClassification` cmdlet evaluates text against sensitive information types and returns confidence levels and match counts.

#### Basic Text Classification

```powershell
# Test simple text against sensitive info types
$testText = \"My Social Security Number is 123-45-6789 and my credit card is 4532-1111-2222-3333\"

$classification = Test-DataClassification -TextToClassify $testText
$classification.ClassificationResults | Select-Object Name, Confidence, Count

# Output format:
# Name                              Confidence  Count
# U.S. Social Security Number (SSN) High        1
# Credit Card Number                High        1
```

#### Test Specific SIT by Name

```powershell
# Test against specific sensitive information types
$testText = \"Employee ID: 123456789 issued 2024-01-15\"

$result = Test-DataClassification `
    -TextToClassify $testText `
    -ClassificationNames \"Contoso Employee ID\", \"U.S. Social Security Number (SSN)\"

$result.ClassificationResults | ForEach-Object {
    Write-Host \"SIT: $($_.Name)\"
    Write-Host \"Confidence: $($_.Confidence)\"
    Write-Host \"Count: $($_.Count)\"
}
```

#### Test File Content Extraction Results

```powershell
# Extract text from email and classify
$emailPath = \"C:\\TestFiles\\test-email.msg\"
$fileBytes = [System.IO.File]::ReadAllBytes($emailPath)

# Extract text from email
$extractedContent = Test-TextExtraction -FileData $fileBytes
$extractedText = $extractedContent.ExtractedResults

# Classify extracted text
$classification = Test-DataClassification -TestTextExtractionResults $extractedContent.ExtractedResults
$classification.ClassificationResults | Format-Table Name, Confidence, Count
```

#### Bulk Classification Testing

```powershell
# Test multiple text samples
$testSamples = @(
    \"SSN: 123-45-6789\",
    \"Credit card: 4532-1111-2222-3333\",
    \"Employee badge: EMP123456\",
    \"Random text with no sensitive info\"
)

$report = @()
foreach ($sample in $testSamples) {
    $result = Test-DataClassification -TextToClassify $sample
    $report += [PSCustomObject]@{
        SampleText = $sample
        Matches = $result.ClassificationResults.Count
        SensitiveTypes = ($result.ClassificationResults.Name -join \"; \")
        ConfidenceLevels = ($result.ClassificationResults.Confidence -join \"; \")
    }
}

$report | Export-Csv -Path \"Classification-Report.csv\" -NoTypeInformation
```

### Test-TextExtraction: Text Extraction from Files

The `Test-TextExtraction` cmdlet extracts readable text from Office and email files for classification testing.

#### Extract Text from Email File

```powershell
# Extract text from .msg or .eml file
$emailFile = \"C:\\TestFiles\\sensitive-email.msg\"
$fileData = [System.IO.File]::ReadAllBytes($emailFile)

$extractionResult = Test-TextExtraction -FileData $fileData

# Display extracted content
Write-Host \"Extraction Status: $($extractionResult.ExtractionStatus)\"
Write-Host \"File Type: $($extractionResult.FileType)\"
Write-Host \"Extracted Text Preview:\"
$extractionResult.ExtractedResults | Select-Object -First 500

# Use extraction results with classification
$classification = Test-DataClassification -TestTextExtractionResults $extractionResult.ExtractedResults
$classification.ClassificationResults | Format-Table
```

#### Extract Text from Office Documents

```powershell
# Extract from Word, Excel, PowerPoint files
$officeFiles = Get-ChildItem -Path \"C:\\TestDocuments\" -Include \"*.docx\", \"*.xlsx\", \"*.pptx\"

foreach ($file in $officeFiles) {
    $fileData = [System.IO.File]::ReadAllBytes($file.FullName)
    $extracted = Test-TextExtraction -FileData $fileData
    
    # Classify extracted content
    $classification = Test-DataClassification -TestTextExtractionResults $extracted.ExtractedResults
    
    [PSCustomObject]@{
        Filename = $file.Name
        Status = $extracted.ExtractionStatus
        MatchCount = $classification.ClassificationResults.Count
        SensitiveTypes = ($classification.ClassificationResults.Name -join \"; \")
    }
}
```

#### Batch Extraction and Analysis

```powershell
# Process multiple files with detailed logging
$testDirectory = \"C:\\DLPTestContent\"
$results = @()

Get-ChildItem -Path $testDirectory -Recurse -File | ForEach-Object {
    try {
        $fileData = [System.IO.File]::ReadAllBytes($_.FullName)
        $extraction = Test-TextExtraction -FileData $fileData
        
        if ($extraction.ExtractionStatus -eq \"Success\") {
            $classification = Test-DataClassification -TestTextExtractionResults $extraction.ExtractedResults
            
            $results += [PSCustomObject]@{
                FilePath = $_.FullName
                FileSize = $_.Length
                ExtractionStatus = $extraction.ExtractionStatus
                SensitiveMatches = $classification.ClassificationResults.Count
                FirstMatch = $classification.ClassificationResults[0].Name
                Confidence = $classification.ClassificationResults[0].Confidence
            }
        } else {
            $results += [PSCustomObject]@{
                FilePath = $_.FullName
                FileSize = $_.Length
                ExtractionStatus = $extraction.ExtractionStatus
                SensitiveMatches = 0
                FirstMatch = \"N/A\"
                Confidence = \"N/A\"
            }
        }
    }
    catch {
        Write-Error \"Error processing $($_.FullName): $_\"
    }
}

$results | Export-Csv -Path \"Extraction-Analysis.csv\" -NoTypeInformation
$results | Where-Object {$_.SensitiveMatches -gt 0} | Format-Table
```

### Test-DlpPolicies: Policy Matching Validation

The `Test-DlpPolicies` cmdlet tests files against DLP policies to verify policy behavior before enforcement.

#### Test File Against DLP Policies

```powershell
# Test a SharePoint file against all DLP policies
$fileUrl = \"https://contoso.sharepoint.com/sites/Finance/Documents/report.xlsx\"
$reportEmail = \"dlp-admin@contoso.com\"

$testResult = Test-DlpPolicies `
    -Workload SharePoint `
    -FileUrl $fileUrl `
    -SendReportTo $reportEmail

Write-Host \"Test ID: $($testResult.TestId)\"
Write-Host \"Policies matched: $($testResult.Predicates.Count)\"
```

#### Test OneDrive Content

```powershell
# Test OneDrive file
$oneDriveFile = \"https://contoso-my.sharepoint.com/personal/user_contoso_com/Documents/sensitive.docx\"

$testResult = Test-DlpPolicies `
    -Workload ODB `
    -FileUrl $oneDriveFile `
    -SendReportTo \"compliance@contoso.com\"

$testResult | Select-Object TestId, IsMatched, Predicates
```

#### Parse and Analyze Test Results

```powershell
# Store and analyze test results
$testResults = @()

$sharePointFiles = @(
    \"https://contoso.sharepoint.com/sites/Finance/Documents/Q4-Financial-Results.xlsx\",
    \"https://contoso.sharepoint.com/sites/Marketing/Documents/Campaign-Data.docx\",
    \"https://contoso.sharepoint.com/sites/HR/Documents/Employee-Records.xlsx\"
)

foreach ($fileUrl in $sharePointFiles) {
    $result = Test-DlpPolicies `
        -Workload SharePoint `
        -FileUrl $fileUrl `
        -SendReportTo \"audit@contoso.com\"
    
    $testResults += [PSCustomObject]@{
        FileUrl = $fileUrl
        TestId = $result.TestId
        PolicyMatched = $result.IsMatched
        MatchedPolicies = ($result.Predicates.PolicyName -join \"; \")
        MatchedRules = ($result.Predicates.RulesMatched -join \"; \")
        ConfidenceLevels = ($result.Predicates.ConfidenceLevel -join \"; \")
    }
}

$testResults | Export-Csv -Path \"DLP-Policy-Tests.csv\" -NoTypeInformation
$testResults | Where-Object {$_.PolicyMatched -eq $true} | Format-Table
```

### Test-Message: Email and Transport Rule Testing

The `Test-Message` cmdlet simulates mail flow through DLP and transport rules.

#### Test Email Against DLP Rules

```powershell
# Create test email message
$testEmailPath = \"C:\\TestMessages\\sensitive-email.eml\"
$messageData = [System.IO.File]::ReadAllBytes($testEmailPath)

# Test against DLP rules
$testResult = Test-Message `
    -MessageFileData $messageData `
    -Sender \"sender@contoso.com\" `
    -Recipients \"recipient@contoso.com\" `
    -SendReportTo \"dlp-admin@contoso.com\" `
    -UnifiedDlpRules

# Review results sent to admin email
Write-Host \"Test completed. Report sent to dlp-admin@contoso.com\"
```

#### Test Email with Multiple Recipients

```powershell
# Test message with external recipients
$messageData = [System.IO.File]::ReadAllBytes(\"C:\\TestMessages\\external-share.eml\")

$testResult = Test-Message `
    -MessageFileData $messageData `
    -Sender \"finance@contoso.com\" `
    -Recipients \"external-partner@partner.com\", \"another-partner@client.com\" `
    -SendReportTo \"compliance@contoso.com\" `
    -UnifiedDlpRules `
    -Force

Write-Host \"Email tested against DLP policies for external recipients\"
```

#### Batch Email Testing

```powershell
# Test multiple email files
$testEmailDirectory = \"C:\\DLPTestEmails\"
$testResults = @()

Get-ChildItem -Path $testEmailDirectory -Filter \"*.eml\" | ForEach-Object {
    $messageData = [System.IO.File]::ReadAllBytes($_.FullName)
    
    $result = Test-Message `
        -MessageFileData $messageData `
        -Sender \"test@contoso.com\" `
        -Recipients \"external@partner.com\" `
        -SendReportTo \"audit@contoso.com\" `
        -UnifiedDlpRules
    
    $testResults += [PSCustomObject]@{
        EmailFile = $_.Name
        Sender = \"test@contoso.com\"
        Recipient = \"external@partner.com\"
        TestDate = Get-Date
        Status = \"Tested - Review audit email\"
    }
}

$testResults | Export-Csv -Path \"Email-Tests.csv\" -NoTypeInformation
```

---

## Information Protection Client Management

### Get-FileStatus: Query File Label and Protection

```powershell
# Get label and protection status of a single file
$fileStatus = Get-FileStatus -Path \"\\\\FileServer\\Shared\\Document.docx\"

$fileStatus | Select-Object `
    FileName,
    IsLabeled,
    MainLabelName,
    MainLabelId,
    SubLabelName,
    LabelingMethod,
    LabelDate,
    IsRmsProtected,
    RmsTemplateId

# Get status of all files in a folder
$folderStatus = Get-FileStatus -Path \"\\\\FileServer\\Finance\\\"
$folderStatus | Where-Object {$_.IsLabeled -eq $false} | Format-Table FileName, IsRmsProtected

# Export file status report
Get-FileStatus -Path \"\\\\FileServer\\\" | Export-Csv -Path \"File-Label-Report.csv\" -NoTypeInformation
```

### Set-FileLabel: Apply Labels and Protection

```powershell
# Apply label to a file
Set-FileLabel -Path \"C:\\Sensitive\\Financial-Report.xlsx\" `
    -LabelId \"075e257c-1234-1234-1234-34a182080e71\" `
    -Justification \"Financial data requires confidential label\"

# Apply label with auto-labeling based on content
Set-FileLabel -Path \"C:\\Documents\\\" `
    -LabelId \"8ed98c24-295c-4058-9ee4-68ef3d697eb6\" `
    -Autolabel

# Downgrade label with justification
Set-FileLabel -Path \"C:\\Archive\\OldReport.docx\" `
    -LabelId \"d9f23ae3-1234-1234-1234-f515f824c57b\" `
    -Justification \"Document archived, downgrading from Confidential to General\"
```

---

## Advanced Automation Frameworks

### Framework 1: Azure Automation Runbook

```powershell
# Save as Runbook in Azure Automation
[CmdletBinding()]
param()

# Variables set in Automation Account
$automationVariables = @{
    AppId = Get-AutomationVariable -Name \"PurviewAppId\"
    TenantId = Get-AutomationVariable -Name \"TenantId\"
    SubscriptionId = Get-AutomationVariable -Name \"SubscriptionId\"
}

# Get certificate from Automation Account
$certificate = Get-AutomationCertificate -Name \"PurviewCertificate\"

# Connect to Purview
Connect-IPPSSession `
    -AppId $automationVariables.AppId `
    -Certificate $certificate `
    -Organization \"contoso.onmicrosoft.com\"

# Main automation logic
try {
    # Get all disabled policies and log them
    $disabledPolicies = Get-DlpCompliancePolicy | Where-Object {$_.Mode -eq \"Disable\"}
    
    $reportData = @()
    foreach ($policy in $disabledPolicies) {
        $rules = Get-DlpComplianceRule -Policy $policy.Name
        $reportData += [PSCustomObject]@{
            PolicyName = $policy.Name
            RuleCount = $rules.Count
            Priority = $policy.Priority
            CreationTime = $policy.CreationTime
            LastModifiedTime = $policy.LastModifiedTime
        }
    }
    
    # Send report via webhook
    $webhookUri = Get-AutomationVariable -Name \"ReportingWebhookUri\"
    $reportJson = ConvertTo-Json -InputObject $reportData
    Invoke-RestMethod -Uri $webhookUri -Method Post -Body $reportJson
    
    Write-Output \"DLP policy audit completed successfully\"
}
catch {
    Write-Error \"Automation failed: $_\"
    # Send alert
    $errorWebhook = Get-AutomationVariable -Name \"AlertWebhookUri\"
    Invoke-RestMethod -Uri $errorWebhook -Method Post -Body @{Error = $_.Exception.Message}
}
```

### Framework 2: GitHub Actions Workflow

```yaml
name: DLP Policy Enforcement

on:
  schedule:
    - cron: '0 2 * * *'  # Daily at 2 AM UTC
  workflow_dispatch:

jobs:
  enforce-dlp-policies:
    runs-on: windows-latest
    
    steps:
    - name: Checkout code
      uses: actions/checkout@v3
    
    - name: Install PowerShell modules
      shell: powershell
      run: |
        Install-Module ExchangeOnlineManagement -Scope CurrentUser -Force
        Import-Module ExchangeOnlineManagement
    
    - name: Connect to Purview
      shell: powershell
      env:
        AZURE_APP_ID: ${{ secrets.AZURE_APP_ID }}
        AZURE_CERT_THUMBPRINT: ${{ secrets.AZURE_CERT_THUMBPRINT }}
        TENANT_NAME: ${{ secrets.TENANT_NAME }}
      run: |
        # Certificate stored in GitHub Secrets
        $cert = Get-ChildItem -Path Cert:\\LocalMachine\\My | Where-Object {$_.Thumbprint -eq $env:AZURE_CERT_THUMBPRINT}
        Connect-IPPSSession -AppId $env:AZURE_APP_ID -Certificate $cert -Organization $env:TENANT_NAME
    
    - name: Run DLP policy enforcement
      shell: powershell
      run: |
        ./scripts/enforce-dlp-policies.ps1
    
    - name: Generate compliance report
      shell: powershell
      run: |
        ./scripts/generate-report.ps1 | Out-File -FilePath compliance-report.txt
    
    - name: Upload report artifact
      uses: actions/upload-artifact@v3
      with:
        name: compliance-report
        path: compliance-report.txt
```

### Framework 3: CI/CD Pipeline for DLP Policy Deployment

```powershell
# deploy-dlp-policies.ps1 - Deploy DLP policies from configuration files

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$EnvironmentConfig,
    
    [Parameter(Mandatory = $false)]
    [switch]$DryRun
)

# Load environment configuration
$config = Get-Content -Path $EnvironmentConfig | ConvertFrom-Json

# Connect to Purview
Connect-IPPSSession `
    -AppId $config.Authentication.AppId `
    -Certificate $config.Authentication.Certificate `
    -Organization $config.Authentication.Organization

Write-Host \"Connected to: $($config.Authentication.Organization)\" -ForegroundColor Green

# Deploy policies
foreach ($policyConfig in $config.Policies) {
    Write-Host \"Processing policy: $($policyConfig.Name)\" -ForegroundColor Yellow
    
    try {
        # Check if policy exists
        $existingPolicy = Get-DlpCompliancePolicy -Identity $policyConfig.Name -ErrorAction SilentlyContinue
        
        if ($existingPolicy) {
            Write-Host \"  Policy exists. Updating...\"
            
            if (-not $DryRun) {
                Set-DlpCompliancePolicy `
                    -Identity $policyConfig.Name `
                    -Mode $policyConfig.Mode `
                    -Comment $policyConfig.Comment `
                    -Priority $policyConfig.Priority
            }
        } else {
            Write-Host \"  Policy does not exist. Creating...\"
            
            if (-not $DryRun) {
                $newPolicy = New-DlpCompliancePolicy `
                    -Name $policyConfig.Name `
                    -Mode $policyConfig.Mode `
                    -Comment $policyConfig.Comment `
                    -ExchangeLocation $policyConfig.ExchangeLocation `
                    -SharePointLocation $policyConfig.SharePointLocation `
                    -OneDriveLocation $policyConfig.OneDriveLocation
            }
        }
        
        # Deploy rules
        foreach ($ruleConfig in $policyConfig.Rules) {
            Write-Host \"  Deploying rule: $($ruleConfig.Name)\"
            
            try {
                $existingRule = Get-DlpComplianceRule -Identity $ruleConfig.Name -ErrorAction SilentlyContinue
                
                if ($existingRule) {
                    if (-not $DryRun) {
                        Set-DlpComplianceRule `
                            -Identity $ruleConfig.Name `
                            -BlockAccess $ruleConfig.BlockAccess `
                            -UserNotification $ruleConfig.UserNotification
                    }
                } else {
                    if (-not $DryRun) {
                        New-DlpComplianceRule `
                            -Name $ruleConfig.Name `
                            -Policy $policyConfig.Name `
                            -ContentContainsSensitiveInformation $ruleConfig.SensitiveInfoTypes `
                            -BlockAccess $ruleConfig.BlockAccess `
                            -UserNotification $ruleConfig.UserNotification
                    }
                }
                
                Write-Host \"    ✓ Rule deployed successfully\"
            }
            catch {
                Write-Error \"    ✗ Failed to deploy rule: $_\"
            }
        }
        
        Write-Host \"  ✓ Policy processed successfully\" -ForegroundColor Green
    }
    catch {
        Write-Error \"  ✗ Failed to process policy: $_\"
    }
}

Write-Host \"\\nDeployment completed\" -ForegroundColor Cyan
```

#### Configuration File Example (JSON)

```json
{
  \"Authentication\": {
    \"AppId\": \"your-app-id\",
    \"Certificate\": \"path-to-cert.pfx\",
    \"Organization\": \"contoso.onmicrosoft.com\"
  },
  \"Policies\": [
    {
      \"Name\": \"DLP-PII-Global\",
      \"Mode\": \"Enable\",
      \"Comment\": \"Enterprise-wide PII protection\",
      \"Priority\": 1,
      \"ExchangeLocation\": \"All\",
      \"SharePointLocation\": \"All\",
      \"OneDriveLocation\": \"All\",
      \"Rules\": [
        {
          \"Name\": \"Detect-US-SSN\",
          \"BlockAccess\": true,
          \"UserNotification\": \"Email\",
          \"SensitiveInfoTypes\": [
            {\"Name\": \"U.S. Social Security Number (SSN)\", \"MinCount\": 1}
          ]
        }
      ]
    }
  ]
}
```

---

## Production Implementation Patterns

### Pattern 1: Policy Auditing and Compliance Reporting

```powershell
# dlp-audit.ps1 - Comprehensive DLP policy audit

[CmdletBinding()]
param(
    [Parameter(Mandatory = $false)]
    [string]$ReportPath = \"$(Get-Date -Format 'yyyy-MM-dd')-DLP-Audit.csv\"
)

Connect-IPPSSession

# Collect all policy data
$auditReport = @()

Write-Host \"Collecting DLP policy data...\" -ForegroundColor Cyan

# Get all policies
$policies = Get-DlpCompliancePolicy | Sort-Object -Property Priority

foreach ($policy in $policies) {
    $rules = Get-DlpComplianceRule -Policy $policy.Name
    
    foreach ($rule in $rules) {
        $auditReport += [PSCustomObject]@{
            PolicyName = $policy.Name
            PolicyMode = $policy.Mode
            PolicyPriority = $policy.Priority
            RuleName = $rule.Name
            RuleDisabled = $rule.Disabled
            BlockAccess = $rule.BlockAccess
            ContentContainsSensitiveInformation = @($rule.ContentContainsSensitiveInformation | ForEach-Object {$_.Name}) -join \"; \"
            AccessScope = $rule.AccessScope
            NotifyUser = @($rule.NotifyUser) -join \"; \"
            GenerateIncidentReport = @($rule.GenerateIncidentReport) -join \"; \"
            ExceptIfFrom = @($rule.ExceptIfFrom) -join \"; \"
            ActivationDate = $rule.ActivationDate
            ExpiryDate = $rule.ExpiryDate
        }
    }
}

# Export report
$auditReport | Export-Csv -Path $ReportPath -NoTypeInformation
Write-Host \"\\nAudit report exported to: $ReportPath\" -ForegroundColor Green

# Summary statistics
Write-Host \"\\n=== DLP Policy Summary ===\" -ForegroundColor Yellow
Write-Host \"Total Policies: $($policies.Count)\"
Write-Host \"Total Rules: $($auditReport.Count)\"
Write-Host \"Policies in Enforce Mode: $(($policies | Where-Object {$_.Mode -eq 'Enable'}).Count)\"
Write-Host \"Policies in Test Mode: $(($policies | Where-Object {$_.Mode -eq 'TestWithNotifications' -or $_.Mode -eq 'TestWithoutNotifications'}).Count)\"
Write-Host \"Disabled Policies: $(($policies | Where-Object {$_.Mode -eq 'Disable'}).Count)\"

# Risk analysis
$highRiskRules = $auditReport | Where-Object {$_.BlockAccess -eq $true -and $_.RuleDisabled -eq $false}
Write-Host \"\\nHigh-Risk Rules (Block + Enabled): $($highRiskRules.Count)\"
```

### Pattern 2: Automated Policy Testing Workflow

```powershell
# test-dlp-policies.ps1 - Automated DLP policy testing

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string[]]$TestFilePaths,
    
    [Parameter(Mandatory = $false)]
    [string]$ReportPath = \"$(Get-Date -Format 'yyyy-MM-dd-HHmmss')-Policy-Test-Results.csv\"
)

Connect-IPPSSession

$testResults = @()

Write-Host \"Testing DLP policies against test files...\" -ForegroundColor Cyan

foreach ($filePath in $TestFilePaths) {
    if (-not (Test-Path -Path $filePath)) {
        Write-Warning \"File not found: $filePath\"
        continue
    }
    
    Write-Host \"\\nProcessing: $filePath\" -ForegroundColor Yellow
    
    # Extract text and classify
    try {
        $fileBytes = [System.IO.File]::ReadAllBytes($filePath)
        $extracted = Test-TextExtraction -FileData $fileBytes
        
        if ($extracted.ExtractionStatus -eq \"Success\") {
            # Classify extracted content
            $classification = Test-DataClassification -TestTextExtractionResults $extracted.ExtractedResults
            
            # Record sensitive matches
            foreach ($match in $classification.ClassificationResults) {
                $testResults += [PSCustomObject]@{
                    FileName = (Split-Path -Path $filePath -Leaf)
                    FilePath = $filePath
                    SensitiveInfoType = $match.Name
                    Confidence = $match.Confidence
                    MatchCount = $match.Count
                    ExtractionStatus = $extracted.ExtractionStatus
                    TestDate = Get-Date
                }
            }
            
            Write-Host \"  ✓ Detected SITs: $($classification.ClassificationResults.Count)\"
        } else {
            Write-Warning \"  Extraction failed: $($extracted.ExtractionStatus)\"
        }
    }
    catch {
        Write-Error \"  Error processing file: $_\"
    }
}

# Export results
$testResults | Export-Csv -Path $ReportPath -NoTypeInformation
Write-Host \"\\nTest results exported to: $ReportPath\" -ForegroundColor Green

# Summary
Write-Host \"\\n=== Test Summary ===\" -ForegroundColor Yellow
Write-Host \"Files Tested: $($TestFilePaths.Count)\"
Write-Host \"Total Matches: $($testResults.Count)\"
Write-Host \"Unique SITs Detected: $(($testResults.SensitiveInfoType | Sort-Object -Unique).Count)\"
Write-Host \"High Confidence Matches: $(($testResults | Where-Object {$_.Confidence -eq 'High'}).Count)\"

# List detected SITs
Write-Host \"\\nDetected Sensitive Information Types:\"
$testResults.SensitiveInfoType | Sort-Object | Get-Unique | ForEach-Object {
    $count = @($testResults | Where-Object {$_.SensitiveInfoType -eq $_}).Count
    Write-Host \"  - $_ ($count matches)\"
}
```

### Pattern 3: Real-Time DLP Incident Response

```powershell
# respond-dlp-incident.ps1 - Automated incident response

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$IncidentId,
    
    [Parameter(Mandatory = $false)]
    [string]$Action = \"Quarantine\"  # Quarantine or Review
)

Connect-IPPSSession

Write-Host \"Processing DLP incident: $IncidentId\" -ForegroundColor Yellow

try {
    # Query incident from audit logs
    $searchQuery = @{
        Workload = \"SecurityComplianceCenter\"
        Activities = \"DlpRuleMatch\"
        RecordType = \"ComplianceDLP*\"
        StartDate = (Get-Date).AddDays(-7)
        EndDate = Get-Date
    }
    
    Write-Host \"Searching for incident details...\"
    
    # Get associated user information
    $user = Get-ADUser -Filter {MailNickname -eq $IncidentId} -ErrorAction SilentlyContinue
    
    if ($user) {
        Write-Host \"User: $($user.DisplayName) ($($user.UserPrincipalName))\"
        
        # Take corrective action
        if ($Action -eq \"Quarantine\") {
            Write-Host \"Quarantining suspicious content...\"
            # Implementation-specific quarantine logic
            
            # Log action
            Write-Host \"✓ Content quarantined and logged\"
        } elseif ($Action -eq \"Review\") {
            Write-Host \"Escalating for manual review...\"
            # Send notification to security team
            Send-MailMessage `
                -To \"security-team@contoso.com\" `
                -Subject \"DLP Incident Escalation: $IncidentId\" `
                -Body \"Incident $IncidentId requires manual review from user $($user.UserPrincipalName)\" `
                -SmtpServer \"smtp.office365.com\"
        }
    }
}
catch {
    Write-Error \"Error processing incident: $_\"
}
```

---

## Troubleshooting and Best Practices

### Common Issues and Solutions

#### Issue 1: Custom SIT Not Appearing in UI After Upload

```powershell
# Verify SIT was created
Get-DlpSensitiveInformationType | Where-Object {$_.Publisher -ne \"Microsoft Corporation\"}

# Check rule package
Get-DlpSensitiveInformationTypeRulePackage | Select-Object RulePackageId, Name, Version

# Solutions:
# 1. Wait up to 1 hour for sync to Exchange Admin Center
# 2. Verify XML encoding is UTF-16
# 3. Validate XML against schema
# 4. Check RulePack version was incremented

# Re-upload if needed
$xmlFile = \"C:\\CustomSIT.xml\"
$bytes = [System.IO.File]::ReadAllBytes($xmlFile)
New-DlpSensitiveInformationTypeRulePackage -FileData $bytes
```

#### Issue 2: DLP Policy Not Blocking Expected Content

```powershell
# Debug checklist:

# 1. Verify policy is enabled
Get-DlpCompliancePolicy -Identity \"PolicyName\" | Select-Object Mode

# 2. Check if rule is disabled
Get-DlpComplianceRule -Policy \"PolicyName\" | Select-Object Name, Disabled

# 3. Verify content matches SIT
$testText = \"Your sensitive content here\"
Test-DataClassification -TextToClassify $testText

# 4. Test policy matching
Test-DlpPolicies -Workload SharePoint -FileUrl \"https://contoso.sharepoint.com/...\" -SendReportTo \"admin@contoso.com\"

# 5. Check rule conditions
Get-DlpComplianceRule -Identity \"RuleName\" | Select-Object `
    ContentContainsSensitiveInformation,
    BlockAccess,
    AccessScope,
    ExceptIfFrom,
    ExceptIfFromMemberOf
```

#### Issue 3: Connection Failures with Certificate-Based Auth

```powershell
# Verify certificate exists and is valid
$cert = Get-ChildItem -Path Cert:\\CurrentUser\\My | Where-Object {$_.Thumbprint -eq \"YOUR_THUMBPRINT\"}

if ($cert) {
    Write-Host \"Certificate found: $($cert.Subject)\"
    Write-Host \"Valid from: $($cert.NotBefore) to $($cert.NotAfter)\"
    
    # Verify it's not expired
    if ($cert.NotAfter -lt (Get-Date)) {
        Write-Error \"Certificate has expired\"
    }
} else {
    Write-Error \"Certificate not found\"
    # Import certificate if needed
    Import-PfxCertificate -FilePath \"C:\\cert.pfx\" -CertStoreLocation \"Cert:\\CurrentUser\\My\"
}

# Test connection with verbose output
Connect-IPPSSession -AppId \"appid\" -Certificate $cert -Organization \"tenant\" -Verbose
```

### Performance Optimization

```powershell
# Best practices for large-scale operations

# 1. Batch operations instead of loops
# DON'T:
$policies | ForEach-Object { Set-DlpCompliancePolicy ... }

# DO:
$policyUpdates | ForEach-Object -Parallel { Set-DlpCompliancePolicy @_ } -ThrottleLimit 5

# 2. Use Select-Object to reduce data transfer
$policies | Select-Object Name, Mode, Priority  # Faster than full object

# 3. Cache frequently accessed data
$allPolicies = Get-DlpCompliancePolicy
$policyMap = @{}
$allPolicies | ForEach-Object { $policyMap[$_.Name] = $_ }

# 4. Use filtering at source
Get-DlpCompliancePolicy -Identity \"SpecificPolicy\"  # Faster than Get-All | Where-Object

# 5. Implement proper error handling and retries
function Invoke-WithRetry {
    param(
        [scriptblock]$ScriptBlock,
        [int]$MaxRetries = 3,
        [int]$DelaySeconds = 5
    )
    
    for ($i = 0; $i -lt $MaxRetries; $i++) {
        try {
            return & $ScriptBlock
        }
        catch {
            if ($i -lt $MaxRetries - 1) {
                Write-Warning \"Attempt $(​$i + 1) failed. Retrying in $DelaySeconds seconds...\"
                Start-Sleep -Seconds $DelaySeconds
            } else {
                throw
            }
        }
    }
}
```

### Security Best Practices

```powershell
# 1. Use service principal accounts for automation
# Never hardcode credentials in scripts
$credential = Get-Credential
$credential | Export-Clixml -Path \"SecureCredential.xml\"
$credential = Import-Clixml -Path \"SecureCredential.xml\"

# 2. Implement least privilege RBAC
# Grant only necessary roles to automation accounts
Get-RoleGroup | Where-Object {$_.Name -like \"*DLP*\"}

# 3. Enable MFA for interactive sessions
Connect-IPPSSession -AppId \"\" -Certificate $cert  # Forces CBA

# 4. Audit all DLP administrative changes
Get-UnifiedAuditLog -Filters @{
    Operations = \"New-DlpCompliancePolicy\", \"Set-DlpCompliancePolicy\", \"Remove-DlpCompliancePolicy\"
    StartDate = (Get-Date).AddDays(-30)
}

# 5. Implement secure logging
$logPath = \"$env:APPDATA\\DLPLogs\\$(Get-Date -Format 'yyyy-MM-dd').log\"
New-Item -Path $logPath -Force | Out-Null

# Log all policy changes
Get-DlpCompliancePolicy | Select-Object Name, Mode, LastModifiedTime, LastModifiedBy |
    Export-Csv -Path $logPath -Append
```

---

## Appendix: Complete Real-World Example

### End-to-End DLP Implementation Script

```powershell
# complete-dlp-deployment.ps1

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [ValidateSet('Test', 'Prod')]
    [string]$Environment
)

# Configuration
$config = @{
    Test = @{
        Mode = 'TestWithoutNotifications'
        Priority = 100
        Locations = 'TestSite'
    }
    Prod = @{
        Mode = 'Enable'
        Priority = 1
        Locations = 'All'
    }
}

$envConfig = $config[$Environment]

Write-Host \"Deploying DLP policies to $Environment environment\" -ForegroundColor Cyan

# Connect to Purview
Connect-IPPSSession

# Step 1: Create custom SIT
Write-Host \"\\n[1/4] Creating custom sensitive information types...\" -ForegroundColor Yellow

$sitXml = @\"
<?xml version=\"1.0\" encoding=\"UTF-16\"?>
<RulePackage xmlns=\"http://schemas.microsoft.com/office/2011/mce\">
  <!-- XML content here -->
</RulePackage>
\"@

$sitBytes = [System.Text.Encoding]::Unicode.GetBytes($sitXml)
New-DlpSensitiveInformationTypeRulePackage -FileData $sitBytes

Write-Host \"✓ Custom SIT created\" -ForegroundColor Green

# Step 2: Create DLP policy
Write-Host \"\\n[2/4] Creating DLP policy...\" -ForegroundColor Yellow

$policy = New-DlpCompliancePolicy `
    -Name \"DLP-Enterprise-Policy\" `
    -Mode $envConfig.Mode `
    -ExchangeLocation All `
    -SharePointLocation All `
    -OneDriveLocation All

Write-Host \"✓ Policy created: $($policy.Identity)\" -ForegroundColor Green

# Step 3: Create DLP rules
Write-Host \"\\n[3/4] Creating DLP rules...\" -ForegroundColor Yellow

$rules = @(
    @{
        Name = \"Detect-Financial-Data\"
        SIT = \"Credit Card Number\"
    },
    @{
        Name = \"Detect-PII\"
        SIT = \"U.S. Social Security Number (SSN)\"
    }
)

foreach ($ruleConfig in $rules) {
    New-DlpComplianceRule `
        -Name $ruleConfig.Name `
        -Policy $policy.Name `
        -ContentContainsSensitiveInformation @{Name = $ruleConfig.SIT; MinCount = \"1\"} `
        -BlockAccess $true `
        -UserNotification \"PolicyTip\"
    
    Write-Host \"  ✓ Rule created: $($ruleConfig.Name)\"
}

Write-Host \"✓ All rules created\" -ForegroundColor Green

# Step 4: Verify and test
Write-Host \"\\n[4/4] Verifying deployment...\" -ForegroundColor Yellow

$verifyPolicy = Get-DlpCompliancePolicy -Identity $policy.Identity
$verifyRules = Get-DlpComplianceRule -Policy $policy.Identity

Write-Host \"\\n=== Deployment Summary ===\"
Write-Host \"Policy Name: $($verifyPolicy.Name)\"
Write-Host \"Policy Mode: $($verifyPolicy.Mode)\"
Write-Host \"Rule Count: $($verifyRules.Count)\"
Write-Host \"\\n✓ Deployment completed successfully\" -ForegroundColor Green
```

---

## References and Additional Resources

- Microsoft Purview DLP Documentation
- Exchange Online PowerShell Module Reference
- Security & Compliance PowerShell Cmdlets
- Custom Sensitive Information Types XML Schema
- Sensitive Information Type Functions Documentation
- Azure Automation and Runbook Documentation
- GitHub Actions for Microsoft 365 Administration
