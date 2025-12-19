# Microsoft Purview DLP and Information Protection PowerShell Management Guide

## Executive Summary

This technical document provides a comprehensive reference for security engineers implementing and automating Microsoft Purview Data Loss Prevention (DLP) policies, Information Protection capabilities, and custom sensitive information types using PowerShell. The document covers complete cmdlet references, advanced configuration techniques, testing methodologies, and practical integration patterns for enterprise automation frameworks.

---

## 1. Foundation and Architecture

### 1.1 Module Architecture

Microsoft Purview DLP management through PowerShell operates across multiple integrated modules:

**Exchange Online Management Module (v3.2.0+)**
- Primary module for all DLP and compliance operations
- Supports REST API-backed cmdlets (recommended)
- Replaces legacy RPS (Remote PowerShell) protocol
- Provides unified access to cloud-based compliance infrastructure

**Component Modules:**
- **Security & Compliance PowerShell (SCC)**: Core DLP policy management
- **AzureInformationProtection**: Legacy classification (transitioning to MIP)
- **ExchangePowerShell**: Modern REST-based compliance cmdlets
- **AIPService**: Rights Management backend operations

### 1.2 Authentication and Connection Strategy

```powershell
# Install or update Exchange Online Management Module
Install-Module -Name ExchangeOnlineManagement -Scope CurrentUser -Force
Update-Module -Name ExchangeOnlineManagement

# Verify module version (must be 3.2.0 or later for REST API support)
Get-Module ExchangeOnlineManagement -ListAvailable | Select-Object Name, Version

# Connect to Security & Compliance PowerShell using REST API
Connect-IPPSSession -UserPrincipalName admin@contoso.com

# For certificate-based authentication (service principals)
$CertPath = "C:\Certificates\automation.pfx"
$CertPassword = ConvertTo-SecureString -String "password" -AsPlainText -Force
$Certificate = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2
$Certificate.Import($CertPath, $CertPassword, 'DefaultKeySet')

Connect-IPPSSession -AppId "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx" `
  -Certificate $Certificate `
  -Organization "contoso.onmicrosoft.com"

# Verify connection
Get-DlpCompliancePolicy -ResultSize 1
```

**Authentication Considerations:**
- REST API mode (preferred): No WinRM basic auth required
- Legacy RPS mode: Requires WinRM basic authentication enabled
- MFA-enabled accounts: Supported with interactive authentication
- Service principals: Requires certificate thumbprint or client secret
- Graph API permissions: `InformationProtectionPolicy.Read.All`, `InformationProtectionPolicy.ReadWrite.All`

---

## 2. DLP Policy Management Cmdlets

### 2.1 Policy Creation and Configuration

**New-DlpCompliancePolicy**

Creates new DLP policies in the Purview compliance portal with comprehensive scope and location controls.

```powershell
# Basic DLP policy creation with multi-workload scope
$PolicyParams = @{
    Name = "Financial Data Protection"
    Comment = "Protects PCI-DSS and financial data across Microsoft 365"
    Mode = "TestWithNotifications"  # Values: Enable, Disable, TestWithNotifications, TestWithoutNotifications
    ExchangeLocation = "All"
    SharePointLocation = "All"
    OneDriveLocation = "All"
    TeamsLocation = "All"
    Priority = 0
}

$Policy = New-DlpCompliancePolicy @PolicyParams

# Advanced policy with adaptive scopes and endpoint DLP
$AdvancedPolicy = New-DlpCompliancePolicy -Name "Endpoint Sensitive Data" `
  -ExchangeLocation "All" `
  -EndpointDlpLocation "All" `
  -Mode "Enable" `
  -Priority 1 `
  -Confirm:$false

# Policy with excluded locations
$PolicyWithExclusions = New-DlpCompliancePolicy -Name "Selective DLP" `
  -SharePointLocation "https://contoso.sharepoint.com/sites/finance", `
    "https://contoso.sharepoint.com/sites/legal" `
  -SharePointLocationException "https://contoso.sharepoint.com/sites/public" `
  -OneDriveLocation "All" `
  -OneDriveLocationException $null

# Power BI specific DLP policy
$PowerBIPolicy = New-DlpCompliancePolicy -Name "PowerBI Datasets" `
  -PowerBIDlpLocation "workspace-id-1", "workspace-id-2" `
  -Mode "Enable" `
  -Priority 2
```

**Key Parameters:**
- `Location` Parameters: Specify workload scopes (Exchange, SharePoint, OneDrive, Teams, Endpoint, PowerBI, ThirdPartyApps)
- `Mode`: Controls enforcement behavior from audit-only to full blocking
- `Priority`: Determines policy evaluation order (lower number = higher priority)
- `AdaptiveScopes`: Target specific groups/departments via adaptive segments
- `EnforcementPlanes`: Define where actions execute (Cloud, Endpoint, OnPremises)

### 2.2 Policy Modification and Management

**Set-DlpCompliancePolicy**

Modifies existing policies without full recreation, supporting incremental location additions/removals.

```powershell
# Add new locations to existing policy
Set-DlpCompliancePolicy -Identity "Financial Data Protection" `
  -AddSharePointLocation "https://contoso.sharepoint.com/sites/accounting"

# Remove locations
Set-DlpCompliancePolicy -Identity "Financial Data Protection" `
  -RemoveOneDriveLocation "https://contoso.sharepoint.com/personal/user_contoso_com"

# Change policy mode (test to enforce)
Set-DlpCompliancePolicy -Identity "Financial Data Protection" `
  -Mode "Enable"

# Add comments and update metadata
Set-DlpCompliancePolicy -Identity "Financial Data Protection" `
  -Comment "Updated enforcement scope - Q4 2025 compliance requirements"

# Update policy priority
Set-DlpCompliancePolicy -Identity "Financial Data Protection" `
  -Priority 2

# Configure adaptive scopes for targeted enforcement
Set-DlpCompliancePolicy -Identity "Financial Data Protection" `
  -ExchangeAdaptiveScopes @{Name="Finance Department"}

# Trigger policy redistribution across endpoints
Set-DlpCompliancePolicy -Identity "Financial Data Protection" `
  -RetryDistribution
```

**Critical Notes:**
- Do NOT pipe multiple values through Foreach-Object for location additions (causes race conditions)
- Use array syntax: `-AddSharePointLocation "url1","url2","url3"`
- Policy mode changes take effect immediately across all workloads
- Distribution delays (5-10 minutes) typical for endpoint policies

### 2.3 Policy Querying and Reporting

**Get-DlpCompliancePolicy**

Retrieves policy configurations for inventory, compliance audits, and integration scenarios.

```powershell
# List all DLP policies
Get-DlpCompliancePolicy | Select-Object Name, Mode, Priority | Sort-Object Priority

# Get specific policy details
$Policy = Get-DlpCompliancePolicy -Identity "Financial Data Protection" | Format-List

# Export policy configurations to CSV
Get-DlpCompliancePolicy | Export-Csv -Path "C:\Reports\DLP_Policies.csv" -NoTypeInformation

# Filter by policy mode
Get-DlpCompliancePolicy | Where-Object {$_.Mode -eq "Enable"} | Select-Object Name, Priority

# Retrieve policy with full rule details
$Policy = Get-DlpCompliancePolicy -Identity "Financial Data Protection"
$Rules = Get-DlpComplianceRule -Policy $Policy.Identity

# Advanced reporting: Policy-to-location mapping
Get-DlpCompliancePolicy | ForEach-Object {
    [PSCustomObject]@{
        PolicyName = $_.Name
        Mode = $_.Mode
        ExchangeLocations = $_.ExchangeLocation -join ", "
        SharePointLocations = $_.SharePointLocation -join ", "
        Priority = $_.Priority
    }
} | Export-Csv -Path "C:\Reports\Policy_Mappings.csv"

# Identify policies by creation timestamp
Get-DlpCompliancePolicy | Where-Object {$_.WhenCreated -gt (Get-Date).AddDays(-7)} | 
  Select-Object Name, WhenCreated, Mode
```

### 2.4 Policy Deletion and Cleanup

**Remove-DlpCompliancePolicy**

Removes policies and associated rules from the compliance infrastructure.

```powershell
# Remove policy by name
Remove-DlpCompliancePolicy -Identity "Deprecated Policy" -Confirm:$false

# Remove policy by GUID
Remove-DlpCompliancePolicy -Identity "7e640345-1a7f-4f4e-9c17-681c070ed5e2"

# Bulk removal with confirmation
Get-DlpCompliancePolicy | Where-Object {$_.Mode -eq "Disable"} | 
  ForEach-Object {Remove-DlpCompliancePolicy -Identity $_.Identity}

# Safe removal pattern (backup then delete)
$BackupPath = "C:\Backups\DLP_$(Get-Date -Format 'yyyyMMdd_HHmmss').json"
Get-DlpCompliancePolicy | ConvertTo-Json -Depth 10 | Out-File -FilePath $BackupPath
Remove-DlpCompliancePolicy -Identity "Deprecated Policy" -Confirm:$false
```

**Safety Considerations:**
- Always backup policy configurations before removal
- Verify no dependent rules exist
- Consider archiving instead of deletion
- Use WhatIf parameter for testing: `-WhatIf`

---

## 3. DLP Rules and Conditions

### 3.1 Rule Creation with Conditions

**New-DlpComplianceRule**

Creates condition-action rules that define DLP behavior when sensitive content is detected.

```powershell
# Rule matching sensitive information types
$Rule = New-DlpComplianceRule -Name "Block Credit Card External" `
  -Policy "Financial Data Protection" `
  -ContentContainsSensitiveInformation @{Name="Credit Card Number"; minCount="1"} `
  -AccessScope "NotInOrganization" `
  -BlockAccess $true `
  -NotifyUser "LastModifier" `
  -NotifyAllowOverride @("FalsePositive", "WithJustification") `
  -NotifyPolicyTipCustomText "Financial data detected. Please verify compliance requirements."

# Multi-condition rule with AND logic
$MultiConditionRule = New-DlpComplianceRule -Name "Sensitive PII Plus Keywords" `
  -Policy "Financial Data Protection" `
  -ContentContainsSensitiveInformation @{Name="U.S. Social Security Number (SSN)"; minCount="1"} `
  -ContentContainsWords @("contract", "confidential", "secret") `
  -BlockAccess $true `
  -GenerateIncidentReport "admin@contoso.com"

# Rule with multiple SIT detections (matches any)
$MultiSitRule = New-DlpComplianceRule -Name "Any PII Detected" `
  -Policy "Financial Data Protection" `
  -ContentContainsSensitiveInformation @{Name="U.S. Social Security Number (SSN)"; minCount="1"}, `
    @{Name="Credit Card Number"; minCount="1"}, `
    @{Name="U.S. Bank Account Number"; minCount="1"} `
  -BlockAccess $true

# Rule with document properties and size conditions
$DocumentRule = New-DlpComplianceRule -Name "Large Document Block" `
  -Policy "Financial Data Protection" `
  -ContentContainsSensitiveInformation @{Name="Credit Card Number"; minCount="5"} `
  -DocumentIsRecord $true `
  -Size ">=5242880" `  # 5MB
  -BlockAccess $true

# Notification and report-only action
$AuditRule = New-DlpComplianceRule -Name "Audit Sensitive Data" `
  -Policy "Financial Data Protection" `
  -ContentContainsSensitiveInformation @{Name="Credit Card Number"; minCount="1"} `
  -GenerateAlert "On" `
  -AlertProperties @{AggregationType="SimpleAggregation"; Threshold=5}
```

**Advanced Conditions:**

```powershell
# Rule with sender domain restrictions
$SenderRule = New-DlpComplianceRule -Name "Block External PII" `
  -Policy "Financial Data Protection" `
  -ContentContainsSensitiveInformation @{Name="U.S. Social Security Number (SSN)"} `
  -SenderDomainIs "contoso.com" `
  -ExceptIfSenderDomainIs "finance.contoso.com" `
  -BlockAccess $true

# Rule with recipient conditions
$RecipientRule = New-DlpComplianceRule -Name "Block to External Recipients" `
  -Policy "Financial Data Protection" `
  -ContentContainsSensitiveInformation @{Name="Credit Card Number"} `
  -RecipientDomainIs "contoso.com" `
  -ExceptIfRecipientDomainIs "trusted-partner.com" `
  -BlockAccess $true

# Rule with activation date (phased deployment)
$ScheduledRule = New-DlpComplianceRule -Name "Future Enforcement" `
  -Policy "Financial Data Protection" `
  -ContentContainsSensitiveInformation @{Name="Custom PII"} `
  -ActivationDate (Get-Date).AddMonths(1) `
  -Mode "Enable"

# Rule with distribution group targeting
$GroupRule = New-DlpComplianceRule -Name "Finance Team Protection" `
  -Policy "Financial Data Protection" `
  -ContentContainsSensitiveInformation @{Name="Credit Card Number"} `
  -SenderMemberOf "finance-team@contoso.com" `
  -BlockAccess $true

# Advanced rule using JSON for complex conditions
$AdvancedJsonRule = @{
    "Operator" = "Not"
    "SubConditions" = @(
        @{
            "Operator" = "OR"
            "SubConditions" = @(
                @{"ConditionName" = "FromMemberOf"; "Value" = "finance@contoso.com"},
                @{"ConditionName" = "SentTo"; "Value" = "compliance@contoso.com"}
            )
        }
    )
} | ConvertTo-Json

New-DlpComplianceRule -Name "Complex Advanced Rule" `
  -Policy "Financial Data Protection" `
  -AdvancedRule $AdvancedJsonRule `
  -BlockAccess $true
```

### 3.2 Rule Modification and Updates

**Set-DlpComplianceRule**

Modifies existing rules to adjust conditions, actions, or notification behavior.

```powershell
# Update block action and access scope
Set-DlpComplianceRule -Identity "Block Credit Card External" `
  -AccessScope "All" `
  -BlockAccess $true `
  -BlockAccessScope "All"

# Modify notification recipients
Set-DlpComplianceRule -Identity "Block Credit Card External" `
  -NotifyUser "LastModifier" `
  -NotifyAllowOverride @("FalsePositive", "WithJustification") `
  -NotifyPolicyTipCustomText "Updated: Financial data policy enforcement in effect."

# Change rule priority
Set-DlpComplianceRule -Identity "Block Credit Card External" `
  -Priority 1

# Add incident reporting
Set-DlpComplianceRule -Identity "Block Credit Card External" `
  -GenerateIncidentReport "dlpadmin@contoso.com" `
  -IncidentReportContent "Default"

# Disable rule without deletion
Set-DlpComplianceRule -Identity "Block Credit Card External" `
  -Disabled $true

# Re-enable previously disabled rule
Set-DlpComplianceRule -Identity "Block Credit Card External" `
  -Disabled $false

# Update rule actions with advanced syntax
$RuleUpdate = @{
    "Operator" = "AND"
    "SubConditions" = @(
        @{"ConditionName" = "ContentContainsSensitiveInformation"; "Value" = "Credit Card"},
        @{"ConditionName" = "SentToScope"; "Value" = "External"}
    )
}

Set-DlpComplianceRule -Identity "Block Credit Card External" `
  -AdvancedRule ($RuleUpdate | ConvertTo-Json)
```

### 3.3 Rule Querying and Analysis

**Get-DlpComplianceRule**

Retrieves rule configurations for audit, compliance reporting, and troubleshooting.

```powershell
# Get all rules for specific policy
Get-DlpComplianceRule -Policy "Financial Data Protection" | 
  Select-Object Name, Priority, Disabled

# Retrieve rule details
$Rule = Get-DlpComplianceRule -Identity "Block Credit Card External" | Format-List

# List enabled rules only
Get-DlpComplianceRule | Where-Object {$_.Disabled -eq $false} | 
  Select-Object Name, Policy, Priority

# Export rules to detailed CSV
Get-DlpComplianceRule -Policy "Financial Data Protection" | 
  ForEach-Object {
    [PSCustomObject]@{
        RuleName = $_.Name
        PolicyName = $_.Policy
        Priority = $_.Priority
        BlockAccess = $_.BlockAccess
        NotifyUser = $_.NotifyUser
        Disabled = $_.Disabled
    }
  } | Export-Csv -Path "C:\Reports\DLP_Rules.csv" -NoTypeInformation

# Identify rules with specific sensitive information types
Get-DlpComplianceRule | Where-Object {$_.ContentContainsSensitiveInformation} |
  Select-Object Name, ContentContainsSensitiveInformation

# Get rule modification history
Get-DlpComplianceRule -Identity "Block Credit Card External" |
  Select-Object Name, WhenCreated, WhenChanged, ModifiedBy
```

### 3.4 Rule Deletion

**Remove-DlpComplianceRule**

Removes individual rules from policies.

```powershell
# Remove rule by name
Remove-DlpComplianceRule -Identity "Block Credit Card External" -Confirm:$false

# Remove rule by GUID
Remove-DlpComplianceRule -Identity "a1234567-890b-cdef-ghij-klmnopqrstuv"

# Remove all rules for a policy
Get-DlpComplianceRule -Policy "Financial Data Protection" |
  Remove-DlpComplianceRule -Confirm:$false

# Conditional rule removal
Get-DlpComplianceRule | Where-Object {$_.Priority -gt 10} |
  Remove-DlpComplianceRule -Confirm:$false
```

---

## 4. Custom Sensitive Information Types (SITs)

### 4.1 Built-in vs. Custom SITs

Microsoft Purview provides 200+ built-in SITs (Credit Cards, SSN, Passport Numbers, etc.). Custom SITs enable organizations to detect proprietary data patterns:

**SIT Classification:**
- **Pattern-based (Regex)**: Match text patterns with optional keywords
- **Fingerprint-based**: Match exact document templates (structural matching)
- **Trainable**: Machine learning classifiers (advanced)
- **Entity-based**: Combine multiple conditions with proximity rules

### 4.2 Creating Custom SITs via XML Rule Packages

**New-DlpSensitiveInformationTypeRulePackage**

Uploads XML-based rule packages containing custom SIT definitions with regex patterns, keywords, and confidence levels.

```powershell
# Create XML rule package for custom SIT
$XmlRulePackage = @'
<?xml version="1.0" encoding="utf-16"?>
<RulePackage xmlns="http://schemas.microsoft.com/office/2011/mce">
  <RulePack id="12345678-1234-1234-1234-123456789012">
    <Version major="1" minor="0" build="0" revision="0" />
    <Publisher id="12345678-1234-1234-1234-123456789012">
      <Name>Organization Security Team</Name>
    </Publisher>
    <Details defaultLangCode="en-us">
      <LocalizedDetails langcode="en-us">
        <PublisherName>Organization Security Team</PublisherName>
        <Name>Custom Organizational Data Types</Name>
        <Description>Custom sensitive information types for organizational data</Description>
      </LocalizedDetails>
    </Details>
  </RulePack>

  <Rules>
    <Regex id="Regex_EmployeeID">(\d{5}[A-Z])</Regex>
    <Regex id="Regex_ProjectCode">(PRJ-\d{4}-[A-Z]{2}-\d{3})</Regex>
    
    <Keyword id="Keyword_Confidential">
      <Group matchStyle="word">
        <Term>Confidential</Term>
        <Term>Internal Only</Term>
        <Term>Restricted</Term>
        <Term>Secret</Term>
      </Group>
    </Keyword>

    <Entity id="12345678-1234-1234-1234-123456789001" patternsProximity="300" recommendedConfidence="85">
      <Pattern confidenceLevel="85">
        <IdMatch idRef="Regex_EmployeeID" />
        <Any minMatches="1">
          <Match idRef="Keyword_Confidential" />
        </Any>
      </Pattern>
    </Entity>

    <Entity id="12345678-1234-1234-1234-123456789002" patternsProximity="300" recommendedConfidence="75">
      <Pattern confidenceLevel="75">
        <IdMatch idRef="Regex_ProjectCode" />
        <Any minMatches="1">
          <Match idRef="Keyword_Confidential" />
        </Any>
      </Pattern>
    </Entity>

    <LocalizedStrings>
      <Resource idRef="12345678-1234-1234-1234-123456789001">
        <Name default="true">Organization Employee ID</Name>
        <Description default="true">Detects organization employee IDs with confidential context</Description>
      </Resource>
      <Resource idRef="12345678-1234-1234-1234-123456789002">
        <Name default="true">Project Code</Name>
        <Description default="true">Detects internal project codes</Description>
      </Resource>
    </LocalizedStrings>
  </Rules>
</RulePackage>
'@

# Save XML to file
$XmlPath = "C:\RulePacks\CustomSITs.xml"
[System.IO.File]::WriteAllText($XmlPath, $XmlRulePackage, [System.Text.Encoding]::Unicode)

# Upload rule package
$FileData = [System.IO.File]::ReadAllBytes($XmlPath)
New-DlpSensitiveInformationTypeRulePackage -FileData $FileData

# Verify upload
Get-DlpSensitiveInformationType | Where-Object {$_.Publisher -notmatch "Microsoft"}
```

### 4.3 SIT Retrieval and Validation

**Get-DlpSensitiveInformationType**

Queries built-in and custom SITs to identify available classifiers and their properties.

```powershell
# List all SITs
Get-DlpSensitiveInformationType | Select-Object Name, Id, Publisher

# Get custom SITs only (non-Microsoft)
Get-DlpSensitiveInformationType | Where-Object {$_.Publisher -ne "Microsoft Corporation"}

# Retrieve specific SIT details
$EmployeeIdSit = Get-DlpSensitiveInformationType -Identity "Organization Employee ID" | Format-List

# Export SIT inventory to CSV
Get-DlpSensitiveInformationType | 
  Select-Object Name, Id, Publisher, @{Name="RulePackages"; Expression={$_.RulePackages -join ";"}} |
  Export-Csv -Path "C:\Reports\SIT_Inventory.csv" -NoTypeInformation

# Filter SITs by pattern
Get-DlpSensitiveInformationType | Where-Object {$_.Name -match "Credit"} | Select-Object Name, Id
```

### 4.4 Rule Package Management

**Get-DlpSensitiveInformationTypeRulePackage**

Manages XML rule packages containing SIT definitions.

```powershell
# List all rule packages
Get-DlpSensitiveInformationTypeRulePackage | Select-Object Id, PublisherName

# Export rule package for backup
$RulePackage = Get-DlpSensitiveInformationTypeRulePackage -Identity "12345678-1234-1234-1234-123456789012"
$RulePackage | Export-Clixml -Path "C:\Backups\RulePackage_Backup.xml"
```

**Set-DlpSensitiveInformationTypeRulePackage**

Updates existing rule packages with modified SIT definitions.

```powershell
# Update rule package with new SIT definitions
$UpdatedXml = [System.IO.File]::ReadAllBytes("C:\RulePacks\UpdatedCustomSITs.xml")
Set-DlpSensitiveInformationTypeRulePackage -Identity "12345678-1234-1234-1234-123456789012" `
  -FileData $UpdatedXml
```

**Remove-DlpSensitiveInformationTypeRulePackage**

Removes rule packages and associated custom SITs.

```powershell
# Remove rule package
Remove-DlpSensitiveInformationTypeRulePackage -Identity "12345678-1234-1234-1234-123456789012" -Confirm:$false
```

### 4.5 Document Fingerprinting

**New-DlpFingerprint**

Creates document fingerprints for structural template matching (e.g., detect exact replicas of financial templates).

```powershell
# Create fingerprint from template document
$TemplateData = [System.IO.File]::ReadAllBytes("C:\Templates\ContosoBankStatement.pdf")
$Fingerprint = New-DlpFingerprint -FileData $TemplateData `
  -Description "Contoso Bank Statement Template" `
  -IsExact $true

# Create and use fingerprint in sensitive information type
$EmployeeTemplate = [System.IO.File]::ReadAllBytes("C:\Templates\EmployeeForm.docx")
$EmployeeFingerprint = New-DlpFingerprint -FileData $EmployeeTemplate `
  -Description "Organization Employee Form" `
  -IsExact $true

$CustomerTemplate = [System.IO.File]::ReadAllBytes("C:\Templates\CustomerDatabase.xlsx")
$CustomerFingerprint = New-DlpFingerprint -FileData $CustomerTemplate `
  -Description "Customer Database Template"

# Create SIT using fingerprints
New-DlpSensitiveInformationType -Name "Template-Based Sensitive Documents" `
  -Fingerprints $EmployeeFingerprint[0], $CustomerFingerprint[0] `
  -Description "Detects documents matching organizational templates"
```

---

## 5. Testing and Validation Cmdlets

### 5.1 Text Extraction Testing

**Test-TextExtraction**

Extracts text from files for downstream DLP classification analysis (supports MSG, EML, PDF, Office documents).

```powershell
# Extract text from email file
$MessageFile = "C:\TestData\sensitive_email.msg"
$MessageData = [System.IO.File]::ReadAllBytes($MessageFile)
$ExtractionResult = Test-TextExtraction -FileData $MessageData

# Display extracted content
$ExtractionResult.ExtractedResults | Select-Object -First 5

# Extract from PDF
$PdfFile = "C:\TestData\financial_report.pdf"
$PdfData = [System.IO.File]::ReadAllBytes($PdfFile)
$PdfExtraction = Test-TextExtraction -FileData $PdfData

# Store extraction results for classification testing
$ExtractionPath = $PdfExtraction.Path
$ExtractedText = $ExtractionResult.ExtractedResults
```

### 5.2 Data Classification Testing

**Test-DataClassification**

Analyzes text strings to detect sensitive information types, confidence levels, and match counts.

```powershell
# Test single text string
$TextToClassify = "Credit card information Visa: 4532-1234-5678-9010. Customer ID: 123456"
$ClassificationResult = Test-DataClassification -TextToClassify $TextToClassify

# Display classification results
$ClassificationResult.ClassificationResults | Format-Table Name, ConfidenceLevel, Count

# Test with specific SIT targeting
$Result = Test-DataClassification -TextToClassify $TextToClassify `
  -ClassificationNames "Credit Card Number", "U.S. Social Security Number (SSN)"

# Chain extraction and classification
$ExtractedText = (Test-TextExtraction -FileData $MessageData).ExtractedResults
$Classification = Test-DataClassification -TestTextExtractionResults $ExtractedText

# Classify from file with multiple extractions
$DocumentData = [System.IO.File]::ReadAllBytes("C:\TestData\report.docx")
$ExtractionResults = Test-TextExtraction -FileData $DocumentData
$Classifications = $ExtractionResults.ExtractedResults | 
  ForEach-Object {Test-DataClassification -TextToClassify $_}

# Advanced: Convert results to JSON for analysis
$Result = Test-DataClassification -TextToClassify $TextToClassify
$ResultJson = $Result | ConvertTo-Json -Depth 10
$ParsedResult = $ResultJson | ConvertFrom-Json

# Format classification results table
($Result | ConvertTo-Json | ConvertFrom-Json).ClassificationResults | 
  Format-Table ClassificationName, ConfidenceLevel, Count -AutoSize
```

### 5.3 DLP Policy Testing

**Test-DlpPolicies**

Simulates policy evaluation against specific SharePoint/OneDrive files, providing detailed matching results.

```powershell
# Test file against DLP policies
$SiteUrl = "https://contoso.sharepoint.com/sites/finance"
$FilePath = "https://contoso.sharepoint.com/sites/finance/Documents/sensitive_report.docx"
$ReportEmail = "dlpadmin@contoso.com"

$TestResult = Test-DlpPolicies -Workload "SPO" `
  -FileUrl $FilePath `
  -SiteId (New-Guid).Guid `
  -SendReportTo $ReportEmail

# Test OneDrive files
$OneDriveFile = "https://contoso-my.sharepoint.com/personal/user_contoso_com/Documents/financial.xlsx"
Test-DlpPolicies -Workload "ODB" `
  -FileUrl $OneDriveFile `
  -SendReportTo $ReportEmail

# Extract site ID from user email
$UserEmail = "user@contoso.com"
$ExchangeRecord = Get-User -Identity $UserEmail
$OneDriveSiteId = $ExchangeRecord.RecipientTypeDetails

# Bulk test multiple files
$TestFiles = @(
    "https://contoso.sharepoint.com/sites/finance/Documents/budget.xlsx",
    "https://contoso.sharepoint.com/sites/finance/Documents/contracts.docx"
)

$TestFiles | ForEach-Object {
    Test-DlpPolicies -Workload "SPO" -FileUrl $_ -SendReportTo $ReportEmail
}

# Parse test results
Write-Host "DLP Policy Test Report Generated" -ForegroundColor Green
```

### 5.4 Message Testing for DLP

**Test-Message**

Simulates mail flow and DLP rule evaluation on test messages before deployment.

```powershell
# Test message with DLP rules
$TestMessagePath = "C:\TestData\test_email.eml"
$MessageData = [System.IO.File]::ReadAllBytes($TestMessagePath)

$TestMessageResult = Test-Message -MessageFileData $MessageData `
  -Sender "user@contoso.com" `
  -Recipients "external@example.com" `
  -SendReportTo "dlpadmin@contoso.com" `
  -UnifiedDlpRules

# Test with transport rules
Test-Message -MessageFileData $MessageData `
  -Sender "user@contoso.com" `
  -Recipients "external@example.com" `
  -SendReportTo "dlpadmin@contoso.com" `
  -TransportRules `
  -UnifiedDlpRules

# Test from inline content
$InlineMessage = @"
To: external@recipient.com
Subject: Budget Report
Body: Credit Card: 4532-1234-5678-9010, SSN: 123-45-6789
"@

$InlineData = [System.Text.Encoding]::UTF8.GetBytes($InlineMessage)
Test-Message -MessageFileData $InlineData `
  -Sender "finance@contoso.com" `
  -Recipients "partner@vendor.com" `
  -SendReportTo "compliance@contoso.com" `
  -UnifiedDlpRules `
  -Force
```

---

## 6. Information Protection and Sensitivity Labels

### 6.1 Sensitivity Label Management

**New-Label**

Creates sensitivity labels with encryption, watermarking, and marking configurations.

```powershell
# Create basic sensitivity label
$Label = New-Label -DisplayName "Confidential" `
  -Name "Confidential" `
  -Tooltip "This document contains confidential organizational information" `
  -Comment "Created for organizational data protection"

# Create label with encryption and content marking
$EncryptedLabel = New-Label -DisplayName "Highly Confidential" `
  -Name "HighlyConfidential" `
  -Tooltip "Restricted access with encryption" `
  -EncryptionEnabled $true `
  -EncryptionProtectionType "UserDefined"

# Label with footer marking
Set-Label -Identity $Label.Id `
  -LabelActions '[{
    "Type": "applycontentmarking",
    "SubType": "footer",
    "Settings": [
      {"Key": "fontsize", "Value": "10"},
      {"Key": "placement", "Value": "Footer"},
      {"Key": "text", "Value": "Classification: Confidential"},
      {"Key": "fontcolor", "Value": "#FF0000"}
    ]
  }]'

# Label with watermark
Set-Label -Identity $Label.Id `
  -LabelActions '[{
    "Type": "applywatermarking",
    "SubType": null,
    "Settings": [
      {"Key": "fontsize", "Value": "12"},
      {"Key": "layout", "Value": "Diagonal"},
      {"Key": "fontcolor", "Value": "#FF0000"},
      {"Key": "text", "Value": "CONFIDENTIAL"}
    ]
  }]'

# Create multiple labels efficiently
$LabelDefinitions = @(
    @{DisplayName="Public"; Name="Public"; Tooltip="Public information"},
    @{DisplayName="Internal"; Name="Internal"; Tooltip="Internal use only"},
    @{DisplayName="Confidential"; Name="Confidential"; Tooltip="Restricted access"}
)

$LabelDefinitions | ForEach-Object {
    New-Label -DisplayName $_.DisplayName -Name $_.Name -Tooltip $_.Tooltip
}
```

**Get-Label**

Retrieves sensitivity label configurations for auditing and integration.

```powershell
# List all sensitivity labels
Get-Label | Select-Object Name, DisplayName, Priority

# Get label with detailed actions
Get-Label -Identity "Confidential" -IncludeDetailedLabelActions | Format-List

# Export labels to CSV
Get-Label | Select-Object Name, DisplayName, Priority, ContentType |
  Export-Csv -Path "C:\Reports\Sensitivity_Labels.csv" -NoTypeInformation

# Find labels by priority
Get-Label | Sort-Object Priority | Select-Object Priority, DisplayName
```

**Set-Label**

Modifies label configurations including priority and policy settings.

```powershell
# Update label priority
Set-Label -Identity "Confidential" -Priority 1

# Update label tooltip and description
Set-Label -Identity "Confidential" `
  -Tooltip "Updated: Restricted organizational data" `
  -Comment "Revised encryption and marking policies"

# Apply encryption to existing label
Set-Label -Identity "HighlyConfidential" `
  -EncryptionEnabled $true `
  -EncryptionProtectionType "DoubleKeyEncryption"

# Remove label
Remove-Label -Identity "Deprecated" -Confirm:$false
```

### 6.2 Label Policy Management

**New-LabelPolicy**

Creates and publishes sensitivity label policies to specific workloads and users.

```powershell
# Create basic label policy
$LabelPolicy = New-LabelPolicy -Name "Finance Department Labels" `
  -Labels "Confidential", "Internal" `
  -AddExchangeLocation "All" `
  -AddSharePointLocation "https://contoso.sharepoint.com/sites/finance"

# Advanced policy with user/group targeting
$AdvancedPolicy = New-LabelPolicy -Name "Executive Labels" `
  -Labels "Executive Confidential" `
  -AddExchangeLocation "All" `
  -AddOneDriveLocation "All" `
  -AdvancedSettings @{
    "defaultLabelId" = "confidential-label-id"
    "enableMandatoryLabeling" = $true
    "requireDowngradeJustification" = $true
  }

# Publish labels to specific SharePoint sites
$SitePolicy = New-LabelPolicy -Name "Legal Department Labels" `
  -Labels "Legal Confidential", "Attorney-Client Privilege" `
  -AddSharePointLocation "https://contoso.sharepoint.com/sites/legal" `
  -Comment "Applied to legal department SharePoint site"
```

**Get-LabelPolicy**

Retrieves label policy configurations and publishing locations.

```powershell
# List all label policies
Get-LabelPolicy | Select-Object Name, Priority

# Get policy details
Get-LabelPolicy -Identity "Finance Department Labels" | Format-List

# Export policies to CSV
Get-LabelPolicy | Select-Object Name, ExchangeLocation, SharePointLocation |
  Export-Csv -Path "C:\Reports\Label_Policies.csv" -NoTypeInformation
```

**Set-LabelPolicy**

Modifies label policy settings including location scope and label assignments.

```powershell
# Add labels to policy
Set-LabelPolicy -Identity "Finance Department Labels" `
  -AddLabels "Restricted", "For Official Use Only"

# Change policy scope
Set-LabelPolicy -Identity "Finance Department Labels" `
  -AddOneDriveLocation "All" `
  -AddTeamsLocation "All"

# Update advanced settings
Set-LabelPolicy -Identity "Finance Department Labels" `
  -AdvancedSettings @{enableMandatoryLabeling = $true}
```

### 6.3 Auto-Labeling Policies

**New-AutoSensitivityLabelPolicy**

Creates policies for automatic label application based on sensitive content detection.

```powershell
# Create auto-labeling policy
$AutoLabelPolicy = New-AutoSensitivityLabelPolicy -Name "Auto-Label Financial Data" `
  -Comment "Automatically labels documents containing financial information" `
  -SharePointLocation "https://contoso.sharepoint.com/sites/finance" `
  -ApplySensitivityLabel "Confidential" `
  -Mode "TestWithoutNotifications"

# Advanced auto-labeling with conditions
$AdvancedAutoPolicy = New-AutoSensitivityLabelPolicy -Name "PII Auto-Label" `
  -Comment "Automatically protects PII-containing documents" `
  -OneDriveLocation "All" `
  -SharePointLocation "All" `
  -ApplySensitivityLabel "Highly Confidential" `
  -ContentContainsSensitiveInformation @{Name="U.S. Social Security Number"; MinCount="1"} `
  -Mode "Enable"

# Switch from testing to enforcement
Set-AutoSensitivityLabelPolicy -Identity "Auto-Label Financial Data" `
  -Mode "Enable"
```

---

## 7. Advanced Integration and Automation Patterns

### 7.1 CI/CD Pipeline Integration

**GitHub Actions Workflow for DLP Policy Deployment**

```yaml
name: Deploy DLP Policies
on:
  push:
    branches: [main]
    paths:
      - 'dlp-policies/**'
jobs:
  deploy:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      
      - name: Install PowerShell Modules
        run: |
          pwsh -Command "Install-Module ExchangeOnlineManagement -Force -Scope CurrentUser"
      
      - name: Authenticate to Microsoft 365
        run: |
          pwsh -Command {
            $CertPath = "${{ secrets.CERT_PATH }}"
            $CertPassword = ConvertTo-SecureString "${{ secrets.CERT_PASSWORD }}" -AsPlainText -Force
            $Cert = Get-PfxCertificate -FilePath $CertPath -Password $CertPassword
            Connect-IPPSSession -AppId "${{ secrets.APP_ID }}" -Certificate $Cert -Organization "${{ secrets.TENANT }}"
          }
      
      - name: Deploy DLP Policies
        run: |
          pwsh -File ./scripts/Deploy-DLPPolicies.ps1
          
      - name: Run Policy Tests
        run: |
          pwsh -File ./scripts/Test-DLPPolicies.ps1
```

### 7.2 Python REST API Integration

```python
import requests
import json
from azure.identity import ClientSecretCredential

class PurviewDLPClient:
    def __init__(self, tenant_id, client_id, client_secret):
        self.tenant_id = tenant_id
        self.client_id = client_id
        self.client_secret = client_secret
        self.token = self._get_token()
    
    def _get_token(self):
        """Acquire access token for Microsoft Graph"""
        credential = ClientSecretCredential(
            tenant_id=self.tenant_id,
            client_id=self.client_id,
            client_secret=self.client_secret
        )
        token = credential.get_token("https://graph.microsoft.com/.default")
        return token.token
    
    def invoke_powershell_cmdlet(self, cmdlet):
        """Execute PowerShell cmdlet via Graph API"""
        headers = {
            'Authorization': f'Bearer {self.token}',
            'Content-Type': 'application/json'
        }
        
        payload = {
            "commands": [{"commandType": 1, "command": cmdlet}]
        }
        
        response = requests.post(
            "https://graph.microsoft.com/v1.0/deviceManagement/powershellScripts",
            headers=headers,
            json=payload
        )
        
        return response.json()
    
    def get_dlp_policies(self):
        """Retrieve all DLP policies via PowerShell"""
        cmdlet = "Get-DlpCompliancePolicy | ConvertTo-Json"
        return self.invoke_powershell_cmdlet(cmdlet)

# Usage
client = PurviewDLPClient(
    tenant_id="tenant-id",
    client_id="client-id",
    client_secret="client-secret"
)
policies = client.get_dlp_policies()
```

### 7.3 Infrastructure as Code (Terraform)

```hcl
# Provider configuration
terraform {
  required_providers {
    azuread = {
      source = "hashicorp/azuread"
    }
    http = {
      source = "hashicorp/http"
    }
  }
}

# Data source for DLP policy retrieval via PowerShell
resource "null_resource" "get_dlp_policies" {
  provisioners "local-exec" {
    command = "pwsh -Command {Connect-IPPSSession -AppId 'xxx' -Certificate (Get-PfxCertificate -FilePath 'cert.pfx'); Get-DlpCompliancePolicy | ConvertTo-Json | Out-File dlp_policies.json}"
  }
}

# Local variable from PowerShell output
locals {
  dlp_policies = jsondecode(file("${path.module}/dlp_policies.json"))
}
```

### 7.4 Enterprise Automation Framework

```powershell
# Comprehensive automation module
function Deploy-DLPPolicies {
    param(
        [Parameter(Mandatory = $true)]
        [PSObject[]]$PolicyDefinitions,
        
        [Parameter(Mandatory = $false)]
        [Switch]$DryRun,
        
        [Parameter(Mandatory = $false)]
        [String]$BackupPath = "C:\DLP_Backups"
    )
    
    # Backup existing policies
    if (-not (Test-Path $BackupPath)) {
        New-Item -ItemType Directory -Path $BackupPath | Out-Null
    }
    
    $BackupFile = Join-Path $BackupPath "DLP_Backup_$(Get-Date -Format 'yyyyMMdd_HHmmss').json"
    Get-DlpCompliancePolicy | ConvertTo-Json -Depth 10 | Out-File -FilePath $BackupFile
    Write-Host "Policies backed up to $BackupFile" -ForegroundColor Green
    
    # Deploy policies
    foreach ($PolicyDef in $PolicyDefinitions) {
        $PolicyName = $PolicyDef.Name
        
        try {
            # Check if policy exists
            $ExistingPolicy = Get-DlpCompliancePolicy -Identity $PolicyName -ErrorAction SilentlyContinue
            
            if ($ExistingPolicy) {
                if ($DryRun) {
                    Write-Host "[DRY-RUN] Would update policy: $PolicyName" -ForegroundColor Yellow
                } else {
                    Set-DlpCompliancePolicy -Identity $PolicyName @$PolicyDef
                    Write-Host "Updated policy: $PolicyName" -ForegroundColor Green
                }
            } else {
                if ($DryRun) {
                    Write-Host "[DRY-RUN] Would create policy: $PolicyName" -ForegroundColor Yellow
                } else {
                    New-DlpCompliancePolicy @$PolicyDef
                    Write-Host "Created policy: $PolicyName" -ForegroundColor Green
                }
            }
        }
        catch {
            Write-Host "Error processing policy $PolicyName : $_" -ForegroundColor Red
        }
    }
}

# Usage
$Policies = @(
    @{
        Name = "Financial Data Protection"
        Mode = "Enable"
        ExchangeLocation = "All"
        Priority = 0
    }
)

Deploy-DLPPolicies -PolicyDefinitions $Policies
```

---

## 8. Troubleshooting and Diagnostics

### 8.1 Common Issues and Resolution

| Issue | Cause | Resolution |
|-------|-------|-----------|
| "Insufficient Graph Permissions" | Missing API permissions | Grant `InformationProtectionPolicy.ReadWrite.All` in Azure AD |
| "Connection denied" | RPS mode on unsupported version | Update to ExchangeOnlineManagement 3.2.0+ for REST API |
| "SIT not detecting content" | Low confidence threshold | Lower confidence level (85→75) or update pattern matching |
| "Policy not applying" | Distribution delay | Wait 5-10 minutes for endpoint distribution |
| "Rule validation failed" | Invalid condition syntax | Validate JSON structure in AdvancedRule parameter |

### 8.2 Logging and Auditing

```powershell
# Enable verbose logging
$VerbosePreference = "Continue"
Connect-IPPSSession -UserPrincipalName admin@contoso.com -Verbose

# Search audit logs for DLP events
$StartDate = (Get-Date).AddDays(-30)
$EndDate = Get-Date

Search-UnifiedAuditLog -StartDate $StartDate -EndDate $EndDate -RecordType DataLossPrevention |
  Select-Object CreationDate, UserIds, Operation, AuditData |
  Export-Csv -Path "C:\Reports\DLP_Audit.csv"

# Export detailed DLP incident data
Get-DlpCompliancePolicy | ForEach-Object {
    Get-DlpComplianceRule -Policy $_.Identity
} | Export-Csv -Path "C:\Reports\DLP_Configuration.csv"
```

### 8.3 Debugging Custom SITs

```powershell
# Test SIT pattern matching
$TestStrings = @(
    "Employee ID: ABC123DEF",
    "Project Code: PRJ-2024-FIN-001",
    "No sensitive data here"
)

$TestStrings | ForEach-Object {
    $Result = Test-DataClassification -TextToClassify $_
    Write-Host "Text: $_"
    Write-Host "Matches: $($Result.ClassificationResults | ConvertTo-Json)`n"
}

# Validate XML rule package syntax
[xml]$RulePackageXml = Get-Content "C:\RulePacks\CustomSITs.xml"
$RulePackageXml.SelectNodes("//Entity") | ForEach-Object {
    Write-Host "Entity ID: $($_.Id)" -ForegroundColor Cyan
    Write-Host "Patterns: $($_.Pattern.Count)"
}
```

---

## 9. Security Best Practices

### 9.1 RBAC and Least Privilege

```powershell
# Create custom RBAC role for DLP administrators
# Minimum required roles: DLP Administrator, Compliance Administrator

# Restrict policy modification to specific administrators
Get-DlpCompliancePolicy | Where-Object {$_.Name -match "Critical"} |
  Set-DlpCompliancePolicy -PolicyRBACScopes "FinanceAdmins"

# Audit role assignments
Get-RoleGroupMember "DLP Administrators" | Select-Object Name, PrimarySmtpAddress
```

### 9.2 Policy Versioning and Change Management

```powershell
# Implement version control for policies
$PolicyVersion = 1
$PolicyName = "Financial Data Protection_v$PolicyVersion"

# Export current state before modifications
Get-DlpCompliancePolicy -Identity "Financial Data Protection" |
  Export-Clixml -Path "C:\PolicyVersions\policy_v$PolicyVersion.xml"

# Store policy changes in change log
$ChangeLog = @{
    Timestamp = Get-Date
    Operation = "Updated rule conditions"
    Administrator = $env:USERNAME
    PolicyName = "Financial Data Protection"
    Details = "Increased confidence threshold from 75 to 85"
} | ConvertTo-Json | Out-File -FilePath "C:\Logs\DLP_ChangeLog.json" -Append
```

### 9.3 Secure Credential Management

```powershell
# Use certificate-based authentication (service principal)
$CertThumbprint = "ABCDEF1234567890ABCDEF1234567890ABCDEF12"
Connect-IPPSSession -AppId "xxxxx" `
  -CertificateThumbprint $CertThumbprint `
  -Organization "contoso.onmicrosoft.com"

# Avoid storing credentials in scripts
# Use Azure Key Vault for sensitive data
$KeyVaultName = "ContosoKeyVault"
$SecretName = "DLPAdminCert"
$CertSecret = Get-AzKeyVaultSecret -VaultName $KeyVaultName -Name $SecretName

# Never use plaintext passwords
# Always use SecureString for sensitive parameters
$SecurePassword = Read-Host -Prompt "Enter password" -AsSecureString
ConvertFrom-SecureString -SecureString $SecurePassword | Out-File "C:\Secrets\encrypted.txt"
```

---

## 10. Appendix: Complete Automation Script Template

```powershell
<#
.SYNOPSIS
Enterprise DLP Policy Automation Framework

.DESCRIPTION
Comprehensive PowerShell framework for deploying, testing, and managing DLP policies
across Microsoft 365 tenants with CI/CD integration support.

.PARAMETER TenantId
Azure AD Tenant ID

.PARAMETER AppId
Service principal application ID

.PARAMETER CertificatePath
Path to certificate PFX file for authentication

.EXAMPLE
./Deploy-DLPFramework.ps1 -TenantId "xxxxx" -AppId "yyyyy" -CertificatePath "C:\cert.pfx"
#>

param(
    [Parameter(Mandatory = $true)]
    [String]$TenantId,
    
    [Parameter(Mandatory = $true)]
    [String]$AppId,
    
    [Parameter(Mandatory = $true)]
    [String]$CertificatePath,
    
    [Parameter(Mandatory = $false)]
    [Switch]$DryRun
)

# Initialize logging
$LogFile = "C:\Logs\DLP_Deployment_$(Get-Date -Format 'yyyyMMdd_HHmmss').log"
function Write-Log {
    param([String]$Message, [String]$Level = "INFO")
    $Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $LogMessage = "[$Timestamp] [$Level] $Message"
    Write-Host $LogMessage
    Add-Content -Path $LogFile -Value $LogMessage
}

try {
    Write-Log "Starting DLP deployment framework..."
    
    # Authenticate to tenant
    $Certificate = Get-PfxCertificate -FilePath $CertificatePath
    Connect-IPPSSession -AppId $AppId -Certificate $Certificate -Organization "$TenantId.onmicrosoft.com"
    
    Write-Log "Successfully authenticated to tenant: $TenantId"
    
    # Backup existing policies
    $BackupPath = "C:\DLP_Backups\$(Get-Date -Format 'yyyyMMdd')"
    New-Item -ItemType Directory -Path $BackupPath -Force | Out-Null
    Get-DlpCompliancePolicy | ConvertTo-Json -Depth 10 | 
      Out-File -FilePath "$BackupPath\policies_backup.json"
    
    Write-Log "Policies backed up to $BackupPath"
    
    # Deploy policies from configuration
    $PolicyConfig = Import-Csv -Path "C:\DLP_Config\policies.csv"
    
    foreach ($Policy in $PolicyConfig) {
        try {
            $Params = @{
                Name = $Policy.Name
                Mode = $Policy.Mode
                ExchangeLocation = $Policy.ExchangeLocation
                Priority = [Int32]$Policy.Priority
            }
            
            $Existing = Get-DlpCompliancePolicy -Identity $Policy.Name -ErrorAction SilentlyContinue
            
            if ($Existing) {
                if ($DryRun) {
                    Write-Log "[DRY-RUN] Would update policy: $($Policy.Name)" -Level "WARN"
                } else {
                    Set-DlpCompliancePolicy -Identity $Policy.Name @Params
                    Write-Log "Updated policy: $($Policy.Name)" -Level "SUCCESS"
                }
            } else {
                if ($DryRun) {
                    Write-Log "[DRY-RUN] Would create policy: $($Policy.Name)" -Level "WARN"
                } else {
                    New-DlpCompliancePolicy @Params
                    Write-Log "Created policy: $($Policy.Name)" -Level "SUCCESS"
                }
            }
        }
        catch {
            Write-Log "Error processing policy $($Policy.Name): $_" -Level "ERROR"
        }
    }
    
    # Run validation tests
    Write-Log "Running policy validation tests..."
    
    $TestFiles = Get-ChildItem -Path "C:\TestData\*.xlsx", "C:\TestData\*.docx"
    foreach ($File in $TestFiles) {
        $TestResult = Test-DlpPolicies -Workload "SPO" -FileUrl $File.FullName -SendReportTo "admin@contoso.com"
        Write-Log "Test result for $($File.Name): $(if ($TestResult.IsMatched) { 'MATCHED' } else { 'NO MATCH' })"
    }
    
    Write-Log "DLP deployment framework completed successfully" -Level "SUCCESS"
}
catch {
    Write-Log "Fatal error: $_" -Level "ERROR"
    exit 1
}
finally {
    Disconnect-IPPSSession
}
```

---

## Conclusion

This comprehensive guide provides security engineers with the technical depth required to implement enterprise-grade DLP solutions using PowerShell. By leveraging the cmdlet ecosystem, custom SITs, and automation frameworks, organizations can achieve scalable, auditable data protection across Microsoft 365 and beyond.

For advanced implementation support, refer to the official Microsoft Learn documentation and leverage the validation cmdlets (Test-TextExtraction, Test-DataClassification, Test-DlpPolicies) for continuous testing and refinement of your DLP infrastructure.