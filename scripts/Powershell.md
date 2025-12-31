# Microsoft Purview PowerShell Management

## oberview

Managing Microsoft Purview using PowerShell, inclusing Data Loss Prevention (DLP), Information Protection, custom Sensitive Information Types (SITs), and enterprise automation frameworks.

---

## Table of Contents

1. [Module Architecture & Prerequisites](#module-architecture--prerequisites)
2. [Connection & Authentication](#connection--authentication)
3. [DLP Policy Management](#dlp-policy-management)
4. [Sensitive Information Types (SITs)](#sensitive-information-types-sits)
5. [Information Protection & Sensitivity Labels](#information-protection--sensitivity-labels)
6. [Testing & Validation Cmdlets](#testing--validation-cmdlets)
7. [Compliance & eDiscovery Operations](#compliance--ediscovery-operations)
8. [Enterprise Integration Patterns](#enterprise-integration-patterns)
9. [Automation & CI/CD Deployment](#automation--cicd-deployment)
10. [Advanced Troubleshooting](#advanced-troubleshooting)

---

## Module Architecture & Prerequisites

### PowerShell Module Ecosystem

Microsoft Purview management operates across multiple specialized modules, each serving distinct purposes within the compliance and data governance stack:

**Security & Compliance PowerShell Module**
The primary module for managing Purview compliance features, available through the Exchange Online Management framework. This module provides cmdlets for DLP policies, retention policies, sensitivity labels, custom SITs, eDiscovery cases, and compliance searches.

**ExchangeOnlineManagement Module**
This module serves as the foundational connectivity layer for both Exchange Online and Security & Compliance PowerShell. It includes the connection cmdlet `Connect-IPPSSession` that establishes authenticated sessions to the Purview compliance portal.

**PurviewInformationProtection Module**
Dedicated to client-side information protection operations. This module supports file labeling, protection removal, scanner deployment, and unattended labeling scenarios. It requires separate installation and configuration distinct from Security & Compliance PowerShell.

**AIPService Module**
For Azure Rights Management service administration, supporting protection service configuration, super-user features, and Azure RMS policy management. This module is often overlooked but critical for advanced information protection deployments.

### Prerequisites & Environmental Requirements

```powershell
# Prerequisites Checklist
# 1. PowerShell Version: 7.x minimum (PowerShell Core recommended)
# 2. Module Installation Requirements:
#    - ExchangeOnlineManagement v3.0.0 or later
#    - Windows PowerShell execution policy: RemoteSigned (minimum)
#    - Administrative privileges for module installation

# Verify PowerShell version
$PSVersionTable.PSVersion

# Set execution policy (if needed)
Set-ExecutionPolicy -Scope CurrentUser RemoteSigned -Force

# Check current execution policy
Get-ExecutionPolicy -List

# Install or update ExchangeOnlineManagement module
Install-Module -Name ExchangeOnlineManagement -Scope CurrentUser -Force -AllowClobber

# Verify module installation
Get-Module ExchangeOnlineManagement -ListAvailable
```

### Role-Based Access Control (RBAC) Requirements

Cmdlet execution requires specific Purview role assignments within the compliance portal:

| Operation Category | Required Roles | Permission Level |
|---|---|---|
| DLP Policy Management | Compliance Administrator, Compliance Data Administrator | Full create, read, update, delete |
| Sensitivity Labels | Compliance Administrator, Compliance Data Administrator | Full management |
| Custom SITs | Compliance Administrator, Compliance Data Administrator | Create and manage rule packages |
| eDiscovery Case Management | eDiscovery Manager, eDiscovery Administrator | Case-dependent scoped access |
| Audit & Search | Compliance Administrator, Audit Manager | Read-only or limited access |
| Endpoint DLP | Compliance Data Administrator | Required for endpoint-specific parameters |

Verify role assignments before executing scripts:

```powershell
# This will fail gracefully if insufficient permissions exist
Get-DlpCompliancePolicy -Identity "TestPolicy" -ErrorAction SilentlyContinue
```

---

## Connection & Authentication

### Session Establishment

The `Connect-IPPSSession` cmdlet establishes the foundation for all Purview operations. This cmdlet differs fundamentally from `Connect-ExchangeOnline` and must be used for compliance-related operations.

```powershell
# Interactive Connection (Recommended for initial setup)
Connect-IPPSSession -UserPrincipalName "admin@contoso.com"

# Connection with MFA (Automatic prompt if required)
Connect-IPPSSession -UserPrincipalName "admin@contoso.com" -PSSessionOption (New-PSSessionOption -ProxyAccessType NoProxyServer)

# Connection to Specific Environment (Compliance Only)
Connect-IPPSSession -UserPrincipalName "admin@contoso.com" -ConnectionUri https://ps.compliance.protection.outlook.com/powershell-liveid/

# Verify Active Session
Get-PSSession | Where-Object { $_.ConfigurationName -like "*Compliance*" }
```

### Unattended (Service Account) Authentication

For production automation scenarios requiring service account execution without interactive prompts:

```powershell
# Method 1: Credential object (Legacy - less recommended)
$securePassword = ConvertTo-SecureString -String "Password123!" -AsPlainText -Force
$credential = New-Object System.Management.Automation.PSCredential("svc-purview@contoso.com", $securePassword)
Connect-IPPSSession -Credential $credential -UserPrincipalName "svc-purview@contoso.com"

# Method 2: Application-based authentication with certificate (Recommended)
# Prerequisites: Self-signed or CA certificate, app registration in Entra ID with appropriate permissions
$CertThumbprint = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
$AppID = "12345678-1234-1234-1234-123456789012"
$Organization = "contoso.onmicrosoft.com"

Connect-ExchangeOnline -CertificateThumbprint $CertThumbprint -AppId $AppID -Organization $Organization

# Method 3: Managed Identity (Azure Automation / Azure Functions)
Connect-IPPSSession -ManagedIdentity -Organization $Organization
```

### Connection State Management

```powershell
# Check connection status and properties
$session = Get-PSSession | Where-Object { $_.ConfigurationName -like "*Compliance*" }
$session | Select-Object ComputerName, State, Availability, ConfigurationName

# Refresh token if connection drops (automatic reconnection)
Connect-IPPSSession -UserPrincipalName "admin@contoso.com" -UseRPSSession $false

# Disconnect and cleanup
Get-PSSession | Where-Object { $_.ConfigurationName -like "*Compliance*" } | Remove-PSSession
```

---

## DLP Policy Management

### Policy Architecture

DLP policies in Microsoft Purview consist of two interdependent components:

**Policy Container**: Defines scope (workloads, locations, users/groups) and enforcement mode
**Policy Rules**: Define detection conditions, sensitive information types, and actions

### Creating DLP Policies

#### Basic Policy Creation

```powershell
# Connect to Purview compliance
Connect-IPPSSession -UserPrincipalName "admin@contoso.com"

# Create a basic DLP policy with test mode
$policyParams = @{
    Name = "Global-PII-Policy-v1"
    Mode = "TestWithNotifications"
    Comment = "Global policy detecting US PII across all M365 workloads"
    ExchangeLocation = "All"
    SharePointLocation = "All"
    OneDriveLocation = "All"
    TeamsLocation = "All"
}

$newPolicy = New-DlpCompliancePolicy @policyParams

# Retrieve policy details
Get-DlpCompliancePolicy -Identity "Global-PII-Policy-v1" | Format-List

# Display distribution status across tenant
Get-DlpCompliancePolicy -Identity "Global-PII-Policy-v1" -DistributionDetail | Format-List DistributionStatus
```

#### Advanced Policy Creation with Scoping

```powershell
# Scoped policy targeting specific user groups
$dlpParams = @{
    Name = "Finance-Dept-DLP-Policy"
    Comment = "DLP policy scoped to Finance department only"
    ExchangeLocation = "All"
    ExchangeSenderMemberOf = @("FinanceTeam@contoso.com", "CFOGroup@contoso.com")
    SharePointLocation = "https://contoso.sharepoint.com/sites/Finance", "https://contoso.sharepoint.com/sites/Accounting"
    OneDriveLocation = "All"
    OneDriveSharedByMemberOf = @("FinanceTeam@contoso.com")
    Mode = "Enable"
    Priority = 1
}

New-DlpCompliancePolicy @dlpParams

# Policy with exceptions (users/locations excluded)
$policyWithExceptions = @{
    Name = "Broad-PII-Policy"
    ExchangeLocation = "All"
    ExchangeSenderMemberOfException = @("ExternalPartners@contoso.com")
    SharePointLocation = "All"
    SharePointLocationException = "https://contoso.sharepoint.com/sites/PublicInfo"
    Mode = "TestWithNotifications"
}

New-DlpCompliancePolicy @policyWithExceptions
```

#### Endpoint DLP Policy Creation

```powershell
# Endpoint DLP applies to devices where users are logged in
$endpointParams = @{
    Name = "Endpoint-DLP-Devices"
    Comment = "DLP enforcement on managed endpoints"
    EndpointDlpLocation = @("user1@contoso.com", "user2@contoso.com", "user3@contoso.com")
    Mode = "TestWithNotifications"
}

New-DlpCompliancePolicy @endpointParams

# Endpoint policy with all users but excluding specific accounts
$endpointExceptParams = @{
    Name = "Endpoint-Global-Policy"
    EndpointDlpLocation = "All"
    EndpointDlpLocationException = @("contractor@contoso.com", "tempuser@contoso.com")
    Mode = "Enable"
}

New-DlpCompliancePolicy @endpointExceptParams
```

#### Power BI DLP Policy Creation

```powershell
# Power BI DLP only applies to Premium Gen2 workspaces
$powerBIParams = @{
    Name = "PowerBI-Sensitive-Data-Policy"
    Comment = "DLP for Power BI Premium Gen2 workspaces"
    PowerBIDlpLocation = "All"
    PowerBIDlpLocationException = @("workspace-id-1", "workspace-id-2")
    Mode = "TestWithNotifications"
}

New-DlpCompliancePolicy @powerBIParams

# Find Power BI workspace IDs via PowerShell
# Get-PowerBIWorkspace | Select-Object Name, Id
```

### Policy Modification & Maintenance

```powershell
# Update policy comment and priority
Set-DlpCompliancePolicy `
    -Identity "Global-PII-Policy-v1" `
    -Comment "Updated policy version 1.1 - Added Teams monitoring" `
    -Priority 2

# Modify policy mode from test to enforcement
Set-DlpCompliancePolicy `
    -Identity "Global-PII-Policy-v1" `
    -Mode "Enable"

# Expand policy to include additional locations
$currentPolicy = Get-DlpCompliancePolicy -Identity "Global-PII-Policy-v1"
Set-DlpCompliancePolicy `
    -Identity "Global-PII-Policy-v1" `
    -SharePointLocation @($currentPolicy.SharePointLocation + "https://contoso.sharepoint.com/sites/NewSite")

# Disable policy without deletion
Set-DlpCompliancePolicy `
    -Identity "Global-PII-Policy-v1" `
    -Mode "Disable"

# Permanently delete policy (irreversible)
Remove-DlpCompliancePolicy -Identity "Global-PII-Policy-v1" -Confirm:$false
```

### DLP Rule Creation & Management

DLP rules define the specific conditions that trigger policy actions. Each policy must contain at least one rule.

```powershell
# Create a basic DLP rule targeting credit card detection
$ruleParams = @{
    Name = "Detect-Credit-Cards"
    Policy = "Global-PII-Policy-v1"
    ContentContainsSensitiveInformation = @{
        Name = "Credit Card Number"
        minCount = "1"
    }
    BlockAccess = $true
    BlockAccessScope = "All"
    UserNotification = "Email"
    NotificationUserMessage = "Sensitive financial data detected. Please review content before sending."
}

New-DlpComplianceRule @ruleParams

# Create rule with multiple sensitive information types (OR logic)
$multiSitRule = @{
    Name = "Detect-Multiple-PII-Types"
    Policy = "Global-PII-Policy-v1"
    ContentContainsSensitiveInformation = @(
        @{ Name = "U.S. Social Security Number (SSN)"; minCount = "1" },
        @{ Name = "Credit Card Number"; minCount = "1" },
        @{ Name = "U.S. Bank Account Number"; minCount = "1" }
    )
    IncidentReportContent = @("Detections", "Severity", "Source", "MatchedContent")
    ReportSeverityLevel = "High"
    NotifyUser = @("Restricted")
}

New-DlpComplianceRule @multiSitRule

# Rule with exceptions for specific recipient domain
$ruleWithExceptions = @{
    Name = "Detect-PII-Except-Legal"
    Policy = "Global-PII-Policy-v1"
    ContentContainsSensitiveInformation = @{
        Name = "U.S. Social Security Number (SSN)"
        minCount = "1"
    }
    ExceptIfRecipientDomainIs = @("legal.contoso.com", "compliance.contoso.com")
    BlockAccess = $true
    AllowOverride = "FalsyPositiveOverride"
    OverrideJustificationRequired = $true
}

New-DlpComplianceRule @ruleWithExceptions

# Rule targeting specific file types
$fileTypeRule = @{
    Name = "Detect-PII-in-Docs"
    Policy = "Global-PII-Policy-v1"
    ContentContainsSensitiveInformation = @{
        Name = "U.S. Social Security Number (SSN)"
        minCount = "1"
    }
    ExceptIfContentFileTypeMatches = @("exe", "dll", "zip")
    ContentFileTypeMatches = @("docx", "xlsx", "pptx", "pdf")
    BlockAccess = $true
}

New-DlpComplianceRule @fileTypeRule
```

### Advanced Rule Configuration

```powershell
# Rule with size-based conditions
$sizeBasedRule = @{
    Name = "Detect-Large-Sensitive-Files"
    Policy = "Global-PII-Policy-v1"
    ContentContainsSensitiveInformation = @{
        Name = "Credit Card Number"
        minCount = "5"
    }
    ContentSizeRangeMin = 1048576  # 1 MB in bytes
    ContentSizeRangeMax = 52428800 # 50 MB in bytes
    BlockAccess = $true
    GenerateAlert = $true
}

New-DlpComplianceRule @sizeBasedRule

# Rule with advanced pattern matching using AdvancedRule parameter
$advancedRuleJson = @{
    Version = "1.0"
    Condition = @{
        Operator = "And"
        SubConditions = @(
            @{
                ConditionName = "ContentContainsSensitiveInformation"
                Value = @(
                    @{
                        groups = @(
                            @{
                                Operator = "Or"
                                sitNames = @(
                                    @{ name = "Credit Card Number" },
                                    @{ name = "U.S. Social Security Number (SSN)" }
                                )
                            }
                        )
                    }
                )
            },
            @{
                ConditionName = "ContentSizeRange"
                Value = @{
                    minSize = 1024
                    maxSize = 52428800
                }
            }
        )
    }
} | ConvertTo-Json -Depth 100

Set-DlpComplianceRule `
    -Identity "Detect-PII-in-Docs" `
    -AdvancedRule $advancedRuleJson
```

### Rule Retrieval & Analysis

```powershell
# Get all rules for a specific policy
Get-DlpComplianceRule -Policy "Global-PII-Policy-v1" | Format-Table Name, Enabled, Priority

# Get specific rule with detailed configuration
$rule = Get-DlpComplianceRule -Identity "Detect-Credit-Cards"
$rule | Format-List Name, Policy, ContentContainsSensitiveInformation, BlockAccess, UserNotification

# Enumerate all rules across all policies
$policies = Get-DlpCompliancePolicy
foreach ($policy in $policies) {
    Write-Host "Policy: $($policy.Name)" -ForegroundColor Green
    Get-DlpComplianceRule -Policy $policy.Identity | Select-Object Name, Enabled, Priority
}

# Export rule configuration to JSON for backup/version control
$rule = Get-DlpComplianceRule -Identity "Detect-Credit-Cards"
$rule | Select-Object Name, Policy, ContentContainsSensitiveInformation, BlockAccess, UserNotification | ConvertTo-Json | Out-File -FilePath "C:\Backups\dlp-rule-backup.json"
```

---

## Sensitive Information Types (SITs)

### SIT Architecture & Discovery

Sensitive Information Types form the detection backbone of DLP policies. Microsoft provides built-in SITs covering common scenarios (credit cards, SSN, passport numbers), but most enterprises require custom SITs for organization-specific patterns.

```powershell
# Discover all available SITs
$allSits = Get-DlpSensitiveInformationType
$allSits | Select-Object Name, Publisher, Identity | Format-Table

# Find Microsoft-provided SITs
$microsoftSits = Get-DlpSensitiveInformationType | Where-Object { $_.Publisher -eq "Microsoft Corporation" }
Write-Host "Found $($microsoftSits.Count) Microsoft-provided SITs"

# Find custom SITs (non-Microsoft publisher)
$customSits = Get-DlpSensitiveInformationType | Where-Object { $_.Publisher -ne "Microsoft Corporation" }
$customSits | Select-Object Name, Identity, RulePackId

# Search for SIT by partial name
Get-DlpSensitiveInformationType | Where-Object { $_.Name -like "*Credit*" }

# Get detailed SIT properties
$sit = Get-DlpSensitiveInformationType -Identity "Credit Card Number"
$sit | Select-Object Name, Identity, Publisher, RulePackId, Confidence, Count
```

### Custom SIT Creation via XML Rule Packages

Custom SITs are defined in XML rule packages that follow Microsoft's classifier schema. Each XML package can contain multiple SIT definitions.

```powershell
# Step 1: Create XML rule package structure
$xmlRulePack = @"
<?xml version="1.0" encoding="utf-16"?>
<RulePackage xmlns="http://schemas.microsoft.com/office/2011/mce">
  <RulePack id="12345678-1234-1234-1234-123456789012">
    <Version major="1" minor="0" build="0" revision="0"/>
    <Publisher id="aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"/>
    <Details defaultLangCode="en-us">
      <LocalizedDetails langcode="en-us">
        <PublisherName>Contoso Corporation</PublisherName>
        <Name>Contoso Custom SITs</Name>
        <Description>Custom sensitive information types for Contoso organization</Description>
      </LocalizedDetails>
    </Details>
  </RulePack>
  <Rules>
    <Entity id="12345678-1234-1234-1234-111111111111" patternsProximity="300" 
            workload="Exchange, SharePoint, OneDrive">
      <Pattern confidenceLevel="85">
        <IdMatch idRef="Project-Code-Pattern"/>
        <Any minMatches="1">
          <Match idRef="Project-Keywords"/>
        </Any>
      </Pattern>
    </Entity>
    <Regex id="Project-Code-Pattern">PROJ-[0-9]{6}</Regex>
    <Keywords id="Project-Keywords">
      <Keyword>confidential project</Keyword>
      <Keyword>internal project</Keyword>
      <Keyword>proj</Keyword>
    </Keywords>
  </Rules>
  <LocalizedStrings>
    <Resource idRef="12345678-1234-1234-1234-111111111111">
      <Name default="true" langcode="en-us">Internal Project Code</Name>
      <Description default="true" langcode="en-us">Detects internal project codes matching pattern PROJ-######</Description>
    </Resource>
  </LocalizedStrings>
</RulePackage>
"@

# Step 2: Save XML with Unicode encoding
$xmlPath = "C:\CustomSITs\ProjectCodeSIT.xml"
[System.IO.File]::WriteAllText($xmlPath, $xmlRulePack, [System.Text.Encoding]::Unicode)

# Step 3: Upload custom SIT rule package
New-DlpSensitiveInformationTypeRulePackage -FileData ([System.IO.File]::ReadAllBytes($xmlPath))

# Step 4: Verify SIT creation
$customSit = Get-DlpSensitiveInformationType -Identity "Internal Project Code"
$customSit | Select-Object Name, Identity, RulePackId, Confidence
```

### Custom SIT Creation - Advanced Patterns

```powershell
# Complex XML with multiple patterns and confidence levels
$advancedXmlRulePack = @"
<?xml version="1.0" encoding="utf-16"?>
<RulePackage xmlns="http://schemas.microsoft.com/office/2011/mce">
  <RulePack id="aaaabbbb-cccc-dddd-eeee-ffff00001111">
    <Version major="1" minor="0" build="0" revision="0"/>
    <Publisher id="bbbbcccc-dddd-eeee-ffff-0000111122223333"/>
    <Details defaultLangCode="en-us">
      <LocalizedDetails langcode="en-us">
        <PublisherName>Contoso</PublisherName>
        <Name>Employee ID SITs</Name>
        <Description>Custom SITs for detecting Contoso employee identifiers</Description>
      </LocalizedDetails>
    </Details>
  </RulePack>
  <Rules>
    <!-- Employee ID Pattern: EMP followed by 7 digits -->
    <Entity id="ccccdddd-eeee-ffff-0000-1111222233334444" patternsProximity="300" 
            workload="Exchange, SharePoint, OneDrive">
      <!-- High confidence: Employee ID with supporting keywords -->
      <Pattern confidenceLevel="85">
        <IdMatch idRef="EmployeeID-HighConfidence"/>
        <Any minMatches="1">
          <Match idRef="EmployeeKeywords"/>
        </Any>
      </Pattern>
      <!-- Medium confidence: Employee ID alone -->
      <Pattern confidenceLevel="65">
        <IdMatch idRef="EmployeeID-Pattern"/>
      </Pattern>
      <!-- Low confidence: Loose pattern with proximity requirements -->
      <Pattern confidenceLevel="45">
        <IdMatch idRef="EmployeeID-Loose"/>
        <Any minMatches="1">
          <Match idRef="EmployeeContext"/>
        </Any>
      </Pattern>
    </Entity>
    
    <!-- Exact Match for known employee IDs (Exact Data Match - EDM) -->
    <Entity id="ddddeeee-ffff-0000-1111-2222333344445555" 
            patternsProximity="150" workload="Exchange, SharePoint">
      <Pattern confidenceLevel="95">
        <IdMatch idRef="EDM-EmployeeDatabase"/>
      </Pattern>
    </Entity>
    
    <Regex id="EmployeeID-HighConfidence">EMP\d{7}[A-Z]{2}</Regex>
    <Regex id="EmployeeID-Pattern">EMP\d{7}</Regex>
    <Regex id="EmployeeID-Loose">[Ee]mployee.*?[0-9]{7}</Regex>
    
    <Keywords id="EmployeeKeywords">
      <Keyword>employee id</Keyword>
      <Keyword>emp id</Keyword>
      <Keyword>personnel number</Keyword>
      <Keyword>staff id</Keyword>
    </Keywords>
    
    <Keywords id="EmployeeContext">
      <Keyword>department</Keyword>
      <Keyword>manager</Keyword>
      <Keyword>payroll</Keyword>
      <Keyword>hr</Keyword>
    </Keywords>
  </Rules>
  <LocalizedStrings>
    <Resource idRef="ccccdddd-eeee-ffff-0000-1111222233334444">
      <Name default="true" langcode="en-us">Contoso Employee ID</Name>
      <Description default="true" langcode="en-us">Detects employee identifiers in formats: EMP#######, EMP#######XX</Description>
    </Resource>
    <Resource idRef="ddddeeee-ffff-0000-1111-2222333344445555">
      <Name default="true" langcode="en-us">Contoso Employee Database Match</Name>
      <Description default="true" langcode="en-us">Exact match against known employee database</Description>
    </Resource>
  </LocalizedStrings>
</RulePackage>
"@

# Save and upload advanced SIT
$advPath = "C:\CustomSITs\EmployeeIDSIT.xml"
[System.IO.File]::WriteAllText($advPath, $advancedXmlRulePack, [System.Text.Encoding]::Unicode)
New-DlpSensitiveInformationTypeRulePackage -FileData ([System.IO.File]::ReadAllBytes($advPath))
```

### SIT Rule Package Management

```powershell
# List all rule packages (including built-in Microsoft package)
Get-DlpSensitiveInformationTypeRulePackage | Format-Table Name, Publisher, Id

# Extract existing rule package for modification
$rulePackId = (Get-DlpSensitiveInformationType -Identity "Internal Project Code").RulePackId
$rulePackage = Get-DlpSensitiveInformationTypeRulePackage -Identity $rulePackId

# Export rule package XML to file
[System.Text.Encoding]::Unicode.GetString([System.Convert]::FromBase64String((
    $rulePackage.ClassificationRuleCollectionXml | ConvertTo-Json
))) | Out-File -FilePath "C:\CustomSITs\ExportedRulePack.xml" -Encoding Unicode

# Update existing rule package (modify and re-upload)
# After modifying the XML file, use Set-DlpSensitiveInformationTypeRulePackage
Set-DlpSensitiveInformationTypeRulePackage `
    -FileData ([System.IO.File]::ReadAllBytes("C:\CustomSITs\EmployeeIDSIT.xml")) `
    -Confirm:$false

# Remove custom rule package (WARNING: Removes all SITs in package)
Remove-DlpSensitiveInformationTypeRulePackage -Identity $rulePackId -Confirm:$false
```

### Exact Data Match (EDM) SITs

EDM SITs match against a sensitive data repository for extremely high confidence detection:

```powershell
# Step 1: Create EDM sensitive data schema
$edmSchema = @"
<?xml version="1.0" encoding="utf-16"?>
<Schema xmlns="http://schemas.microsoft.com/office/2020/edm">
  <DocSet>
    <Version build="0" revision="1"/>
    <Fields>
      <Field name="EmployeeID" searchable="true" retrievable="false" indexed="true"/>
      <Field name="FirstName" searchable="false" retrievable="true" indexed="false"/>
      <Field name="LastName" searchable="false" retrievable="true" indexed="false"/>
      <Field name="EmailAddress" searchable="true" retrievable="false" indexed="true"/>
    </Fields>
  </DocSet>
</Schema>
"@

# Step 2: Upload EDM schema
$schemaPath = "C:\EDM\EmployeeSchema.xml"
[System.IO.File]::WriteAllText($schemaPath, $edmSchema, [System.Text.Encoding]::Unicode)

# Step 3: Upload EDM sensitive data source
# This requires running the EDM Upload Agent on a secure system
# Example data format: EmployeeID|FirstName|LastName|EmailAddress
# EMP0001234|John|Doe|john.doe@contoso.com
```

---

## Information Protection & Sensitivity Labels

### Sensitivity Label Management

Sensitivity labels provide classification and protection (encryption, watermarking, access restrictions) for content across M365.

```powershell
# Retrieve all sensitivity labels
$allLabels = Get-Label
$allLabels | Select-Object DisplayName, Name, Identity, Priority | Format-Table

# Get detailed label configuration
$label = Get-Label -Identity "Confidential"
$label | Format-List DisplayName, Name, Tooltip, Comment, Priority, ContentType, Parent

# Create new sensitivity label
$newLabelParams = @{
    DisplayName = "Highly Confidential"
    Name = "HighlyConfidential"
    Tooltip = "This content is restricted to authorized personnel only"
    Comment = "Standard label for financial and legal documents"
    ContentType = @("File", "Email", "Meeting")
}

New-Label @newLabelParams

# Create hierarchical label (parent-child relationship)
$parentLabel = New-Label -DisplayName "Internal" -Name "Internal" -Tooltip "Internal organization content"
$sublabelParams = @{
    DisplayName = "Internal - Restricted"
    Name = "Internal-Restricted"
    Parent = $parentLabel.Identity
    Tooltip = "Internal content with restricted access"
}

New-Label @sublabelParams

# Update label properties
Set-Label `
    -Identity "Confidential" `
    -DisplayName "Confidential - Updated" `
    -Comment "Updated label configuration" `
    -Tooltip "Updated tooltip for confidential content"

# Delete label (irreversible if content is labeled)
Remove-Label -Identity "Outdated-Label" -Confirm:$false
```

### Sensitivity Label Policies

Label policies control which labels are published to users and which label policies are enforced:

```powershell
# Create label policy for specific user groups
$policyParams = @{
    DisplayName = "Finance Department Labels"
    Name = "FinanceDeptLabelPolicy"
    Labels = @("Confidential", "Internal")
    Settings = @{
        mandatory = "true"
        tooltip = "Financial documents must be classified"
    }
}

New-LabelPolicy @policyParams

# Publish label policy to specific groups
$labelPolicyParams = @{
    DisplayName = "Executive Labels Policy"
    Name = "ExecLabelPolicy"
    Labels = @("Highly Confidential", "Confidential", "Internal")
    Users = @("cfo@contoso.com", "coo@contoso.com")
}

New-LabelPolicy @labelPolicyParams

# Apply mandatory labeling policy
Set-LabelPolicy `
    -Identity "ComplianceLabelPolicy" `
    -DisplayName "Mandatory Labeling Policy" `
    -MandatoryOutlook $true `
    -MandatoryWord $true `
    -MandatoryExcel $true `
    -MandatoryPowerPoint $true

# Retrieve all label policies
Get-LabelPolicy | Select-Object DisplayName, Name, Users, Labels | Format-Table

# Remove label policy
Remove-LabelPolicy -Identity "LabelPolicy-ToDelete" -Confirm:$false
```

### Advanced Label Configuration

```powershell
# Label with encryption settings
$encryptedLabelParams = @{
    DisplayName = "Confidential - Encrypted"
    Name = "ConfidentialEncrypted"
    EncryptionEnabled = $true
    EncryptionProtocol = "TLS1_2"
    EncryptionRightsUrl = "https://contoso.rms.protection.outlook.com/RmsSharingInitiative"
}

New-Label @encryptedLabelParams

# Label with watermark and header/footer
Set-Label `
    -Identity "Confidential" `
    -DisplayName "Confidential" `
    -Watermark = "CONFIDENTIAL"
    -HeaderText = "Classification: Confidential" `
    -FooterText = "Page [#] of [##]"

# Label with advanced settings (PowerShell advanced settings for Unified Label client)
# These settings are configured via Set-LabelPolicy with AdvancedSettings parameter
$advSettings = @{
    "DisableMandatoryClassificationForContainers" = "true"
    "ExternalContentMarkingAlignment" = "Center"
    "EnableContainerSupport" = "true"
}

Set-LabelPolicy `
    -Identity "AdvancedLabelPolicy" `
    -AdvancedSettings $advSettings
```

### PurviewInformationProtection Module - File Labeling

```powershell
# Install PurviewInformationProtection module
Install-Module PurviewInformationProtection -Scope CurrentUser -Force

# Import module for file operations
Import-Module PurviewInformationProtection

# Set label on a single file
Set-FileLabel `
    -Path "C:\Documents\Financial-Report.docx" `
    -LabelId "a1b2c3d4-e5f6-7890-abcd-ef1234567890" `
    -Owner "admin@contoso.com"

# Apply label with custom permissions
$customPerms = New-CustomPermissions `
    -Users "user1@contoso.com", "user2@contoso.com" `
    -Permissions Reviewer

Set-FileLabel `
    -Path "C:\Documents\Sensitive-Data.xlsx" `
    -CustomPermissions $customPerms

# Auto-label files based on content detection
Set-FileLabel `
    -Path "C:\Documents\*.docx" `
    -AutoLabel `
    -DiscoveryInfoTypes All `
    -Owner "admin@contoso.com"

# Get file label and protection status
$fileStatus = Get-FileStatus -Path "C:\Documents\Financial-Report.docx"
$fileStatus | Select-Object FilePath, Labels, ProtectionInfo

# Batch labeling operation
Get-ChildItem -Path "C:\Documents" -Filter "*.docx" -Recurse | ForEach-Object {
    Set-FileLabel `
        -Path $_.FullName `
        -LabelId "a1b2c3d4-e5f6-7890-abcd-ef1234567890" `
        -Owner "admin@contoso.com" `
        -Force
}
```

---

## Testing & Validation Cmdlets

### Test-DataClassification Cmdlet

Validates SIT detection logic against sample text without policy enforcement:

```powershell
# Test basic text classification
$testText = "My SSN is 123-45-6789 and my credit card is 4532-1234-5678-9101"
$result = Test-DataClassification -TextToClassify $testText

# Extract classification results
$result.ClassificationResults | Select-Object ClassificationName, ConfidenceLevel, Count

# Example output:
# ClassificationName          ConfidenceLevel Count
# U.S. Social Security Number 85              1
# Credit Card Number          85              1

# Test specific classification names only
$specificClassifications = Test-DataClassification `
    -TextToClassify "SSN: 555-66-7777" `
    -ClassificationNames @("U.S. Social Security Number (SSN)", "Credit Card Number")

# Test with file extension specification (affects text extraction)
$fileExtTest = Test-DataClassification `
    -TextToClassify "EMP0001234 - Employee Database" `
    -FileExtension ".txt"

# Batch test multiple strings
$testStrings = @(
    "My ID is PROJ-123456",
    "Employee number: EMP0000123",
    "Credit card: 4024-0071-5678-9101"
)

$batchResults = $testStrings | ForEach-Object {
    $result = Test-DataClassification -TextToClassify $_
    [PSCustomObject]@{
        Text = $_
        DetectedTypes = ($result.ClassificationResults.ClassificationName -join ", ")
        Confidence = ($result.ClassificationResults.ConfidenceLevel -join ", ")
    }
}

$batchResults | Format-Table
```

### Test-TextExtraction Cmdlet

Extracts and returns text from email message files (.msg, .eml) for testing classification:

```powershell
# Extract text from .msg file
$msgFilePath = "C:\TestMessages\Test-Email.msg"
$fileBytes = [System.IO.File]::ReadAllBytes($msgFilePath)
$extractedContent = Test-TextExtraction -FileData $fileBytes

# View extracted text
$extractedContent.ExtractedResults

# Chain with Test-DataClassification for comprehensive analysis
$msgFile = "C:\TestMessages\Financial-Email.msg"
$msgBytes = [System.IO.File]::ReadAllBytes($msgFile)
$extraction = Test-TextExtraction -FileData $msgBytes
$classification = Test-DataClassification -TestTextExtractionResults $extraction.ExtractedResults

$classification.ClassificationResults | Select-Object ClassificationName, ConfidenceLevel, Count

# Process multiple message files
$msgFiles = Get-ChildItem -Path "C:\TestMessages" -Filter "*.msg"
foreach ($file in $msgFiles) {
    $bytes = [System.IO.File]::ReadAllBytes($file.FullName)
    $extracted = Test-TextExtraction -FileData $bytes
    $classified = Test-DataClassification -TestTextExtractionResults $extracted.ExtractedResults
    
    Write-Host "File: $($file.Name)" -ForegroundColor Green
    $classified.ClassificationResults | Select-Object ClassificationName, ConfidenceLevel, Count
    Write-Host "---"
}

# Error handling for corrupted/encrypted files
try {
    $bytes = [System.IO.File]::ReadAllBytes("C:\TestMessages\Encrypted.msg")
    $extracted = Test-TextExtraction -FileData $bytes
}
catch {
    Write-Host "Error extracting file: $($_.Exception.Message)" -ForegroundColor Red
}
```

### Test-DlpPolicies Cmdlet

Tests which DLP policies would match a specific file in SharePoint or OneDrive:

```powershell
# Test single file against DLP policies
$fileUrl = "https://contoso.sharepoint.com/sites/Finance/Documents/Report.xlsx"
Test-DlpPolicies `
    -Workload "ODB" `
    -FileUrl $fileUrl `
    -SendReportTo "compliance@contoso.com"

# Test file for SharePoint location
Test-DlpPolicies `
    -Workload "SharePoint" `
    -FileUrl "https://contoso.sharepoint.com/sites/Marketing/Documents/Customer-List.xlsx" `
    -SendReportTo "admin@contoso.com"

# Workflow: Create test file, upload, and validate policy matches
$testFilePath = "C:\temp\test-doc.xlsx"

# Create test file with sample PII
$excel = New-Object -ComObject Excel.Application
$workbook = $excel.Workbooks.Add()
$worksheet = $workbook.Sheets(1)
$worksheet.Cells(1, 1) = "SSN"
$worksheet.Cells(2, 1) = "123-45-6789"
$workbook.SaveAs($testFilePath)
$excel.Quit()

# Upload to SharePoint
$uploadUrl = "https://contoso.sharepoint.com/sites/TestDLP/Documents/TestFile.xlsx"

# Test DLP evaluation
Test-DlpPolicies `
    -Workload "SharePoint" `
    -FileUrl $uploadUrl `
    -SendReportTo "security@contoso.com"

# Retrieve test report from email (sent to SendReportTo address)
# Report contains: Classification ID, Confidence, Count, Policy Details, Rules, Predicates
```

### Test-Message Cmdlet

Simulates email through Transport Rules and DLP policy pipeline:

```powershell
# Test message from sender to recipient (basic test)
Test-Message `
    -Sender "john.doe@contoso.com" `
    -Recipients "external@partner.com" `
    -SendReportTo "admin@contoso.com" `
    -TransportRules `
    -UnifiedDlpRules

# Test with actual message file
$msgFile = "C:\TestMessages\SensitiveEmail.msg"
$msgBytes = [System.IO.File]::ReadAllBytes($msgFile)

Test-Message `
    -MessageFileData $msgBytes `
    -Sender "finance@contoso.com" `
    -Recipients "accounting@contoso.com" `
    -SendReportTo "compliance@contoso.com" `
    -TransportRules `
    -UnifiedDlpRules `
    -Force

# Test with external recipients to validate policy behavior
Test-Message `
    -Sender "employee@contoso.com" `
    -Recipients "external-partner@external.com" `
    -SendReportTo "admin@contoso.com" `
    -UnifiedDlpRules

# Test transport rules without DLP
Test-Message `
    -Sender "user@contoso.com" `
    -Recipients "manager@contoso.com" `
    -SendReportTo "admin@contoso.com" `
    -TransportRules

# Batch test multiple sender/recipient combinations
$testCases = @(
    @{ Sender = "emp1@contoso.com"; Recipients = @("emp2@contoso.com") },
    @{ Sender = "emp1@contoso.com"; Recipients = @("external@partner.com") },
    @{ Sender = "legal@contoso.com"; Recipients = @("emp2@contoso.com") }
)

foreach ($case in $testCases) {
    Write-Host "Testing: $($case.Sender) -> $($case.Recipients)" -ForegroundColor Cyan
    Test-Message `
        -Sender $case.Sender `
        -Recipients $case.Recipients `
        -SendReportTo "admin@contoso.com" `
        -UnifiedDlpRules `
        -Force
    Start-Sleep -Seconds 2
}
```

### Comprehensive Testing Workflow

```powershell
# Establish testing baseline
function Invoke-PurviewComplianceTest {
    param(
        [string]$TestName,
        [string]$TestContent,
        [string[]]$TestFiles
    )
    
    $testResults = @{}
    
    # Phase 1: Text classification
    if ($TestContent) {
        $classResult = Test-DataClassification -TextToClassify $TestContent
        $testResults["DataClassification"] = $classResult.ClassificationResults
    }
    
    # Phase 2: File-based testing
    if ($TestFiles) {
        foreach ($file in $TestFiles) {
            $bytes = [System.IO.File]::ReadAllBytes($file)
            
            # Text extraction
            $extracted = Test-TextExtraction -FileData $bytes
            
            # Classification
            $classified = Test-DataClassification -TestTextExtractionResults $extracted.ExtractedResults
            $testResults["FileExtraction_$($file)"] = @{
                Extracted = $extracted.ExtractedResults
                Classification = $classified.ClassificationResults
            }
        }
    }
    
    return $testResults
}

# Execute comprehensive test
$testResults = Invoke-PurviewComplianceTest `
    -TestName "Q1-Compliance-Audit" `
    -TestContent "SSN: 123-45-6789, Credit Card: 4024-0071-5678-9101" `
    -TestFiles @("C:\TestMessages\email1.msg", "C:\TestMessages\email2.msg")

# Output results
$testResults | ConvertTo-Json | Out-File "C:\Reports\compliance-test-results.json"
```

---

## Compliance & eDiscovery Operations

### Compliance Case Management

```powershell
# Create new eDiscovery case
$caseParams = @{
    Name = "Investigation-2025-Q1-001"
    Description = "Investigation into potential data breach Q1 2025"
    CaseType = "eDiscovery"
}

New-ComplianceCase @caseParams

# List all compliance cases
Get-ComplianceCase | Select-Object Name, CaseType, CreatedTime, Status | Format-Table

# Get specific case details
$case = Get-ComplianceCase -Identity "Investigation-2025-Q1-001"
$case | Format-List Name, Description, CaseType, Status, CreatedTime

# Add case members (grant access)
Add-ComplianceCaseMember `
    -Case "Investigation-2025-Q1-001" `
    -Member "investigator@contoso.com"

# Remove case member
Remove-ComplianceCaseMember `
    -Case "Investigation-2025-Q1-001" `
    -Member "former-investigator@contoso.com"

# Close case
Set-ComplianceCase `
    -Identity "Investigation-2025-Q1-001" `
    -Status "Closed"

# Delete case (must be closed first)
Remove-ComplianceCase -Identity "Investigation-2025-Q1-001" -Confirm:$false
```

### Compliance Searches

```powershell
# Create new compliance search
$searchParams = @{
    Name = "FinancialDocuments-2024"
    ExchangeLocation = @("all")
    SharePointLocation = @("https://contoso.sharepoint.com/sites/Finance")
    ContentMatchQuery = '(filetype:xlsx OR filetype:csv) AND (sender:"cfo@contoso.com" OR to:"cfo@contoso.com")'
    Case = "Investigation-2025-Q1-001"
}

New-ComplianceSearch @searchParams

# Start compliance search (executes the query)
Start-ComplianceSearch -Identity "FinancialDocuments-2024"

# Monitor search progress
Get-ComplianceSearch -Identity "FinancialDocuments-2024" | Select-Object Name, Status, ItemCount, Size

# Get detailed search results
$searchResult = Get-ComplianceSearch -Identity "FinancialDocuments-2024" | Select-Object -ExpandProperty Results

# Export search results
New-ComplianceSearchAction `
    -SearchName "FinancialDocuments-2024" `
    -Action "Export" `
    -ExchangeArchiveFormat "PerUserPST"

# Retrieve export status
Get-ComplianceSearchAction -SearchName "FinancialDocuments-2024" | Select-Object Status, Results
```

### Hold Policies (Content Preservation)

```powershell
# Create hold policy for case
$holdParams = @{
    Case = "Investigation-2025-Q1-001"
    Name = "Finance-Investigation-Hold"
    ExchangeLocation = @("cfo@contoso.com", "controller@contoso.com")
    SharePointLocation = @("https://contoso.sharepoint.com/sites/Finance")
}

New-CaseHoldPolicy @holdParams

# Create indefinite hold
Set-CaseHoldPolicy `
    -Identity "Finance-Investigation-Hold" `
    -AddExchangeLocation @("accounting@contoso.com")

# List all holds for case
Get-CaseHoldPolicy -Case "Investigation-2025-Q1-001"

# Release hold (removes preservation)
Set-CaseHoldPolicy `
    -Identity "Finance-Investigation-Hold" `
    -RemoveExchangeLocation @("cfo@contoso.com")
```

---

## Enterprise Integration Patterns

### Module Abstraction & Wrapper Functions

```powershell
# Create reusable function library
function New-PurviewDlpPolicy {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [string]$PolicyName,
        
        [Parameter(Mandatory=$true)]
        [ValidateSet("Enable", "Disable", "TestWithNotifications", "TestWithoutNotifications")]
        [string]$Mode,
        
        [Parameter(Mandatory=$false)]
        [string[]]$ExchangeLocations = @("All"),
        
        [Parameter(Mandatory=$false)]
        [string[]]$SharePointLocations = @(),
        
        [Parameter(Mandatory=$false)]
        [hashtable[]]$SensitiveTypes,
        
        [Parameter(Mandatory=$false)]
        [hashtable[]]$Rules
    )
    
    try {
        # Validate connection
        $session = Get-PSSession | Where-Object { $_.ConfigurationName -like "*Compliance*" }
        if (-not $session) {
            throw "No Purview compliance session found. Run Connect-IPPSSession first."
        }
        
        # Create policy container
        $policyParams = @{
            Name = $PolicyName
            Mode = $Mode
        }
        
        if ($ExchangeLocations) { $policyParams["ExchangeLocation"] = $ExchangeLocations }
        if ($SharePointLocations) { $policyParams["SharePointLocation"] = $SharePointLocations }
        
        $newPolicy = New-DlpCompliancePolicy @policyParams
        Write-Host "Created policy: $PolicyName" -ForegroundColor Green
        
        # Create associated rules
        if ($Rules) {
            foreach ($rule in $Rules) {
                $ruleParams = @{
                    Name = $rule.Name
                    Policy = $PolicyName
                    ContentContainsSensitiveInformation = $rule.SensitiveInformationTypes
                    BlockAccess = $rule.BlockAccess
                    UserNotification = $rule.UserNotification
                }
                
                New-DlpComplianceRule @ruleParams
                Write-Host "Created rule: $($rule.Name)" -ForegroundColor Green
            }
        }
        
        return $newPolicy
    }
    catch {
        Write-Error "Failed to create DLP policy: $_"
        return $null
    }
}

# Function to deploy SIT from JSON configuration
function Deploy-PurviewSIT {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [string]$XmlConfigPath,
        
        [Parameter(Mandatory=$false)]
        [switch]$BackupExisting
    )
    
    try {
        if (-not (Test-Path $XmlConfigPath)) {
            throw "XML configuration file not found: $XmlConfigPath"
        }
        
        if ($BackupExisting) {
            $packages = Get-DlpSensitiveInformationTypeRulePackage
            $packages | ForEach-Object {
                $backupPath = "$env:TEMP\RulePack_$($_.Id)_backup.xml"
                # Export logic here
                Write-Host "Backed up rule package to: $backupPath"
            }
        }
        
        # Upload new SIT
        $fileBytes = [System.IO.File]::ReadAllBytes($XmlConfigPath)
        New-DlpSensitiveInformationTypeRulePackage -FileData $fileBytes
        
        Write-Host "Successfully deployed SIT from: $XmlConfigPath" -ForegroundColor Green
    }
    catch {
        Write-Error "Failed to deploy SIT: $_"
    }
}

# Example usage
$rules = @(
    @{
        Name = "Detect-CreditCards"
        SensitiveInformationTypes = @{ Name = "Credit Card Number"; minCount = "1" }
        BlockAccess = $true
        UserNotification = "Email"
    },
    @{
        Name = "Detect-SSN"
        SensitiveInformationTypes = @{ Name = "U.S. Social Security Number (SSN)"; minCount = "1" }
        BlockAccess = $true
        UserNotification = "Email"
    }
)

$newPolicy = New-PurviewDlpPolicy `
    -PolicyName "Comprehensive-PII-Policy" `
    -Mode "TestWithNotifications" `
    -ExchangeLocations @("All") `
    -SharePointLocations @("All") `
    -Rules $rules
```

### Logging & Audit Trail Integration

```powershell
# Create structured logging for Purview operations
function Log-PurviewOperation {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [string]$Operation,
        
        [Parameter(Mandatory=$true)]
        [ValidateSet("Success", "Warning", "Error", "Info")]
        [string]$Level,
        
        [Parameter(Mandatory=$true)]
        [string]$Details,
        
        [Parameter(Mandatory=$false)]
        [string]$LogPath = "C:\Logs\Purview-Operations.log"
    )
    
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss.fff"
    $logEntry = "$timestamp | $Level | $Operation | $Details"
    
    # Write to file
    Add-Content -Path $LogPath -Value $logEntry
    
    # Write to console with color
    switch ($Level) {
        "Success" { Write-Host $logEntry -ForegroundColor Green }
        "Warning" { Write-Host $logEntry -ForegroundColor Yellow }
        "Error" { Write-Host $logEntry -ForegroundColor Red }
        "Info" { Write-Host $logEntry -ForegroundColor Cyan }
    }
}

# Track all DLP policy modifications
function Invoke-DlpPolicyChangeTracking {
    param(
        [string]$PolicyName
    )
    
    $currentPolicies = Get-DlpCompliancePolicy -Identity $PolicyName
    $configJson = $currentPolicies | ConvertTo-Json
    
    # Store in version control or audit database
    $timestamp = Get-Date -Format "yyyyMMdd-HHmmss"
    $backupFile = "C:\Audits\DLP-Policy_$($PolicyName)_$timestamp.json"
    
    $configJson | Out-File -FilePath $backupFile
    Log-PurviewOperation -Operation "DLPPolicyBackup" -Level "Info" -Details "Backed up policy $PolicyName to $backupFile"
}

# Usage
Connect-IPPSSession -UserPrincipalName "admin@contoso.com"
Invoke-DlpPolicyChangeTracking -PolicyName "Global-PII-Policy-v1"
```

### Error Handling & Retry Logic

```powershell
# Implement resilient error handling for production scenarios
function Invoke-PurviewCmdletWithRetry {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [scriptblock]$ScriptBlock,
        
        [Parameter(Mandatory=$false)]
        [int]$MaxRetries = 3,
        
        [Parameter(Mandatory=$false)]
        [int]$RetryDelaySeconds = 5
    )
    
    $attempt = 0
    $lastException = $null
    
    while ($attempt -lt $MaxRetries) {
        try {
            $attempt++
            Write-Host "Attempt $attempt of $MaxRetries..." -ForegroundColor Cyan
            $result = & $ScriptBlock
            return $result
        }
        catch [Microsoft.Exchange.Configuration.Tasks.ManagementServiceConnectionException] {
            $lastException = $_
            Write-Warning "Connection error: $_. Retrying in $RetryDelaySeconds seconds..."
            Start-Sleep -Seconds $RetryDelaySeconds
        }
        catch [System.InvalidOperationException] {
            $lastException = $_
            Write-Warning "Operation failed: $_. Retrying..."
            Start-Sleep -Seconds $RetryDelaySeconds
        }
        catch {
            # Non-retryable error
            throw $_
        }
    }
    
    throw "Failed after $MaxRetries attempts. Last exception: $lastException"
}

# Usage with retry
$result = Invoke-PurviewCmdletWithRetry -ScriptBlock {
    New-DlpCompliancePolicy -Name "Test-Policy" -Mode Enable -ExchangeLocation All
}
```

---

## Automation & CI/CD Deployment

### Azure DevOps Pipeline Integration

```yaml
# .azure-pipelines/deploy-purview-dlp.yml
trigger:
  - main
  - develop

pool:
  vmImage: 'windows-latest'

variables:
  purviewAdmin: 'compliance-admin@contoso.com'
  purviewOrg: 'contoso.onmicrosoft.com'
  environment: 'production'

stages:
- stage: Validate
  displayName: 'Validate DLP Configuration'
  jobs:
  - job: SchemaValidation
    displayName: 'Validate DLP Policy Schema'
    steps:
    - task: PowerShell@2
      displayName: 'Install Exchange Online Management'
      inputs:
        targetType: 'inline'
        script: |
          Install-Module -Name ExchangeOnlineManagement -Scope CurrentUser -Force
          Import-Module ExchangeOnlineManagement
    
    - task: PowerShell@2
      displayName: 'Validate DLP Configuration Files'
      inputs:
        targetType: 'filePath'
        filePath: '$(Build.SourcesDirectory)/scripts/Validate-DLPConfig.ps1'
        arguments: '-ConfigPath "$(Build.SourcesDirectory)/configs"'

- stage: Deploy
  displayName: 'Deploy to Purview'
  dependsOn: Validate
  condition: succeeded()
  jobs:
  - deployment: DeployDLP
    displayName: 'Deploy DLP Policies'
    environment: ${{ variables.environment }}
    strategy:
      runOnce:
        deploy:
          steps:
          - task: PowerShell@2
            displayName: 'Connect to Purview'
            inputs:
              targetType: 'inline'
              script: |
                $cert = Get-Item "Cert:\CurrentUser\My\$(CertThumbprint)"
                Connect-ExchangeOnline -CertificateThumbprint $(CertThumbprint) -AppId $(AppId) -Organization $(purviewOrg)
          
          - task: PowerShell@2
            displayName: 'Deploy DLP Policies'
            inputs:
              targetType: 'filePath'
              filePath: '$(Build.SourcesDirectory)/scripts/Deploy-DLPPolicies.ps1'
              arguments: '-ConfigPath "$(Build.SourcesDirectory)/configs" -Mode "Production"'

- stage: Test
  displayName: 'Test DLP Policies'
  dependsOn: Deploy
  condition: succeeded()
  jobs:
  - job: TestPolicies
    displayName: 'Validate DLP Policy Functionality'
    steps:
    - task: PowerShell@2
      displayName: 'Run DLP Policy Tests'
      inputs:
        targetType: 'filePath'
        filePath: '$(Build.SourcesDirectory)/scripts/Test-DLPPolicies.ps1'
        arguments: '-TestDataPath "$(Build.SourcesDirectory)/test-data"'
```

### Python-Based Deployment Orchestration

```python
# deploy_purview_dlp.py
import subprocess
import json
import logging
from pathlib import Path
from typing import List, Dict
import sys

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('purview_deployment.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

class PurviewDLPDeployer:
    def __init__(self, tenant_id: str, app_id: str, cert_thumbprint: str):
        self.tenant_id = tenant_id
        self.app_id = app_id
        self.cert_thumbprint = cert_thumbprint
        
    def connect_to_purview(self) -> bool:
        """Establish connection to Purview via PowerShell"""
        ps_command = f"""
        Connect-ExchangeOnline -CertificateThumbprint "{self.cert_thumbprint}" -AppId "{self.app_id}" -Organization "{self.tenant_id}"
        if ($?) {{ Write-Output "Connected" }} else {{ Write-Output "Failed" }}
        """
        
        try:
            result = subprocess.run(
                ["powershell", "-Command", ps_command],
                capture_output=True,
                text=True,
                timeout=30
            )
            
            if "Connected" in result.stdout:
                logger.info("Successfully connected to Purview")
                return True
            else:
                logger.error(f"Connection failed: {result.stderr}")
                return False
        except subprocess.TimeoutExpired:
            logger.error("Connection timeout")
            return False
    
    def deploy_dlp_policies(self, config_path: str) -> bool:
        """Deploy DLP policies from configuration file"""
        try:
            with open(config_path, 'r') as f:
                config = json.load(f)
            
            for policy in config.get('policies', []):
                logger.info(f"Deploying policy: {policy['name']}")
                
                # Build PowerShell command for policy creation
                ps_command = self._build_policy_command(policy)
                
                # Execute deployment
                result = subprocess.run(
                    ["powershell", "-Command", ps_command],
                    capture_output=True,
                    text=True,
                    timeout=60
                )
                
                if result.returncode != 0:
                    logger.error(f"Failed to deploy policy {policy['name']}: {result.stderr}")
                    return False
                else:
                    logger.info(f"Successfully deployed policy: {policy['name']}")
            
            return True
        except Exception as e:
            logger.error(f"Deployment failed: {str(e)}")
            return False
    
    def _build_policy_command(self, policy: Dict) -> str:
        """Generate PowerShell command for policy creation"""
        locations = []
        if policy.get('exchangeLocation'):
            locations.append(f"-ExchangeLocation 'All'")
        if policy.get('sharePointLocation'):
            locations.append(f"-SharePointLocation 'All'")
        
        rules = []
        for rule in policy.get('rules', []):
            rules.append(f"""
            New-DlpComplianceRule `
                -Name '{rule['name']}' `
                -Policy '{policy['name']}' `
                -ContentContainsSensitiveInformation @{{Name='{rule['sensitiveType']}'; minCount='1'}} `
                -BlockAccess $true
            """)
        
        ps_command = f"""
        New-DlpCompliancePolicy -Name '{policy['name']}' -Mode '{policy.get('mode', 'Enable')}' {' '.join(locations)}
        {' '.join(rules)}
        """
        
        return ps_command
    
    def test_dlp_policies(self, test_data_path: str) -> bool:
        """Test DLP policies against test data"""
        logger.info("Testing DLP policies")
        
        test_files = Path(test_data_path).glob("*.txt")
        
        for test_file in test_files:
            with open(test_file, 'r') as f:
                test_content = f.read()
            
            ps_command = f"""
            $result = Test-DataClassification -TextToClassify @"
            {test_content}
            "@
            $result.ClassificationResults | ConvertTo-Json
            """
            
            result = subprocess.run(
                ["powershell", "-Command", ps_command],
                capture_output=True,
                text=True,
                timeout=30
            )
            
            if result.returncode == 0:
                classifications = json.loads(result.stdout)
                logger.info(f"Test file {test_file.name}: {len(classifications)} classifications found")
            else:
                logger.warning(f"Test failed for {test_file.name}")
        
        return True

# Main execution
if __name__ == "__main__":
    deployer = PurviewDLPDeployer(
        tenant_id="contoso.onmicrosoft.com",
        app_id="12345678-1234-1234-1234-123456789012",
        cert_thumbprint="AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
    )
    
    # Connect
    if not deployer.connect_to_purview():
        sys.exit(1)
    
    # Deploy policies
    if not deployer.deploy_dlp_policies("configs/dlp-policies.json"):
        sys.exit(1)
    
    # Test policies
    if not deployer.test_dlp_policies("test-data/"):
        sys.exit(1)
    
    logger.info("Deployment completed successfully")
```

### Infrastructure as Code (IaC) with Terraform

```hcl
# main.tf - Purview DLP Infrastructure as Code
terraform {
  required_providers {
    azapi = {
      source  = "azure/azapi"
      version = "~> 1.0"
    }
  }
}

provider "azapi" {
  tenant_id = var.tenant_id
}

# Variable definitions
variable "tenant_id" {
  type = string
}

variable "policies" {
  type = list(object({
    name        = string
    description = string
    mode        = string
    workloads   = list(string)
  }))
}

# Create DLP Policy Resource
resource "azapi_resource" "dlp_policy" {
  for_each = { for p in var.policies : p.name => p }
  
  type      = "Microsoft.Purview/policies@2021-07-01"
  name      = each.value.name
  parent_id = "/subscriptions/${data.azurerm_client_config.current.subscription_id}/resourceGroups/${var.resource_group}"
  
  body = jsonencode({
    properties = {
      displayName = each.value.name
      description = each.value.description
      mode        = each.value.mode
      workloads   = each.value.workloads
    }
  })
}

# Output policy IDs
output "policy_ids" {
  value = {
    for name, policy in azapi_resource.dlp_policy :
    name => policy.id
  }
}
```

---

## Advanced Troubleshooting

### Permission & Access Diagnostics

```powershell
# Diagnose permission issues
function Diagnose-PurviewPermissions {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$false)]
        [string]$UserPrincipalName = (Get-AzContext).Account.Id
    )
    
    $permissionReport = @{
        Timestamp = Get-Date
        UserPrincipalName = $UserPrincipalName
        RoleAssignments = @()
        CommandResults = @()
    }
    
    # Test various cmdlets to determine accessible permissions
    $testCmdlets = @(
        @{ Cmdlet = "Get-DlpCompliancePolicy"; Category = "DLP" },
        @{ Cmdlet = "Get-Label"; Category = "Labels" },
        @{ Cmdlet = "Get-DlpSensitiveInformationType"; Category = "SIT" },
        @{ Cmdlet = "Get-ComplianceCase"; Category = "eDiscovery" },
        @{ Cmdlet = "Get-ComplianceSearch"; Category = "Search" }
    )
    
    foreach ($test in $testCmdlets) {
        try {
            $result = Invoke-Expression $test.Cmdlet
            $permissionReport.CommandResults += @{
                Cmdlet = $test.Cmdlet
                Category = $test.Category
                Accessible = $true
                ResultCount = ($result | Measure-Object).Count
            }
        }
        catch {
            $permissionReport.CommandResults += @{
                Cmdlet = $test.Cmdlet
                Category = $test.Category
                Accessible = $false
                ErrorMessage = $_.Exception.Message
            }
        }
    }
    
    return $permissionReport
}

# Usage
$diagReport = Diagnose-PurviewPermissions
$diagReport | ConvertTo-Json | Out-File "C:\Diagnostics\permissions-report.json"
$diagReport.CommandResults | Format-Table
```

### Session Management Troubleshooting

```powershell
# Diagnose connection issues
function Resolve-PurviewConnectionIssue {
    [CmdletBinding()]
    param(
        [string]$UserPrincipalName = "admin@contoso.com"
    )
    
    # Check existing sessions
    $sessions = Get-PSSession | Where-Object { $_.ConfigurationName -like "*Compliance*" }
    
    if ($sessions) {
        Write-Host "Found $($sessions.Count) active Purview session(s)"
        
        foreach ($session in $sessions) {
            $timeConnected = (Get-Date) - $session.CreationTime
            Write-Host "Session created: $($session.CreationTime), Duration: $($timeConnected.Hours)h $($timeConnected.Minutes)m"
            
            # Test connection
            try {
                Invoke-Command -Session $session -ScriptBlock { Get-DlpCompliancePolicy -ResultSize 1 }
                Write-Host "Session is ACTIVE and functional" -ForegroundColor Green
            }
            catch {
                Write-Host "Session is INACTIVE or broken: $_" -ForegroundColor Red
                Remove-PSSession -Session $session
            }
        }
    }
    else {
        Write-Host "No active Purview sessions found. Attempting new connection..." -ForegroundColor Yellow
        
        try {
            Connect-IPPSSession -UserPrincipalName $UserPrincipalName
            Write-Host "Successfully established new Purview session" -ForegroundColor Green
        }
        catch {
            Write-Host "Failed to establish connection: $_" -ForegroundColor Red
            return $false
        }
    }
    
    return $true
}

# Usage
Resolve-PurviewConnectionIssue -UserPrincipalName "admin@contoso.com"
```

### Policy Distribution Troubleshooting

```powershell
# Monitor and resolve policy distribution issues
function Monitor-DlpPolicyDistribution {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [string]$PolicyName,
        
        [Parameter(Mandatory=$false)]
        [int]$MaxWaitMinutes = 30
    )
    
    $policy = Get-DlpCompliancePolicy -Identity $PolicyName
    $elapsedMinutes = 0
    
    do {
        $distributionStatus = (Get-DlpCompliancePolicy -Identity $PolicyName -DistributionDetail).DistributionStatus
        
        Write-Host "Distribution Status: $distributionStatus (Elapsed: $elapsedMinutes minutes)"
        
        if ($distributionStatus -eq "Complete") {
            Write-Host "Policy distribution COMPLETE" -ForegroundColor Green
            return $true
        }
        elseif ($distributionStatus -eq "Error") {
            Write-Host "Policy distribution ERROR" -ForegroundColor Red
            return $false
        }
        
        if ($elapsedMinutes -ge $MaxWaitMinutes) {
            Write-Host "Distribution timeout (exceeded $MaxWaitMinutes minutes)" -ForegroundColor Yellow
            return $false
        }
        
        Start-Sleep -Seconds 30
        $elapsedMinutes += 0.5
    } while ($true)
}

# Usage
Monitor-DlpPolicyDistribution -PolicyName "Global-PII-Policy-v1"
```