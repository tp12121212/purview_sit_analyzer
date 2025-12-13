# Advanced Regex Patterns & Custom Classification Methods for Microsoft Purview

## Table of Contents
1. [Advanced Regex Validators & Checksum Logic](#advanced-validators)
2. [Complex Pattern Matching with Lookaround Assertions](#lookaround-patterns)
3. [Hybrid Detection Approaches](#hybrid-approaches)
4. [EDM & Fingerprinting Integration](#edm-fingerprinting)
5. [Performance Optimization Techniques](#performance)
6. [XML Rule Package Configuration](#xml-configuration)
7. [Real-World Advanced Patterns](#real-world)

---

## Advanced Regex Validators & Checksum Logic {#advanced-validators}

### 1. Custom Checksum Validator with Weighted Algorithms

```xml
<Validators id="Validator_custom_account_number">
  <Validator type="Checksum">
    <Param name="Weights">7,3,1,7,3,1,7,3,1,7,3,1,7,3</Param>
    <Param name="Mod">11</Param>
    <Param name="CheckDigit">15</Param>
    <Param name="ModCoefficient">0</Param>
  </Validator>
</Validators>
```

**Use Case**: Detecting organization-specific account numbers with custom mod-11 checksum validation across 14 digits with a check digit in position 15.

### 2. Advanced Checksum with ASCII Conversion & Position-Based Updates

```xml
<Validators id="Validator_alphanumeric_license">
  <Validator type="Checksum">
    <Param name="Weights">1,1,2,1,1,1,1,1,1,1,1,1,1,1,1,1</Param>
    <Param name="Mod">9</Param>
    <Param name="CheckDigit">7</Param>
    <Param name="UseAscii">1</Param>
    <Param name="PositionBasedUpdate">match-1-A-10,match-2-B-11</Param>
  </Validator>
</Validators>
```

**Purpose**: Supports alphanumeric identifiers where letters are converted to ASCII values before checksum computation, with position-specific substitution rules.

### 3. Multi-Digit Result Reduction (Luhn-Style Validation)

```xml
<Validators id="Validator_multi_digit_reduction">
  <Validator type="Checksum">
    <Param name="Weights">2,1,2,1,2,1,2,1,2,1,2,1,2,1,2,1</Param>
    <Param name="Mod">10</Param>
    <Param name="MultiDigitResult">sum_digits</Param>
    <Param name="CheckDigit">16</Param>
  </Validator>
</Validators>
```

**Application**: Credit card detection (Luhn algorithm) where multi-digit intermediate results are reduced via digit summation.

### 4. Conditional Check Digit Substitution

```xml
<Validators id="Validator_conditional_check_digit">
  <Validator type="Checksum">
    <Param name="Weights">1,2,3,4,5,6,7,8,9,1</Param>
    <Param name="Mod">11</Param>
    <Param name="CheckDigit">10</Param>
    <Param name="CheckDigitValue">repeat-list:0,10|substitute-with:X</Param>
  </Validator>
</Validators>
```

**Use Case**: Identifiers where check digit values of 0 or 10 are substituted with 'X', requiring recomputation logic.

---

## Complex Pattern Matching with Lookaround Assertions {#lookaround-patterns}

### 1. Negative Lookahead for Excluding Test Data

```regex
^(?!.*(?:TEST|DEMO|SAMPLE))(?!.*\b(0000|1111|2222|3333|4444|5555|6666|7777|8888|9999)\b)[0-9]{10}$
```

**Pattern Logic**:
- `(?!.*(?:TEST|DEMO|SAMPLE))` - Rejects any string containing test markers anywhere
- `(?!.*\b(0000|1111|2222|3333|4444|5555|6666|7777|8888|9999)\b)` - Excludes repetitive digit sequences
- `[0-9]{10}` - Matches exactly 10 digits
- Anchors `^` and `$` ensure full string matching

**Performance Note**: Place most likely-to-fail conditions first to enable early rejection.

### 2. Negative Lookbehind with Boundary Conditions

```regex
(?<!GUID:)(?<!ID-)(?<!REF:)[A-Z]{3}[0-9]{8}(?![-]\d{2})(?!TEST)
```

**Breakdown**:
- `(?<!GUID:)(?<!ID-)(?<!REF:)` - Negative lookbehind rejecting common prefixes (fixed-width limitation applies)
- `[A-Z]{3}[0-9]{8}` - Core pattern: 3 letters + 8 digits
- `(?![-]\d{2})(?!TEST)` - Negative lookahead excluding suffixes indicating test records

**Optimized for .NET**: Use position-based lookahead first, then lookbehind to minimize backtracking.

### 3. Positive Lookahead with Context Extraction

```regex
(?=.*\b(CONFIDENTIAL|SENSITIVE|SECRET)\b)(?:PROJ|PRJ)-[0-9]{6}-[A-Z]{2}(?=["\s,]|$)
```

**Purpose**: Ensures project IDs appear within documents marked as sensitive, validating contextual relevance.

### 4. Variable-Width Lookbehind (. NET-Specific)

```regex
(?<=[A-Z]{0,3}[:|=|_])([0-9A-F]{32})(?![0-9A-F])
```

**Use Case**: Detecting 32-character hex tokens (like API keys) preceded by variable-length identifiers, using .NET's reversed pattern engine.

---

## Hybrid Detection Approaches {#hybrid-approaches}

### 1. Multi-Pattern SIT with Cascading Confidence Levels

```xml
<Entity id="CustomFinancialId" patternsProximity="300" recommendedConfidence="85">
  
  <!-- High Confidence: Full format + checksum + keywords -->
  <Pattern confidenceLevel="85">
    <IdMatch idRef="Regex_financial_id_full" />
    <All minMatches="3">
      <Match idRef="Keyword_financial" />
      <Match idRef="Keyword_account" />
      <Match idRef="Validator_checksum" />
    </All>
  </Pattern>
  
  <!-- Medium Confidence: Core pattern + keywords + proximity -->
  <Pattern confidenceLevel="75">
    <IdMatch idRef="Regex_financial_id_core" />
    <Any minMatches="2">
      <Match idRef="Keyword_financial" />
      <Match idRef="Keyword_transaction" />
      <Match idRef="Regex_currency" />
    </Any>
  </Pattern>
  
  <!-- Low Confidence: Pattern alone with broad matching -->
  <Pattern confidenceLevel="65">
    <IdMatch idRef="Regex_financial_id_pattern" />
  </Pattern>
  
</Entity>
```

**Strategy**: Tiered detection enabling high-confidence blocking while maintaining lower-confidence detection for audit trails.

### 2. Context-Aware Detection with Column Name Matching

**For Data Map Classification Rules**:
```regex
Column Pattern: ^(Employee_ID|EMP_ID|EMPID)$
Data Pattern: (?i)^[A-Z]{3}[0-9]{8}$
```

Combines column metadata with data validation, reducing false positives in structured datasets.

### 3. EDM + Pattern-Based Hybrid Approach

```xml
<!-- EDM Configuration for Exact Matches -->
<EDMSchema id="employee_records_schema">
  <Field name="EmployeeID" type="primary" />
  <Field name="Department" type="secondary" />
  <Field name="Manager" type="secondary" />
</EDMSchema>

<!-- Pattern-Based Supporting Element -->
<Entity id="EDM_Employee_Hybrid" patternsProximity="500" recommendedConfidence="90">
  <Pattern confidenceLevel="90">
    <IdMatch idRef="EDM_Match_EmployeeID" />
    <All minMatches="2">
      <Match idRef="Keyword_department_list" />
      <Match idRef="Regex_manager_name" />
    </All>
  </Pattern>
</Entity>
```

**Advantage**: Combines exact matching for zero false positives with pattern validation for flexibility.

---

## EDM & Fingerprinting Integration {#edm-fingerprinting}

### 1. EDM Schema with Multi-Field Matching

```xml
<EDMSchema id="customer_pii_schema">
  <Field name="SSN" type="primary" />
  <Field name="AccountNumber" type="primary" />
  <Field name="FirstName" type="secondary" />
  <Field name="LastName" type="secondary" />
  <Field name="Email" type="secondary" ignored_delimiters="." />
</EDMSchema>
```

**CSV Format** (hashed before upload):
```
SSN,AccountNumber,FirstName,LastName,Email
123-45-6789,ACC-9876543210,John,Doe,john.doe@company.com
```

### 2. EDM with Ignored Delimiters for Flexible Matching

```xml
<EDMSchema id="flexible_phone_schema">
  <Field name="PhoneNumber" type="primary" ignored_delimiters="- ()." />
  <Field name="Name" type="secondary" />
</EDMSchema>
```

**Matches All Variants**:
- `555-123-4567`
- `(555) 123-4567`
- `5551234567`
- `555.123.4567`

### 3. Fingerprinting Configuration via PowerShell

```powershell
# Create fingerprints from template documents
$EmployeeTemplate = [System.IO.File]::ReadAllBytes('C:\Templates\Employee_Form_Template.docx')
$EmployeeFingerprint = New-DlpFingerprint -FileData $EmployeeTemplate `
  -Description "Employee Onboarding Form Template"

$ContractTemplate = [System.IO.File]::ReadAllBytes('C:\Templates\Service_Agreement.docx')
$ContractFingerprint = New-DlpFingerprint -FileData $ContractTemplate `
  -Description "Service Agreement Template"

# Create SIT combining multiple fingerprints
New-DlpSensitiveInformationType -Name "Confidential_HR_Contracts" `
  -Fingerprints $EmployeeFingerprint[0], $ContractFingerprint[0] `
  -Description "HR documents and legal contracts" `
  -IsExact $false
```

---

## Performance Optimization Techniques {#performance}

### 1. Lookahead Ordering for Early Failure

```regex
# GOOD: Fast-failing conditions first
^(?=^.{9,}$)(?!.*\b(TEST|0000|INVALID)\b)(?=[A-Z]{3})[A-Z]{3}[0-9]{6}$

# BAD: Expensive conditions first (will check full string before failing)
^[A-Z]{3}[0-9]{6}(?!.*\b(TEST|0000|INVALID)\b)(?=^.{9,}$)$
```

### 2. Anchor Placement for Regex Engine Efficiency

```regex
# OPTIMIZED: Use anchors to prevent unnecessary backtracking
^(?=.*[A-Z])(?=.*[0-9])(?!.*[TEST])([A-Z0-9]{15})$

# LESS EFFICIENT: Same logic without strategic anchoring
(?=.*[A-Z])([A-Z0-9]{15})(?=.*[0-9])(?!.*TEST)
```

### 3. Non-Capturing Groups to Reduce Overhead

```regex
# Use (?:...) instead of (...) for non-captured patterns
^(?:EMP|EMPL)-(?:[A-Z]{3})-(?:\d{6})$  # Better
^(EMP|EMPL)-(A-Z]{3})-(\d{6})$         # More memory overhead
```

### 4. Atomic Groups for Preventing Backtracking (PCRE/. NET)

```regex
^(?>EMP-)[0-9]{6}$
```

Prevents engine from reconsidering the `EMP-` prefix if later parts fail, significantly improving performance on non-matching strings.

---

## XML Rule Package Configuration {#xml-configuration}

### 1. Complete Custom SIT Rule Package Example

```xml
<?xml version="1.0" encoding="utf-16"?>
<RulePackage xmlns="http://schemas.microsoft.com/office/2011/mce">
  <RulePack id="8f0ab8b9-8e4f-4e9d-a5c8-1b2e3f4a5b6c">
    <Version major="1" minor="0" build="0" revision="0"/>
  </RulePack>
  
  <!-- Define regex patterns -->
  <Resources>
    <Regex id="Regex_enhanced_employee_id">
      ^(?!.*\b(0000|1111|2222|3333|4444|5555|6666|7777|8888|9999)\b)
      (?!.*TEST)(?!.*DEMO)[A-Z]{3}[0-9]{8}$
    </Regex>
    
    <Regex id="Regex_project_identifier">
      ^(?=.*PROJ)(?!.*ARCHIVED)PROJ-[0-9]{4}-[A-Z]{2}-[0-9]{3}$
    </Regex>
  </Resources>
  
  <!-- Define keyword lists -->
  <Keywords>
    <Keyword id="Keyword_employment_terms" name="Employment">
      <Group>
        <Term>employee</Term>
        <Term>personnel</Term>
        <Term>staff</Term>
        <Term>hire</Term>
      </Group>
    </Keyword>
  </Keywords>
  
  <!-- Define validators -->
  <Validators>
    <Validator id="Validator_employee_checksum" type="Checksum">
      <Param name="Weights">1,2,3,4,5,6,7,8</Param>
      <Param name="Mod">11</Param>
      <Param name="CheckDigit">8</Param>
    </Validator>
  </Validators>
  
  <!-- Entity definition combining all elements -->
  <Entity id="CustomEmployeeID" patternsProximity="300" 
          recommendedConfidence="85">
    
    <Pattern confidenceLevel="85">
      <IdMatch idRef="Regex_enhanced_employee_id" />
      <Any minMatches="2">
        <Match idRef="Keyword_employment_terms" />
        <Match idRef="Keyword_hr_related" />
      </Any>
    </Pattern>
    
    <Pattern confidenceLevel="75">
      <IdMatch idRef="Regex_enhanced_employee_id" />
    </Pattern>
    
  </Entity>
  
</RulePackage>
```

### 2. XML Pattern with TextMatchFilters

```xml
<Entity id="CustomFinancialAccount" patternsProximity="300">
  <Pattern confidenceLevel="80">
    <IdMatch idRef="Regex_account_number" />
    <TextMatchFilter refname="FilterExcludeTestAccounts" operator="Not Equal">
      <Pattern>TEST|SAMPLE|DEMO</Pattern>
    </TextMatchFilter>
    <TextMatchFilter refname="FilterRequireBankKeyword" operator="Equal">
      <Pattern>(ACCOUNT|BANK|FINANCIAL)</Pattern>
    </TextMatchFilter>
  </Pattern>
</Entity>
```

---

## Real-World Advanced Patterns {#real-world}

### 1. Sophisticated Financial Account Detection

```regex
# Pattern: Institution code (2 chars) + Branch code (4 digits) + Account (10 digits) + Check digit
# With negative lookaheads for test values and repetitive sequences

(?!.*\b(0000|1111|2222|3333|4444|5555|6666|7777|8888|9999)\b)
(?!.*TEST(?:ACCT|ACC|ACCOUNT))
(?!.*DEMO)
(?=.*(?:BANK|ACCOUNT|FINANCIAL))
[A-Z]{2}\d{4}\d{10}(?=[\s\-,;]|$)
```

### 2. Healthcare Provider Identification

```regex
# Pattern: NPI (10 digits) with Luhn checksum validation
# Excludes test NPIs (2500000000-2599999999)

(?!25\d{8})  # Exclude test NPI range
(?=.*(?:NPI|PROVIDER))
(?:[0-9]{7}(?:[0-9]{3}|X{3}))  # Legacy format
|
(?:[0-9]{10}(?:\[0-9]{1})?)  # Standard NPI with optional suffix
```

### 3. Intellectual Property Classification with Context

```regex
# Detects project codes with surrounding sensitive terms

(?=.*(?:CONFIDENTIAL|PROPRIETARY|SECRET|PATENT))
(?!.*PUBLIC)
(?!.*RELEASED)
(?:PROJ|PROJECT)-[0-9]{6}-[A-Z]{2}
(?=[\s\-:#]|\b(?:VERSION|DRAFT|INTERNAL)\b)
```

### 4. Multi-Country Tax ID Detection

```regex
# Handles varying formats across regions with validation

# US SSN with exclusions
(?!000-00-0000)(?!666-?(?:0{2}))(?!9\d{2}-?(?:0{2}))
(\d{3}-?\d{2}-?\d{4})

# Canadian SIN with MOD 10
(?!0{3}-?\d{6})
([0-9]{3}-[0-9]{3}-[0-9]{3})

# UK NINO
(?!BG|GB|NK|KN|TN|ZZ)
([A-CEHJLMPRSTVWXYZ]{1}[A-CEHJLMPRSTVWXYZ]{1}\d{6}[A-D]{1})
```

### 5. Advanced Credential Detection

```regex
# API Key + Bearer Token + Secret Key patterns with contextual validation

# AWS Access Key ID format
(?<![A-Z0-9])AKIA[0-9A-Z]{16}(?![A-Z0-9])

# Azure SAS Token pattern
(?=.*SharedAccessSignature)
sv=\d{4}-\d{2}-\d{2}&ss=[a-z]+&srt=[a-z]+&sp=[a-z]+&se=\d{4}-\d{2}-\d{2}

# Generic Bearer Token (high context requirement)
(?=.*(?:Authorization|Bearer|Token|API[_-]?KEY))
(?!.*TEST|SAMPLE)
(?:[A-Za-z0-9\-._~+/]+=*)
```

---

## Best Practices for Advanced SITs

1. **Complexity Scaling**: Start with low-complexity patterns and incrementally add conditions rather than building overly complex initial patterns
2. **Performance Testing**: Always test regex patterns on 1-5 MB sample files before production deployment
3. **Validation Chaining**: Layer validators (checksum → date → functions) rather than attempting all-in-one patterns
4. **False Positive Reduction**: Use `TextMatchFilter` with exclusion lists for known test/demo data
5. **Confidence Level Alignment**: High confidence requires multiple supporting elements; use carefully to avoid missed detections
6. **Proximity Optimization**: Set character proximity to reasonable distances (200-500) to avoid matching unrelated nearby content
7. **EDM Preference**: For structured, known-value data (employee IDs, customer accounts), prefer EDM over regex for near-zero false positives
8. **Documentation**: Maintain regex comments and validation logic documentation for maintenance teams

