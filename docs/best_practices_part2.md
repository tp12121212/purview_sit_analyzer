# ADVANCED REGEX PATTERNS AND CUSTOM SIT IMPLEMENTATION GUIDE
## Microsoft Purview - Enterprise Data Classification

---

## TABLE OF CONTENTS
1. Advanced Regex Pattern Techniques
2. Purview-Specific Pattern Implementation
3. Validation Methods and Algorithms
4. Custom Pattern Development Workflow
5. XML Rule Package Configuration
6. Multi-Language and Unicode Patterns
7. False Positive Mitigation
8. Performance Optimization Strategies

---

## 1. ADVANCED REGEX PATTERN TECHNIQUES

### 1.1 Negative Lookahead and Lookbehind

**Negative Lookahead Pattern:**
```regex
(?!0{3}|666|9\d{2})(?:\d{3})-(?:\d{2})-(?:\d{4})
```
- Excludes patterns starting with 000, 666, or 900-999
- Used for SSN validation to eliminate invalid ranges
- More efficient than multiple alternation patterns

**Negative Lookbehind Pattern:**
```regex
(?<!\d)(?:4[0-9]{12}(?:[0-9]{3})?)(?!\d)
```
- Ensures the credit card number isn't embedded in a longer digit sequence
- Fixed-width requirement for lookbehind in .NET regex
- Useful for word boundary detection

### 1.2 Atomic Grouping

**Pattern with Atomic Group:**
```regex
^(?>(?:[A-Z]{3})?)[0-9]{9}$
```
- Atomic group `(?>...)` prevents backtracking
- Significantly improves performance for large-scale scanning
- Prevents regex engine from trying permutations after match failure
- Recommended for patterns with alternation or repetition

### 1.3 Possessive Quantifiers

**Pattern with Possessive Quantifier:**
```regex
^[A-Z]++[0-9]++$
```
- `++` denotes possessive matching (requires .NET or Python 3.11+)
- Prevents backtracking to find alternative matches
- Improves performance for complex patterns
- Use in high-volume DLP scanning scenarios

### 1.4 Conditional Patterns

**Alternation-Based Conditional:**
```regex
(?:(?<=SSN:\s*)\d{3}-\d{2}-\d{4}|(?<=Employee\sID:\s*)[A-Z]\d{8})
```
- Matches different formats based on preceding context
- Reduces false positives by requiring format-specific context
- More accurate than generic pattern matching

### 1.5 Unicode Character Classes

**Multilingual Name Detection:**
```regex
\b[\p{L}]{2,}\s[\p{L}]{2,}\b
```
- `\p{L}` matches any Unicode letter (works with Python regex module)
- Essential for international document scanning
- Supports Greek, Cyrillic, Arabic, CJK characters
- In Purview UI, use locales parameter for language-specific matching

**Script-Specific Matching:**
```regex
\p{Script=Cyrillic}+\s\p{Script=Cyrillic}+
```
- Detects content in specific scripts (Cyrillic, Arabic, etc.)
- Useful for multi-language environments
- Requires Unicode support in regex engine

---

## 2. PURVIEW-SPECIFIC PATTERN IMPLEMENTATION

### 2.1 Enhanced IBAN Pattern

**Pattern:**
```regex
^(?=.*[A-Z]{2})(?=.*[0-9]{2})[A-Z0-9]{15,34}$
```

**Features:**
- Positive lookahead for country code (2 uppercase letters)
- Positive lookahead for check digits (2 digits)
- Validates length range (15-34 characters)
- Supports all IBAN-participating countries

**Purview Configuration:**
- Primary Element: Regex with validators
- Supporting Elements: Keywords (bank, account, IBAN)
- Proximity: 300 characters
- Confidence Level: High (with keywords), Medium (without)

### 2.2 Credit Card Detection with Luhn Validation

**Pattern:**
```regex
(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13}|3(?:0[0-5]|[68][0-9])[0-9]{11}|6(?:011|5[0-9]{2})[0-9]{12}|(?:2131|1800|35\d{3})\d{11})
```

**Features:**
- Visa: 4 + 12-15 digits
- Mastercard: 51-55 + 14 digits
- American Express: 34/37 + 13 digits
- Discover: 6011/65 + 12 digits
- Diners Club: 300-305/36/38 + varying digits

**Purview Validator:**
```xml
<Validators id="CreditCardLuhn">
  <Validator type="Luhn" />
</Validators>
```

**Supporting Elements:**
- Keywords: CVV, CVV2, security code, CID, expir, expiration, valid
- Proximity: 300 characters

### 2.3 SSN with Advanced Exclusion

**Pattern:**
```regex
(?!(?:000|666|9\d{2})\d{4})(?!(?:0{1})\d{4})(?:[0-9]{3}[-\s]?(?:(?:[0-9]{2}[-\s]?[0-9]{4})|(?:[0-9]{5})))(?:\b|(?=[^\d]))
```

**Exclusion Rules:**
- Negative lookahead excludes 000-66-xxxx
- Negative lookahead excludes 666-xx-xxxx
- Negative lookahead excludes 9xx-xx-xxxx
- Negative lookahead excludes xxx-00-xxxx
- Word boundary ensures not part of larger number

**Supporting Elements:**
- Keywords: SSN, Social Security, Tax ID
- Confidence Level: High (with keywords), Medium (without)

### 2.4 Indian Aadhaar Number

**Pattern:**
```regex
(?!(?:0000|1111|2222|3333|4444|5555|6666|7777|8888|9999))(?:[0-9]){12}
```

**Validation:**
- 12-digit requirement
- Excludes repeating digits (0000, 1111, etc.)
- Verhoeff algorithm for checksum (advanced validator)

**Purview Configuration:**
```xml
<Validators id="AadhaarValidator">
  <Validator type="Checksum">
    <Param name="Algorithm">Verhoeff</Param>
    <Param name="CheckDigit">12</Param>
  </Validator>
</Validators>
```

---

## 3. VALIDATION METHODS AND ALGORITHMS

### 3.1 Checksum Validator Configuration

**Weighted Sum with Modulo:**
```xml
<Validators id="LicenseChecksum">
  <Validator type="Checksum">
    <Param name="Weights">1,1,2,1,1,1,1,1</Param>
    <Param name="Mod">9</Param>
    <Param name="CheckDigit">8</Param>
    <Param name="ModCoefficient">0</Param>
  </Validator>
</Validators>
```

**Calculation:**
```
Sum = d1*w1 + d2*w2 + d3*w3 + d4*w4 + d5*w5 + d6*w6 + d7*w7 + d8*w8
Result = Sum % Mod
Validate: Result == CheckDigit
```

### 3.2 Advanced Checksum with ASCII Conversion

**Pattern for Alphanumeric Validation:**
```xml
<Validators id="AdvancedAlphanumeric">
  <Validator type="Checksum">
    <Param name="UseAscii">1</Param>
    <Param name="Weights">1,1,2,1,1,1,1,1,1,1,1,1,1,1,1,1</Param>
    <Param name="Mod">9</Param>
    <Param name="CheckDigit">7</Param>
    <Param name="MultiDigitResult">1</Param>
  </Validator>
</Validators>
```

**Key Parameters:**
- `UseAscii`: Convert letters to ASCII values (A=65, B=66, etc.)
- `MultiDigitResult`: Reduce multi-digit results by summing digits (12 → 1+2 = 3)
- `PositionBasedUpdate`: Replace specific digit positions before calculation
- `CheckDigitValue`: Define disallowed check digit values

### 3.3 Luhn Algorithm

**Standard Implementation:**
```
1. From right to left, double every second digit
2. If doubling results in > 9, subtract 9
3. Sum all digits
4. Total % 10 must equal 0
```

**Purview Application:**
```xml
<Validators id="CardLuhn">
  <Validator type="Luhn" />
</Validators>
```

### 3.4 Date Validator

**Configuration:**
```xml
<Validators id="EmployeeIDDateValidator">
  <Validator type="Date">
    <Param name="DateFormat">DDMMYY</Param>
    <Param name="StartOffset">0</Param>
    <Param name="Length">6</Param>
  </Validator>
</Validators>
```

---

## 4. CUSTOM PATTERN DEVELOPMENT WORKFLOW

### 4.1 Pattern Testing Process

**Step 1: Create Test Data**
```
Valid entries:
- Employee ID: ABC12345678
- SSN: 123-45-6789
- Credit Card: 4532-1234-5678-9010

Invalid entries (test for false positives):
- Project Code: ABC00000000
- Sample Data: TEST12345678
- Demo: 000-00-0000
```

**Step 2: Test Regex Directly**
```
Use regex101.com or similar tool
Test against all valid and invalid entries
Document match counts
```

**Step 3: Configure Purview SIT**
- Upload custom SIT to Purview
- Test using Purview's test feature
- Review confidence scores
- Validate with production samples

### 4.2 Confidence Level Strategy

**High Confidence (Strict):**
- Multiple supporting elements required
- Short character proximity (50-300 characters)
- Specific validators (checksum + date)
- Use when false positives are costly

**Medium Confidence (Balanced):**
- At least one supporting element OR pattern-specific context
- Medium proximity (300-500 characters)
- Single validator or pattern complexity
- Standard use case

**Low Confidence (Permissive):**
- Pattern alone without supporting elements
- Longer proximity (500+ characters)
- No validators
- Use for initial detection/review

### 4.3 Supporting Elements Strategy

**Keyword Lists:**
- Financial: bank, account, routing, transfer, wire
- Identity: SSN, tax ID, passport, license, identification
- Medical: patient, MRN, chart, record, diagnosis

**Keyword Dictionaries:**
- Import from CSV file
- Support multiple languages
- Enable phrase matching with context
- Use for domain-specific terminology

**Proximity Configuration:**
- Closer proximity = higher confidence
- 50-100 characters: Very strict, high confidence
- 100-300 characters: Standard, medium-high confidence
- 300-500 characters: Relaxed, medium confidence
- 500+ characters: Very permissive, low confidence

---

## 5. XML RULE PACKAGE CONFIGURATION

### 5.1 Basic Rule Package Structure

```xml
<?xml version="1.0" encoding="utf-8"?>
<RulePackage xmlns="http://schemas.microsoft.com/office/2011/mce">
  <RulePack id="[GUID]">
    <Version major="1" minor="0" build="0" revision="0" />
    <Publisher id="[GUID]" />
    <Details defaultLangCode="en-us">
      <LocalizedDetails langcode="en-us">
        <PublisherName>Organization Name</PublisherName>
        <Name>Custom SIT Rule Pack</Name>
        <Description>Custom Sensitive Information Types</Description>
      </LocalizedDetails>
    </Details>
  </RulePack>
  <Rules>
    <!-- Entity definitions go here -->
  </Rules>
</RulePackage>
```

### 5.2 Entity Configuration Example

```xml
<Entity id="[GUID-Entity]" patternsProximity="300" recommendedConfidence="85">
  <Pattern confidenceLevel="85">
    <IdMatch idRef="[GUID-Regex]" />
    <Any minMatches="1">
      <Match idRef="[GUID-Keywords]" />
    </Any>
  </Pattern>
  <Pattern confidenceLevel="65">
    <IdMatch idRef="[GUID-Regex]" />
  </Pattern>
</Entity>
```

### 5.3 Regex with Validators

```xml
<Regex id="[GUID-Regex]">
  ^(?!(?:000|666|9\d{2})\d{4})(?:\d{3})-(?:\d{2})-(?:\d{4})$
</Regex>

<Validators id="[GUID-Validators]">
  <Validator type="Checksum">
    <Param name="Weights">...</Param>
    <Param name="Mod">10</Param>
    <Param name="CheckDigit">9</Param>
  </Validator>
</Validators>
```

### 5.4 Keyword Dictionary

```xml
<Keyword id="[GUID-Keywords]">Social Security</Keyword>
<Keyword id="[GUID-Keywords]">SSN</Keyword>
<Keyword id="[GUID-Keywords]">Tax ID</Keyword>

<KeywordList id="[GUID-KeywordList]">
  <Group matchStyle="word" idRef="[GUID-Keywords]" />
</KeywordList>
```

---

## 6. MULTI-LANGUAGE AND UNICODE PATTERNS

### 6.1 Unicode Property Support

**Chinese Characters:**
```regex
[\p{Script=Han}]{2,}
```

**Cyrillic Script:**
```regex
[\p{Script=Cyrillic}]+
```

**Arabic:**
```regex
[\p{Script=Arabic}]+
```

### 6.2 Multilingual Name Detection

**International Names:**
```regex
(?:[\p{L}\p{M}]+[\s-]?)+[\p{L}\p{M}]+
```
- Supports letters and combining marks
- Handles spaces and hyphens
- Works across all Unicode scripts

### 6.3 Locale-Specific Patterns

**In Purview XML:**
```xml
<Pattern confidenceLevel="85">
  <IdMatch idRef="[Regex-ID]" />
  <LocalizeData>
    <Locale langcode="en-us">High</Locale>
    <Locale langcode="fr-fr">High</Locale>
    <Locale langcode="de-de">High</Locale>
    <Locale langcode="zh-cn">Medium</Locale>
  </LocalizeData>
</Pattern>
```

---

## 7. FALSE POSITIVE MITIGATION

### 7.1 Exclusion Strategies

**Exclude Test Values:**
```xml
<Entity>
  <ExcludedMatches>
    <Match>4111111111111111</Match>
    <Match>0000000000</Match>
    <Match>TEST</Match>
  </ExcludedMatches>
</Entity>
```

**Prefix Exclusion:**
```xml
<AdditionalCheck type="ExcludePrefix">
  <Value>EXAMPLE:</Value>
  <Value>DEMO:</Value>
  <Value>TEST:</Value>
</AdditionalCheck>
```

### 7.2 Negative Lookahead Optimization

```regex
(?!0{6})(?!9{6})\d{6}
```
- Excludes patterns that are all zeros
- Excludes patterns that are all nines
- Reduces false positives from generated/test data

### 7.3 Context-Based Filtering

**High Proximity with Keywords:**
- Require sensitive keywords within 100-300 characters
- Increases precision
- Reduces false matches in unrelated content

**Supporting Elements as Gates:**
- Require matching supporting elements before flagging
- Multiple supporting elements = higher confidence
- Uses AND logic for strict matching

---

## 8. PERFORMANCE OPTIMIZATION STRATEGIES

### 8.1 Regex Optimization Techniques

**Use Atomic Groups for Complex Patterns:**
```regex
^(?>(?:pattern1|pattern2|pattern3)).*$
```
- Prevents backtracking after successful match
- Improves scanning speed

**Combine Alternation with Character Classes:**
```
Inefficient: (a|b|c|d|e|f)
Efficient: [a-f]
```

### 8.2 Validator Configuration

**Strategic Validator Placement:**
- Use validators only when necessary
- Checksum validators: ~5-10% performance overhead
- Luhn validation: ~3-5% performance overhead
- Function processors: ~10-15% performance overhead

**Caching Strategies:**
- Purview automatically caches SIT definitions
- Organize related patterns in single rule package
- Limit total rule packages to <10 per tenant

### 8.3 Pattern Complexity Assessment

**Low Complexity (Fast):**
- Simple character classes: `[A-Z0-9]{10}`
- Basic quantifiers: `\d{3}-\d{2}-\d{4}`
- Single alternation: `(format1|format2)`

**Medium Complexity (Moderate):**
- Multiple lookaheads: `(?=.*[A-Z])(?=.*[0-9])`
- Atomic grouping: `(?>pattern)`
- Single validator: Checksum

**High Complexity (Slower):**
- Nested groups with alternation: `(?>(?:a|b)*)`
- Multiple validators: Checksum + Date + Custom
- Extensive Unicode properties: `[\p{L}\p{M}\p{N}]+`

### 8.4 Batch Processing Recommendations

**For Organizations with 100K+ Documents:**
- Use EDM for high-value, frequently occurring data
- Use pattern-based SIT for variable/new data
- Implement confidence level tiers
- Schedule DLP scans during off-peak hours
- Monitor scan performance metrics

---

## BEST PRACTICES SUMMARY

1. **Always Use Validators:** Combine regex with checksum/date validators for 95%+ accuracy
2. **Implement Context Matching:** Use keyword proximity and supporting elements
3. **Test Thoroughly:** Test all patterns against real organizational data before deployment
4. **Monitor False Positives:** Review and exclude common false positive patterns
5. **Use Confidence Levels:** High confidence for critical data, lower for screening
6. **Document Custom SITs:** Maintain XML documentation of all custom SITs
7. **Version Control:** Track changes to rule packages via PowerShell version parameters
8. **Performance Monitor:** Track scan times and adjust pattern complexity accordingly
9. **Use EDM for Exact Data:** Complement regex SIT with EDM for highest accuracy
10. **Regular Updates:** Quarterly review and update of custom SIT definitions

---

## REFERENCES

- Microsoft Learn: Sensitive Information Type Entity Definitions
- Microsoft Learn: DLP Functions
- Microsoft Learn: Exact Data Match (EDM)
- Purview Compliance Portal Documentation
- Regular Expressions.info: Advanced Techniques
