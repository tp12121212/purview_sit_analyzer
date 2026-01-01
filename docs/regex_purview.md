# Advanced Regex Patterns for Microsoft Purview Custom Sensitive Information Types

## 1. Advanced Regex Pattern Architecture

### 1.1 Negative Lookahead/Lookbehind for Exclusion

Negative lookahead `(?!pattern)` and lookbehind `(?<!pattern)` are critical for reducing false positives by excluding patterns you don't want matched.

#### Pattern: Employee ID with Repeat Digit Exclusion
```regex
(?!.*(0000|1111|2222|3333|4444|5555|6666|7777|8888|9999).*)(?!(0))[0-9]{9}(?!(0))[0-9]
```

**Explanation:**
- `(?!.*(0000|1111|2222|3333|4444|5555|6666|7777|8888|9999).*)` - Negative lookahead rejecting four consecutive identical digits anywhere in the string
- `(?!(0))` - Negative lookahead ensuring first digit is not 0
- `[0-9]{9}` - Matches exactly 9 digits
- `(?!(0))` - Negative lookahead ensuring final digit is not 0

**Use Case:** Organizational employee identifiers where sequential repeats and leading/trailing zeros are invalid patterns.

#### Pattern: Email Address Excluding Common Literals
```regex
(?<!((From|To|CC):\s*([a-zA-Z0-9.\s<>@\-\(\)];)*))([a-zA-Z0-9._\-]+@[a-zA-Z0-9._\-]+\.[a-zA-Z]{2,15})\b
```

**Explanation:**
- `(?<!((From|To|CC):\s*(...)*))` - Negative lookbehind excluding email addresses immediately after email headers
- Prevents flagging email addresses in To/From/CC lines as sensitive when embedded in document metadata

**Use Case:** Detecting email addresses in document body without triggering on header metadata that's already part of email headers.

---

## 2. Character Proximity & Instance Count Optimization

### 2.1 Understanding Proximity Windows

Purview's default proximity is **300 characters**. This controls how close primary and supporting elements must be.

#### Advanced Proximity Configuration
```xml
<Pattern confidenceLevel="85" patternsProximity="150">
  <IdMatch idRef="Regex_CreditCard"/>
  <Match idRef="KeywordList_CardKeywords"/>
</Pattern>
```

**Optimization Strategy:**
- **High Confidence (85+):** Use tight proximity (100-150 chars) with multiple supporting elements
- **Medium Confidence (65-75):** Default 300 chars with at least one supporting element
- **Low Confidence (<65):** Use 500+ chars or multiple keyword combinations

### 2.2 Instance Count Tuning for Reduced False Positives

Instance count settings (min/max) control how many SIT matches must exist in a single document.

**Strategy Matrix:**

| Pattern Type | Confidence | Min Count | Max Count | Rationale |
|---|---|---|---|---|
| High-Specificity Regex | 85-100 | 1-5 | Any | Few matches = likely true positive |
| Medium-Specificity Regex | 70-84 | 5-10 | 50-100 | Balances sensitivity |
| Low-Specificity Regex | 50-69 | 20-50 | Any | Many matches required for confidence |
| Combined Evidence Pattern | 75-95 | 1-3 | Any | Multiple supporting elements reduce false positives |

**Example: SSN + Name Combination**
```
Min Count: 2 (at least 2 instances of SSN)
Max Count: Any
Confidence: 85 (high, since SSN+Name is specific)
```

---

## 3. Advanced Regex Patterns for Common Sensitive Data

### 3.1 Multi-Format Organizational Identifiers

```regex
(?i)(?:\b[A-Z]{2}\d{6}(?:\-\d{3})?\b|(?:\d{4}[\-\/]\d{4}[\-\/]\d{4})|(?:[A-Z]\d{2}[A-Z]\d{3})\b)
```

**Breakdown:**
- `(?i)` - Case insensitive matching
- `[A-Z]{2}\d{6}(?:\-\d{3})?` - Format: 2 letters + 6 digits, optionally followed by -3 digits
- `\d{4}[\-\/]\d{4}[\-\/]\d{4}` - Format: 4-4-4 digit pattern with hyphens or slashes
- `[A-Z]\d{2}[A-Z]\d{3}` - Format: Letter-2 digits-Letter-3 digits

**Supporting Elements Recommendation:**
- Keywords: "Employee ID", "Emp #", "Staff #"
- Proximity: 200 characters
- Confidence: 75 (medium) - regex catches multiple formats

### 3.2 Medical Record Numbers with Checksums

```regex
(?i)\b([0-9]{3})[\-\s]?([0-9]{5})[\-\s]?([0-9]{1})\b
```

**With Checksum Validator Configuration (XML):**
```xml
<Validators id="Validator_MRN_Checksum">
  <Validator type="Checksum">
    <Param name="Weights">1,2,1,2,1,2,1,2,1</Param>
    <Param name="Mod">10</Param>
    <Param name="CheckDigit">9</Param>
  </Validator>
</Validators>

<Regex id="Regex_MRN" validators="Validator_MRN_Checksum">
  ([0-9]{8}[0-9]{1})
</Regex>
```

**Explanation:**
- Weights define multiplier for each digit position (1 and 2 alternating for Luhn-like algorithm)
- Mod 10 operation validates last digit is correct checksum
- `CheckDigit` parameter specifies position 9 contains the check digit

### 3.3 Bank Account Numbers with Format Validation

```regex
(?i)(?<![\w])(?:^|\s)(?:(?:
  \b[A-Z]{2}[0-9]{2}[A-Z0-9]{1,30}\b|  # IBAN format
  \b[0-9]{8}[\-\s]?[0-9]{7}[\-\s]?[0-9]{1}\b|  # US routing + account + check
  \b(?:AC|ACCT|ACCOUNT)[\s\-:]*([0-9]{10,18})\b  # Keywords + variable length
))(?![\w])
```

**Explanation:**
- IBAN pattern: 2 letters + 2 digits + up to 30 alphanumeric characters
- US format: 8 digits (routing) + 7 digits (account) + 1 digit (check)
- Keyword-based: "AC", "ACCT", "ACCOUNT" followed by 10-18 digit account number
- `(?<![\w])` and `(?![\w])` - Word boundaries to prevent partial matches

### 3.4 Advanced Credit Card Detection (Beyond Luhn)

```regex
(?i)(?:(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13}|3(?:0[0-5]|[68][0-9])[0-9]{11}|6(?:011|5[0-9]{2})[0-9]{12}|(?:2131|1800|35\d{3})\d{11}))(?:[\s\-]?[0-9]{1,4})?)
```

**With Keyword Supporting Elements:**
- Keywords: "card number", "cc", "visa", "mastercard", "amex", "cvv", "cvv2", "cvc"
- Proximity: 200 characters
- Additional check: Exclude common test patterns (4111111111111111, 5555555555554444)

**Exclusion Pattern (Negative Lookahead):**
```regex
(?!4111[\s\-]?1111[\s\-]?1111[\s\-]?1111)(?!5555[\s\-]?5555[\s\-]?5555[\s\-]?5555)
```

---

## 4. Advanced Validator Configuration

### 4.1 Complex Checksum Validators with ASCII Conversion

```xml
<Validators id="Validator_IDCardChecksum">
  <Validator type="Checksum">
    <Param name="Weights">1,1,2,1,1,1,1,1,1,1,1,1,1,1,1,1</Param>
    <Param name="Mod">9</Param>
    <Param name="CheckDigit">7</Param>
    <Param name="UseAscii">1</Param>
    <Param name="PositionBasedUpdate">
      <Update match-position="1" replacewith="2"/>
    </Param>
  </Validator>
</Validators>
```

**Parameters Explained:**
- `UseAscii` - Converts non-digit characters to ASCII values before computation (enables alphanumeric validation)
- `PositionBasedUpdate` - Transforms digit at position before checksum calculation
- `CheckDigitValue` - Post-checksum operations if result is in repeat list

### 4.2 Multi-Digit Result Reduction Strategy

For checksums producing multi-digit results:

```xml
<Param name="MultiDigitResult">SumDigits</Param>
```

This reduces intermediate results to single digits by summing their digits (e.g., 12 → 1+2 = 3).

---

## 5. Multiple Pattern Strategies for Accuracy

### 5.1 Pattern Strategy: Progressive Confidence Levels

```xml
<Entity id="UUID-CustomPII" patternsProximity="300" recommendedConfidence="85">
  <!-- Pattern 1: High confidence - exact format + keywords + checksum -->
  <Pattern confidenceLevel="95">
    <IdMatch idRef="Regex_ExactFormat"/>
    <Match idRef="KeywordList_Primary"/>
    <Match idRef="Regex_Checksum"/>
  </Pattern>

  <!-- Pattern 2: Medium confidence - exact format + keywords only -->
  <Pattern confidenceLevel="75">
    <IdMatch idRef="Regex_ExactFormat"/>
    <Match idRef="KeywordList_Primary"/>
  </Pattern>

  <!-- Pattern 3: Low confidence - exact format only (as fallback) -->
  <Pattern confidenceLevel="55">
    <IdMatch idRef="Regex_ExactFormat"/>
  </Pattern>
</Entity>
```

**Usage:** Use Pattern 1 for strict policies, Pattern 2 for balanced protection, Pattern 3 as catch-all.

### 5.2 Combining Multiple Regex Conditions

```xml
<Pattern confidenceLevel="85">
  <IdMatch idRef="Regex_PrimaryPattern"/>
  <Any minMatches="2" maxMatches="3">
    <Match idRef="Regex_SecondaryPattern1"/>
    <Match idRef="Regex_SecondaryPattern2"/>
    <Match idRef="KeywordList_SupportingEvidenceKeywords"/>
  </Any>
</Pattern>
```

**Explanation:**
- `<Any>` with `minMatches="2"` requires matching at least 2 of the 3 elements
- Dramatically reduces false positives by requiring multiple corroborating evidence

---

## 6. Exact Data Matching (EDM) Advanced Techniques

### 6.1 Multi-Column Composite Matching

```xml
<ExactMatch id="EDM_CustomerPII" patternsProximity="300" dataStore="CustomerDataStore">
  <Pattern confidenceLevel="90">
    <IdMatch matches="SSN" classification="U.S. Social Security Number (SSN)"/>
    <Any minMatches="2" maxMatches="3">
      <Match matches="LastName"/>
      <Match matches="DOB"/>
      <Match matches="Email"/>
    </Any>
  </Pattern>
  
  <Pattern confidenceLevel="75">
    <IdMatch matches="Email" classification="Email Address"/>
    <Match matches="Phone"/>
  </Pattern>
</ExactMatch>
```

**Advanced Consideration:** Use `classification` attributes to specify which built-in SIT to use as trigger, ensuring precise candidate detection.

### 6.2 Dictionary-Based Primary Elements for EDM

```xml
<Entity id="EDM_LastNameMatch" patternsProximity="300" dataStore="PersonalData">
  <Pattern confidenceLevel="80">
    <IdMatch matches="LastName" classification="All Last Names"/>
    <Match matches="FirstName"/>
    <Match matches="SSN"/>
  </Pattern>
</Entity>
```

**Strategy:** Use Named Entity Recognition (All Last Names) as primary element combined with EDM for multi-column validation.

---

## 7. False Positive Reduction Techniques

### 7.1 Exclusion Filtering

```xml
<TextMatchFilter filter="Exclude">
  <Filter>
    <RegularExpression>(?i)(test|demo|sample|example|fake|null)</RegularExpression>
  </Filter>
</TextMatchFilter>
```

Applies to primary element and can exclude entire documents from matching.

### 7.2 String Matching vs Word Matching

**String Match (Default):**
- Matches substring: "ID:123456789Extra" → matches
- Use for: credit cards, SSNs, structured IDs within text

**Word Match:**
- Matches whole word: "ID:123456789" → matches, "ID:123456789Extra" → no match
- Use for: keywords, standalone identifiers

Configuration in UI or XML:
```xml
<Pattern stringMatch="true"> <!-- String match mode -->
  <IdMatch idRef="Regex_Pattern"/>
</Pattern>
```

### 7.3 Proximity-Based Exclusion

Exclude matches where supporting elements are too far away:

```xml
<Pattern confidenceLevel="85" patternsProximity="100">
  <IdMatch idRef="Regex_MainPattern"/>
  <Match idRef="KeywordList_Supporting" minCount="1"/>
</Pattern>
```

Tight proximity (100 chars) ensures supporting evidence is genuinely contextual.

---

## 8. Performance and Scalability Considerations

### 8.1 Regex Performance Optimization

**Avoid These Patterns (Too Expensive):**
```regex
\b\w+\b           # Matches every word (100+ matches per second)
\w+               # Matches any string
\d*               # Matches any digit length
[A-Za-z0-9]+      # Overly broad
```

**Optimized Alternatives:**
```regex
\b[A-Z]{2}\d{6}\b          # Specific format
(?:19|20)\d{2}             # Year range only
[0-9]{9,11}                # Specific length
(?i)(?:SSN|employee).*\d{9} # Keywords + specific pattern
```

### 8.2 Instance Count Boundaries

- **Min Count:** Start at 1 for high-confidence patterns, 5+ for lower confidence
- **Max Count:** Use "Any" for open-ended, or limit to 100+ if suspecting high false positive rate

### 8.3 Rule Package Size Constraints

- Maximum 20 distinct regex patterns per SIT
- Maximum 150 KB rule package size
- Maximum 1 MB total for all keyword dictionaries (post-compression)

---

## 9. Advanced XML RulePackage Configuration

### 9.1 Complete Custom SIT with Multiple Components

```xml
<?xml version="1.0" encoding="utf-8"?>
<RulePackage xmlns="http://schemas.microsoft.com/office/2016/contentmarkup">
  <RulePack id="advanced-custom-sit-rulep">
    <Version build="1" major="1" minor="0" revision="0"/>
    <Publisher id="advanced-publisher"/>
    <Details defaultLangCode="en-us">
      <LocalizedDetails langcode="en-us">
        <PublisherName>Advanced Data Classification</PublisherName>
        <Name>Advanced Custom SIT Library</Name>
        <Description>Production-grade sensitive information types</Description>
      </LocalizedDetails>
    </Details>
  </RulePack>
  
  <Rules>
    <!-- Validators -->
    <Validators id="Validator_LuhnChecksum">
      <Validator type="Checksum">
        <Param name="Weights">2,1,2,1,2,1,2,1,2,1,2,1,2,1,2,1</Param>
        <Param name="Mod">10</Param>
        <Param name="CheckDigit">16</Param>
      </Validator>
    </Validators>

    <!-- Regular Expressions -->
    <Regex id="Regex_CreditCard" validators="Validator_LuhnChecksum">
      (?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14})
    </Regex>

    <Regex id="Regex_CardKeywords">
      (?i)card\s*number|cc\s*number|credit\s*card
    </Regex>

    <!-- Entity Definition -->
    <Entity id="Advanced_CreditCard" patternsProximity="200" recommendedConfidence="85">
      <Pattern confidenceLevel="90">
        <IdMatch idRef="Regex_CreditCard"/>
        <Match idRef="Regex_CardKeywords"/>
      </Pattern>
      <Pattern confidenceLevel="70">
        <IdMatch idRef="Regex_CreditCard"/>
      </Pattern>
    </Entity>

    <!-- Localized Names -->
    <LocalizedStrings>
      <Resource idRef="Advanced_CreditCard">
        <Name default="true" langcode="en-us">Advanced Credit Card Detection</Name>
        <Description default="true" langcode="en-us">Detects credit cards with Luhn checksum validation</Description>
      </Resource>
    </LocalizedStrings>
  </Rules>
</RulePackage>
```

---

## 10. Real-World Implementation Checklist

### Pre-Deployment Validation

- [ ] Test regex against 100+ sample documents with true positives
- [ ] Test against 100+ sample documents expected to NOT match (false positive testing)
- [ ] Validate checksum calculations with known valid/invalid examples
- [ ] Confirm word boundaries work correctly with delimiters (dashes, slashes, spaces)
- [ ] Test proximity settings with documents of varying lengths (100 chars - 50 KB)
- [ ] Validate confidence level distribution (aim for 90% high confidence, 8% medium, 2% low)
- [ ] Check performance: regex execution time < 100ms per document
- [ ] Test exclusion filters actually exclude test/sample/demo data

### Deployment & Monitoring

- [ ] Start with audit/test mode, not enforcement
- [ ] Monitor false positive rate weekly for first month
- [ ] Adjust confidence levels if false positive rate > 5%
- [ ] Use Content Explorer to spot-check random matches
- [ ] Compare detection rates across file types (PDF vs DOCX vs emails)

---

## 11. Purview Regex 5.1.3 Engine Specifics

### Supported Constructs
- **Lookahead/Lookbehind:** `(?=...)`, `(?!...)`, `(?<=...)`, `(?<!...)`
- **Word Boundaries:** `\b`, `\B`
- **Character Classes:** `[abc]`, `[^abc]`, `\d`, `\w`, `\s`, `.`
- **Quantifiers:** `*`, `+`, `?`, `{n}`, `{n,}`, `{n,m}`
- **Alternation:** `|`
- **Grouping:** `(...)`
- **Anchors:** `^`, `$` (multiline mode available)

### NOT Supported / Limited
- **Recursive patterns:** Not supported
- **Backreferences:** Limited support in classification engine
- **Named groups:** Not accessible post-match
- **Conditional patterns:** `(?(condition)yes|no)` - Not supported

### Case Sensitivity
- By default: Case-insensitive matching
- To enforce case sensitivity: Add `(?-i)` at pattern start (specific regex engines)

---

## Conclusion

Advanced Purview SIT development requires balancing multiple competing requirements: pattern specificity, performance constraints, false positive minimization, and scalability. By leveraging negative lookaheads, checksum validators, multi-pattern strategies, and EDM for structured data, you can build detection systems with >95% accuracy while maintaining sub-100ms processing times. Regular validation and monitoring are essential for production deployments handling millions of documents.

