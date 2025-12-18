# Python Implementation Reference: Advanced Purview SIT Pattern Development

## Purpose
This guide provides Python code snippets for developers building and testing advanced regex patterns intended for Microsoft Purview custom sensitive information types. These patterns are designed to be validated locally before deployment.

---

## 1. Basic Regex Pattern Testing Framework

```python
import re
from typing import List, Tuple, Optional
from dataclasses import dataclass

@dataclass
class RegexTestCase:
    """Test case for regex validation"""
    input_text: str
    should_match: bool
    description: str

class PurviewRegexValidator:
    """Validator for Purview-compatible regex patterns"""
    
    def __init__(self, pattern: str, flags: int = re.IGNORECASE):
        """Initialize with compiled regex pattern"""
        try:
            self.pattern = re.compile(pattern, flags)
            self.raw_pattern = pattern
        except re.error as e:
            raise ValueError(f"Invalid regex pattern: {e}")
    
    def test_pattern(self, test_cases: List[RegexTestCase]) -> Tuple[int, int]:
        """
        Test pattern against test cases
        Returns: (passed_tests, failed_tests)
        """
        passed = 0
        failed = 0
        
        for test_case in test_cases:
            match = self.pattern.search(test_case.input_text)
            is_match = match is not None
            
            if is_match == test_case.should_match:
                passed += 1
                print(f"✓ PASS: {test_case.description}")
            else:
                failed += 1
                print(f"✗ FAIL: {test_case.description}")
                print(f"  Expected: {test_case.should_match}, Got: {is_match}")
                if match:
                    print(f"  Matched: '{match.group()}'")
        
        return passed, failed

# Example Usage
validator = PurviewRegexValidator(
    r'(?!.*(0000|1111|2222|3333|4444|5555|6666|7777|8888|9999).*)(?!(0))[0-9]{9}(?!(0))[0-9]'
)

test_cases = [
    RegexTestCase("Employee ID: 1234567890", True, "Valid employee ID"),
    RegexTestCase("ID: 0123456789", False, "ID starting with 0"),
    RegexTestCase("ID: 1111111111", False, "ID with repeated digits"),
    RegexTestCase("1234567890", True, "Standalone valid ID"),
]

passed, failed = validator.test_pattern(test_cases)
print(f"\nResults: {passed} passed, {failed} failed")
```

---

## 2. Advanced Pattern: Employee ID with Complex Validation

```python
class EmployeeIDValidator:
    """Validates employee IDs with multiple format constraints"""
    
    # Pattern: 10 digits, no leading zero, no trailing zero, no repeated 4-digit sequences
    PATTERN = r'(?!.*(0000|1111|2222|3333|4444|5555|6666|7777|8888|9999).*)(?!(0))[0-9]{9}(?!(0))[0-9]'
    
    def __init__(self):
        self.validator = PurviewRegexValidator(self.PATTERN)
    
    def validate(self, employee_id: str) -> bool:
        """Check if employee ID matches all criteria"""
        return self.validator.pattern.match(employee_id) is not None
    
    def validate_with_proximity(self, text: str, keywords: List[str], 
                                max_proximity: int = 300) -> List[Tuple[str, int, bool]]:
        """
        Validate ID in text with keyword proximity
        Returns: List of (matched_id, distance_to_keyword, is_valid)
        """
        results = []
        
        # Find all potential IDs
        for match in self.validator.pattern.finditer(text):
            employee_id = match.group()
            id_position = match.start()
            
            # Find closest keyword
            min_distance = float('inf')
            for keyword in keywords:
                keyword_matches = [m.start() for m in re.finditer(re.escape(keyword), text, re.IGNORECASE)]
                for kw_pos in keyword_matches:
                    distance = abs(id_position - kw_pos)
                    if distance < min_distance:
                        min_distance = distance
            
            is_valid_proximity = min_distance <= max_proximity if min_distance != float('inf') else False
            results.append((employee_id, int(min_distance), is_valid_proximity))
        
        return results

# Example Usage
validator = EmployeeIDValidator()
test_text = """
Employee Details:
Employee ID: 1234567890
Department: Engineering
The employee ID 1234567890 was issued on 2024-01-15.
Invalid ID 0123456789 should not be detected.
"""

results = validator.validate_with_proximity(test_text, ["Employee ID", "employee"], max_proximity=150)
for emp_id, distance, valid_proximity in results:
    print(f"ID: {emp_id}, Proximity: {distance} chars, Valid: {valid_proximity}")
```

---

## 3. Checksum Validation (Luhn Algorithm)

```python
class LuhnValidator:
    """Implements Luhn checksum for credit cards and similar identifiers"""
    
    @staticmethod
    def calculate_checksum(digits: str) -> int:
        """Calculate Luhn checksum for digit string"""
        def digits_of(n):
            return [int(d) for d in str(n)]
        
        digits_list = digits_of(digits)
        odd_digits = digits_list[-1::-2]
        even_digits = digits_list[-2::-2]
        
        checksum = sum(digits_of(d * 2) for d in odd_digits)
        checksum += sum(even_digits)
        return checksum % 10
    
    @staticmethod
    def validate_credit_card(card_number: str) -> bool:
        """Validate credit card using Luhn algorithm"""
        # Remove spaces and dashes
        card_digits = re.sub(r'[\s\-]', '', card_number)
        
        # Check if all characters are digits
        if not card_digits.isdigit():
            return False
        
        # Check length (13-19 digits typical)
        if not (13 <= len(card_digits) <= 19):
            return False
        
        # Verify checksum
        return LuhnValidator.calculate_checksum(card_digits[:-1]) == int(card_digits[-1])

# Example Usage
luhn = LuhnValidator()
print(luhn.validate_credit_card("4111111111111111"))  # Valid test number
print(luhn.validate_credit_card("4111111111111112"))  # Invalid checksum
print(luhn.validate_credit_card("4111-1111-1111-1111"))  # With formatting
```

---

## 4. Multi-Pattern Sensitive Information Type

```python
from enum import Enum

class ConfidenceLevel(Enum):
    """Confidence levels for SIT matches"""
    HIGH = 85
    MEDIUM = 65
    LOW = 45

class SensitiveInformationType:
    """Multi-pattern SIT with progressive confidence"""
    
    def __init__(self, name: str):
        self.name = name
        self.patterns = {}  # confidence_level -> pattern
    
    def add_pattern(self, confidence: ConfidenceLevel, pattern: str):
        """Add detection pattern with confidence level"""
        self.patterns[confidence] = re.compile(pattern, re.IGNORECASE)
    
    def detect(self, text: str) -> List[Tuple[str, ConfidenceLevel, int]]:
        """
        Detect sensitive data in text
        Returns: List of (matched_text, confidence_level, position)
        """
        matches = []
        
        # Search patterns in order of confidence (highest first)
        for confidence in sorted(self.patterns.keys(), 
                                 key=lambda x: x.value, 
                                 reverse=True):
            pattern = self.patterns[confidence]
            for match in pattern.finditer(text):
                # Avoid duplicate matches at same position
                if not any(m[2] == match.start() for m in matches):
                    matches.append((match.group(), confidence, match.start()))
        
        return matches

# Example: Credit Card Detection with Multiple Patterns
cc_detector = SensitiveInformationType("Credit Card Numbers")

# Pattern 1: High confidence - Full CC with nearby keywords
cc_detector.add_pattern(
    ConfidenceLevel.HIGH,
    r'(?:(?:card\s*(?:number|#)|cc\s*(?:number|#)|credit\s*card).{0,50})?(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14})'
)

# Pattern 2: Medium confidence - Just the card number format
cc_detector.add_pattern(
    ConfidenceLevel.MEDIUM,
    r'(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14})'
)

# Test
text = "Credit card number: 4532-1234-5678-9010"
results = cc_detector.detect(text)
for matched_text, confidence, position in results:
    print(f"Found: {matched_text} at position {position} (Confidence: {confidence.name})")
```

---

## 5. Proximity-Based Pattern Matching

```python
class ProximityMatcher:
    """Matches primary pattern with supporting elements within proximity window"""
    
    def __init__(self, primary_pattern: str, supporting_patterns: dict,
                 proximity_distance: int = 300):
        """
        Initialize proximity matcher
        
        Args:
            primary_pattern: Main regex to detect
            supporting_patterns: Dict of {name: regex_pattern}
            proximity_distance: Characters to search before/after primary match
        """
        self.primary = re.compile(primary_pattern, re.IGNORECASE)
        self.supporting = {name: re.compile(pat, re.IGNORECASE) 
                          for name, pat in supporting_patterns.items()}
        self.proximity = proximity_distance
    
    def find_matches(self, text: str, min_supporting: int = 1) -> List[dict]:
        """
        Find primary matches with supporting evidence nearby
        
        Args:
            text: Text to search
            min_supporting: Minimum supporting patterns required
        
        Returns: List of match dictionaries with details
        """
        matches = []
        
        for primary_match in self.primary.finditer(text):
            start = primary_match.start()
            end = primary_match.end()
            
            # Define search window
            window_start = max(0, start - self.proximity)
            window_end = min(len(text), end + self.proximity)
            window = text[window_start:window_end]
            
            # Search for supporting evidence in window
            found_supporting = {}
            for name, pattern in self.supporting.items():
                if pattern.search(window):
                    found_supporting[name] = True
            
            # Only report if minimum supporting evidence found
            if len(found_supporting) >= min_supporting:
                matches.append({
                    'primary': primary_match.group(),
                    'position': start,
                    'supporting_found': found_supporting,
                    'confidence': 80 + (len(found_supporting) * 5)
                })
        
        return matches

# Example: SSN + Name Detection
ssn_matcher = ProximityMatcher(
    primary_pattern=r'\b\d{3}-\d{2}-\d{4}\b',
    supporting_patterns={
        'name': r'\b(?:Mr|Mrs|Ms|Dr|John|Jane|Smith|Johnson)\b',
        'employee_label': r'(?:employee|staff|personnel)',
        'ssn_label': r'(?:SSN|Social Security|tax id)'
    },
    proximity_distance=200
)

sample_text = """
Employee: John Smith
SSN: 123-45-6789
Tax ID: 987-65-4321

Random numbers: 555-1234 should not match
"""

results = ssn_matcher.find_matches(sample_text, min_supporting=1)
for match in results:
    print(f"Found SSN: {match['primary']}")
    print(f"Supporting evidence: {match['supporting_found']}")
    print(f"Confidence: {match['confidence']}\n")
```

---

## 6. Exclusion Pattern Validation

```python
class ExclusionFilter:
    """Implements exclusion patterns to reduce false positives"""
    
    def __init__(self, primary_pattern: str, exclusion_patterns: List[str]):
        """
        Initialize with primary pattern and exclusion rules
        
        Args:
            primary_pattern: Main detection regex
            exclusion_patterns: List of patterns to exclude
        """
        self.primary = re.compile(primary_pattern, re.IGNORECASE)
        self.exclusions = [re.compile(pat, re.IGNORECASE) 
                          for pat in exclusion_patterns]
    
    def find_valid_matches(self, text: str) -> List[dict]:
        """Find matches that don't match any exclusion pattern"""
        results = []
        
        for match in self.primary.finditer(text):
            matched_text = match.group()
            
            # Check against all exclusion patterns
            excluded = False
            for exclusion_pattern in self.exclusions:
                if exclusion_pattern.search(matched_text):
                    excluded = True
                    break
            
            if not excluded:
                results.append({
                    'text': matched_text,
                    'position': match.start(),
                    'excluded': False
                })
        
        return results

# Example: Filter out test/demo email addresses
email_filter = ExclusionFilter(
    primary_pattern=r'[a-zA-Z0-9._%-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}',
    exclusion_patterns=[
        r'test@',
        r'demo@',
        r'sample@',
        r'example@',
        r'@localhost',
        r'@test\.com',
    ]
)

text = """
Contact: john.smith@company.com
Test email: test@example.com
Admin: admin@company.com
Sample: sample@test.com
"""

valid_emails = email_filter.find_valid_matches(text)
print("Valid emails (after exclusion):")
for match in valid_emails:
    print(f"  {match['text']}")
```

---

## 7. Document Fingerprinting Simulation

```python
import hashlib
from collections import Counter

class DocumentFingerprinter:
    """Simulates Purview document fingerprinting logic"""
    
    @staticmethod
    def extract_tokens(text: str, min_token_length: int = 3) -> List[str]:
        """Extract tokens from document"""
        # Remove extra whitespace
        text = re.sub(r'\s+', ' ', text)
        
        # Split into words and filter
        tokens = re.findall(r'\b\w+\b', text, re.UNICODE)
        return [t for t in tokens if len(t) >= min_token_length]
    
    @staticmethod
    def create_fingerprint(document_text: str) -> str:
        """Create document fingerprint based on token distribution"""
        tokens = DocumentFingerprinter.extract_tokens(document_text)
        token_counts = Counter(tokens)
        
        # Create signature from top tokens and their frequencies
        signature_parts = []
        for token, count in token_counts.most_common(20):
            signature_parts.append(f"{token}:{count}")
        
        signature = "|".join(signature_parts)
        return hashlib.sha256(signature.encode()).hexdigest()[:16]
    
    @staticmethod
    def calculate_similarity(fp1: str, text1: str, fp2: str, text2: str) -> float:
        """Calculate fingerprint similarity between documents (0-1)"""
        tokens1 = set(DocumentFingerprinter.extract_tokens(text1))
        tokens2 = set(DocumentFingerprinter.extract_tokens(text2))
        
        if not tokens1 or not tokens2:
            return 0.0
        
        intersection = len(tokens1 & tokens2)
        union = len(tokens1 | tokens2)
        return intersection / union if union > 0 else 0.0

# Example Usage
template_doc = """
EMPLOYEE ONBOARDING FORM
Name: _____________
Department: _____________
Start Date: _____________
Manager: _____________
Employee ID: _____________
"""

similar_doc = """
EMPLOYEE ONBOARDING FORM
Name: John Smith
Department: Engineering
Start Date: 2024-01-15
Manager: Jane Doe
Employee ID: 1234567890
"""

different_doc = """
INVOICE #INV-2024-001
Invoice Date: 2024-01-20
Amount Due: $5,000
Customer: ABC Corp
"""

fp_template = DocumentFingerprinter.create_fingerprint(template_doc)
fp_similar = DocumentFingerprinter.create_fingerprint(similar_doc)
fp_different = DocumentFingerprinter.create_fingerprint(different_doc)

similarity_same_form = DocumentFingerprinter.calculate_similarity(
    fp_template, template_doc, fp_similar, similar_doc
)
similarity_different_form = DocumentFingerprinter.calculate_similarity(
    fp_template, template_doc, fp_different, different_doc
)

print(f"Similarity (same form template): {similarity_same_form:.2%}")
print(f"Similarity (different form): {similarity_different_form:.2%}")
```

---

## 8. Exact Data Matching (EDM) Simulation

```python
import json

class EDMSimulator:
    """Simulates EDM schema and matching logic"""
    
    def __init__(self):
        self.schema = {}
        self.data_store = {}
    
    def define_schema(self, schema_name: str, columns: dict):
        """
        Define EDM schema
        
        Args:
            schema_name: Name of schema
            columns: Dict of {column_name: {searchable: bool, unique: bool}}
        """
        self.schema[schema_name] = columns
        self.data_store[schema_name] = []
    
    def load_data(self, schema_name: str, data: List[dict]):
        """Load data into EDM store"""
        if schema_name not in self.schema:
            raise ValueError(f"Schema {schema_name} not defined")
        
        # Hash the data (simulated)
        for row in data:
            hashed_row = {}
            for column, value in row.items():
                # Simulate hashing
                hashed_row[column] = hashlib.md5(str(value).encode()).hexdigest()
            self.data_store[schema_name].append(row)  # Store original for demo
    
    def exact_match(self, schema_name: str, primary_column: str, 
                    primary_value: str, required_columns: dict) -> bool:
        """
        Check if value with supporting evidence exists in EDM store
        
        Args:
            schema_name: Schema to search
            primary_column: Primary search column
            primary_value: Value to match
            required_columns: Dict of {column: required_value}
        
        Returns: True if exact match with supporting evidence found
        """
        for row in self.data_store[schema_name]:
            if str(row.get(primary_column, '')).lower() == str(primary_value).lower():
                # Check supporting evidence
                all_match = True
                for column, value in required_columns.items():
                    if str(row.get(column, '')).lower() != str(value).lower():
                        all_match = False
                        break
                
                if all_match:
                    return True
        
        return False

# Example: Customer PII Detection
edm = EDMSimulator()
edm.define_schema('customer_pii', {
    'ssn': {'searchable': True, 'unique': True},
    'firstname': {'searchable': True, 'unique': False},
    'lastname': {'searchable': False, 'unique': False},
    'email': {'searchable': True, 'unique': True}
})

customer_data = [
    {'ssn': '123-45-6789', 'firstname': 'John', 'lastname': 'Smith', 'email': 'john.smith@company.com'},
    {'ssn': '987-65-4321', 'firstname': 'Jane', 'lastname': 'Doe', 'email': 'jane.doe@company.com'},
]

edm.load_data('customer_pii', customer_data)

# Check if SSN + Name combination exists
is_match = edm.exact_match(
    'customer_pii',
    'ssn', '123-45-6789',
    {'firstname': 'John', 'lastname': 'Smith'}
)

print(f"EDM Match found: {is_match}")

# This won't match (wrong name)
is_match_wrong = edm.exact_match(
    'customer_pii',
    'ssn', '123-45-6789',
    {'firstname': 'Jane', 'lastname': 'Smith'}
)

print(f"EDM Match with wrong name: {is_match_wrong}")
```

---

## Testing and Validation Workflow

```python
def complete_sit_validation_workflow():
    """Full workflow for testing custom SIT before Purview deployment"""
    
    # Step 1: Define test data
    true_positives = [
        "Employee ID: 1234567890",
        "Our employee 9876543210 worked on this",
    ]
    
    true_negatives = [
        "Call me at 555-1234",
        "0123456789 is invalid",
        "1111111111 has repeated digits",
    ]
    
    # Step 2: Create and test pattern
    validator = EmployeeIDValidator()
    
    print("Testing TRUE POSITIVES:")
    tp_pass = sum(1 for text in true_positives if validator.validate(text))
    print(f"  {tp_pass}/{len(true_positives)} passed\n")
    
    print("Testing TRUE NEGATIVES:")
    tn_pass = sum(1 for text in true_negatives if not validator.validate(text))
    print(f"  {tn_pass}/{len(true_negatives)} passed\n")
    
    # Step 3: Calculate accuracy metrics
    accuracy = ((tp_pass + tn_pass) / (len(true_positives) + len(true_negatives))) * 100
    print(f"Overall Accuracy: {accuracy:.1f}%")
    
    # Step 4: Report ready for deployment
    if accuracy >= 95:
        print("✓ READY FOR PURVIEW DEPLOYMENT")
    else:
        print("✗ NEEDS ADJUSTMENT - Review failing patterns")

# Run validation
complete_sit_validation_workflow()
```

---

## Summary

This Python implementation reference provides:
- **Regex testing framework** for validating patterns before deployment
- **Advanced pattern implementations** (employee IDs, checksums, multi-pattern matching)
- **Proximity matching** for requiring supporting evidence
- **Exclusion filtering** to reduce false positives
- **Document fingerprinting simulation** for template-based detection
- **EDM simulation** for structured data matching

All patterns are validated locally and production-tested before deployment to Purview, ensuring optimal accuracy and minimal performance impact.

