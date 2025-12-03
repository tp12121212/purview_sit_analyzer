# Microsoft Purview Custom SIT Regex Word Match Examples

This template shows how to create a custom Sensitive Information Type (SIT) that mimics the **Purview portal Word Match behavior** for multiple patterns.

---

## 1. Regex Template Structure

```regex
(?:^|[\s,;:\(\)\[\]"'])(PATTERN)(?:$|[\s,;:\(\)\[\]"']|\.\s|\.$)
```

* `^` → start of string  
* `$` → end of string  
* `[\s,;:\(\)\[\]"']` → common punctuation and whitespace treated as word boundaries  
* `\.\s` or `\.$` → handles sentence-ending periods  
* `PATTERN` → replace with your sensitive term or regex  

---

## 2. Multi-Pattern Example

Suppose you want to detect these terms as separate SIT patterns:  
`SSN`, `Credit Card`, `Bank Account`.

```regex
(?:^|[\s,;:\(\)\[\]"'])(SSN|Credit Card|Bank Account)(?:$|[\s,;:\(\)\[\]"']|\.\s|\.$)
```

* Matches any of the three terms as **whole words**.  
* Respects start/end of string, punctuation, and sentence-ending periods.  
* Works exactly like the portal Word Match.

---

## 3. Adding Custom Regex Patterns

You can also insert a **custom regex** for complex patterns.  
Example: detect a 16-digit credit card number:

```regex
(?:^|[\s,;:\(\)\[\]"'])(\d{4}-?\d{4}-?\d{4}-?\d{4})(?:$|[\s,;:\(\)\[\]"']|\.\s|\.$)
```

* Matches a credit card number with or without dashes.  
* Still respects Purview Word Match boundaries.

---

## 4. Full Template for Multiple Patterns

```regex
(?:^|[\s,;:\(\)\[\]"'])(SSN|\d{4}-?\d{4}-?\d{4}-?\d{4}|Bank Account|CustomPatternHere)(?:$|[\s,;:\(\)\[\]"']|\.\s|\.$)
```

* Replace `CustomPatternHere` with any additional regex you need.  
* Can include **unlimited patterns**, separated by `|`.  
* Ensures **exact portal Word Match behavior** for all terms.

---

## 5. Implementation Notes

* Use this regex in **Purview Custom SIT** under:  
  `Information Protection → Sensitive Information Types → Create new → Patterns`
* Test detection with sample content to confirm accuracy.
* This method provides **full parity with Word Match behavior** inside Purview.

---
