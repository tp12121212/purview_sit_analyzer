# Microsoft Purview Custom SIT and the behavior of selecting string and word match options inn the portal.

## 1. Word vs String match behavior when creating a custom SIT in purview portal

- If you select string match and enter a regex that does look for word boundries, it will behave like word match
   - exmaple when selecting string match in purview portal and using the following regex will result in word match 
   
       `(?:^|[\s,;\:\(\)\[\]"'])(hello)(?:$|[\s,\;\:\(\)\[\]"']|\.\s|\.$)`
    - i.e. will only match on hello, not hellooooo


---

## 2. Differences between  using `\b` and Microsofts approad to word boundries 
  
  i.e. `(?:^|[\s,;\:\(\)\[\]"'])(Mention your regex here)(?:$|[\s,\;\:\(\)\[\]"']|\.\s|\.$)`

| Feature | Using `\b` | Using Purview Portal Regex |
|---------|-----------|---------------------------|
| Matches start/end of string | Yes | Yes |
| Matches punctuation like `.` | No, only non-word characters | Yes, handles `. ` or `.$` explicitly |
| Customizable boundaries | No | Yes, can adjust included punctuation |
| Alignment with Purview Word Match | Approximate | Exact |
| Risk of false positives/negatives | Higher for some punctuation | Lower, matches portal behavior |

- The portal regex ensures the term is matched **exactly like the portal Word Match checkbox**, including sentence-ending periods and common punctuation.

---


# Differences Between `\b` and Microsoft Purview Word Boundary Approach

## 1. Using `\b` (Standard Regex Word Boundary)

Example:

```regex
\bPATTERN\b
```

- Matches positions where a **word character** (`[A-Za-z0-9_]`) is next to a **non-word character** (`[^A-Za-z0-9_]`) or string start/end.
- Simple and concise.
- ✅ Ensures `PATTERN` is not part of a larger word.
- ❌ Only recognizes standard “word characters.” Punctuation like `.`, `/`, `-` may not be treated as boundaries.
- ❌ Does not handle special cases like a period at the end of a sentence (`.` followed by space or end of string).

---

## 2. Microsoft Purview Portal Word Match Regex

Example:

```regex
 (?:^|[\s,;\:\(\)\[\]"'])(Mention your regex here)(?:$|[\s,\;\:\(\)\[\]"']|\.\s|\.$)
```

- **Left-hand boundary**: `(?:^|[\s,;:\(\)\[\]"'])`
  - Matches **start of string** or common whitespace/punctuation before the term.
- **Right-hand boundary**: `(?:$|[\s,;:\(\)\[\]"']|\.\s|\.$)`
  - Matches **end of string**, common punctuation, or a period at the end of a sentence.
- ✅ Accurately replicates the **portal Word Match behavior**.
- ✅ Handles sentence-ending periods and common punctuation.
- ✅ Customizable by adding more characters to the boundary sets.
- ❌ Slightly more verbose than `\b`.

---

## 3. Key Differences

| Feature | `\b` | Purview Portal Regex |
|---------|------|--------------------|
| Matches start/end of string | Yes | Yes |
| Matches punctuation like `.` or `-` | No, only non-word characters | Yes, explicitly handled |
| Customizable boundaries | No | Yes, can add/remove punctuation as needed |
| Alignment with Purview Word Match | Approximate | Exact |
| Ease of use | Simple | Slightly verbose |
| Risk of false positives/negatives | Higher for some punctuation | Lower, matches portal behavior exactly |

---

## 4. Summary

- `\b` is suitable for general regex word boundaries but may miss or misinterpret certain punctuation.  
- Purview’s approach using  `(?:^|[\s,;\:\(\)\[\]"'])(Mention your regex here)(?:$|[\s,\;\:\(\)\[\]"']|\.\s|\.$)` **ensures precise word matching** consistent with the portal Word Match checkbox, including sentence-ending punctuation.
