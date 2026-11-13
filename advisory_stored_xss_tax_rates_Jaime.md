# Security Advisory — Stored Cross-Site Scripting in Tax Rates Management

## 1. General Information

| Field | Information |
|---|---|
| Product | Modified eCommerce Shopsoftware |
| Analyzed Version | 3.3.0-r16825 |
| Revision | 16825 |
| Component | Administration — Tax Rates |
| Affected File | `admin/tax_rates.php` |
| Vulnerability | Stored Cross-Site Scripting (XSS) |
| CWE | CWE-79 |
| OWASP Top 10 | A03:2021 — Injection |
| CVSS | To be determined |
| Status | PoC previously reproduced |

## 2. Vulnerability Description

A Stored Cross-Site Scripting (Stored XSS) vulnerability was identified in the administrative component responsible for managing tax rates (Tax Rates).

The vulnerability is associated with the `tax_description` field, whose content is received through POST requests, stored in the database, and subsequently rendered in the administrative interface.

The stored value is retrieved through the `parse_multi_language_value()` function and directly concatenated into the HTML content displayed by the `infoBox` component.

The absence of explicit output escaping at the rendering point allows user-controlled HTML content to be interpreted by the browser.

## 3. Affected Endpoint

**Endpoint used during reproduction:**

```http
GET /admin/tax_rates.php?page=1&tID=118
```

**Analyzed Record:**

| Field | Value |
|---|---|
| Tax Rate ID | `118` |
| Table | `tax_rates` |
| Vulnerable Field | `tax_description` |
| Language Used | `DE` |
| Original Value | `DE::` |

## 4. Identified Parameters

| Parameter | Method | Purpose |
|---|---|---|
| `tID` | GET | Identifies the tax rate record |
| `action` | GET | Specifies the administrative operation |
| `tax_description` | POST | Language-specific tax rate description |
| `tax_zone_id` | POST | Identifies the geographical zone |
| `tax_class_id` | POST | Identifies the tax class |
| `tax_rate` | POST | Tax rate value |
| `tax_priority` | POST | Tax rate priority |

## 5. Technical Evidence

### 5.1. Input Handling

File: `admin/tax_rates.php`

**Lines 70–78 — Data reception and preparation:**

```php
$tax_description = xtc_db_prepare_input($_POST['tax_description']);

$tax_description_array = array();
foreach ($tax_description as $key => $value) {
    if (xtc_not_null($value)) {
        $tax_description_array[] = $key . '::' . $value;
    }
}

$tax_description = implode('||', $tax_description_array);
```

The system receives language-specific descriptions and organizes the values into a structure separated by the `||` delimiter.

### 5.2. Database Persistence

**Line 84 — Field assignment to the persistence structure:**

```php
'tax_description' => $tax_description,
```

**Line 88 — Record update:**

```php
xtc_db_perform(
    TABLE_TAX_RATES,
    $sql_data_array,
    'update',
    "tax_rates_id = '" . (int)$tax_rates_id . "'"
);
```

The received content is stored in the tax rates table.

### 5.3. Record Retrieval

**Line 183:**

```php
if ((!isset($_GET['tID']) ||
    $_GET['tID'] == $rates['tax_rates_id'])
    && !isset($trInfo)
    && (substr($action, 0, 3) != 'new')) {

    $trInfo = new objectInfo($rates);
}
```

The `tID` parameter allows the selection of the record to be displayed in the administrative panel.

### 5.4. Vulnerable Rendering Point

**Line 276:**

```php
$contents[] = array(
    'text' => '<br />' . TEXT_INFO_RATE_DESCRIPTION .
    '<br />' . parse_multi_language_value(
        $trInfo->tax_description,
        $_SESSION['language_code']
    )
);
```

The `tax_description` content is retrieved and directly concatenated into the HTML structure.

The resulting content is subsequently passed to the administrative panel renderer:

```php
$box = new box;
echo $box->infoBox($heading, $contents);
```

**Line 284.**

No explicit output escaping is present in the displayed rendering call.

### 5.5. Editing Form

**Line 253:**

```php
$description .= xtc_draw_input_field(
    'tax_description[' . strtoupper($languages[$i]['code']) . ']',
    parse_multi_language_value(
        $trInfo->tax_description,
        $languages[$i]['code'],
        true
    ),
    'style="margin-left:2px; width:200px"'
) . '<br>';
```

The stored value is also retrieved during editing and passed to the `xtc_draw_input_field()` helper.

The effective protection in this context depends on the helper's internal implementation.

## 6. Proof of Concept (PoC)

**Record Used:**

```text
tax_rates_id = 118
```

**Manipulated Field:**

```text
tax_description
```

**Payload Used During Reproduction:**

```html
DE::</textarea><svg onload=alert(document.domain)>
```

The payload uses an SVG element with an `onload` event handler to demonstrate JavaScript execution in the browser.

The PoC was previously executed in the laboratory environment using the identified record.

After reproduction, the original record content was restored:

```text
DE::
```

## 7. Impact

Exploitation of this vulnerability may allow:

- JavaScript execution in the browsers of users who view the affected record.
- Manipulation of content displayed in the administrative interface.
- Execution of actions on behalf of authenticated users, depending on their permissions and the existing security protections.
- Compromise of administrative session integrity in scenarios where security controls permit it.

The vulnerability is persistent because the content is stored in the database and subsequently rendered in the interface.

## 8. Classification

| Reference | Classification |
|---|---|
| CWE-79 | Improper Neutralization of Input During Web Page Generation |
| OWASP Top 10 2021 | A03 — Injection |
| Category | Stored Cross-Site Scripting |
| CVSS | Pending assessment |

## 9. Remediation Recommendations

The following measures are recommended:

1. Implement contextual HTML output escaping before rendering `tax_description`.
2. Review the implementation of `parse_multi_language_value()` to ensure it is not treated as a sanitization mechanism without guarantees.
3. Ensure proper encoding at every administrative interface rendering point.
4. Review the implementation of `xtc_draw_input_field()` to ensure that values inserted into HTML attributes are properly escaped.
5. Apply input validation according to the expected format for each language.
6. Review other multilingual fields that use the same persistence and rendering mechanism.

Input validation does not replace contextual output encoding.

## 10. References

- CWE-79: https://cwe.mitre.org/data/definitions/79.html
- OWASP Cross Site Scripting Prevention Cheat Sheet: https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html

## 11. Investigation Status

- [x] Identification of the administrative endpoint.
- [x] Identification of the parameters.
- [x] Identification of the `tax_description` field.
- [x] Identification of the persistence flow.
- [x] Identification of the rendering point at line 276.
- [x] PoC previously executed.
- [x] Record restored after reproduction, according to the investigation history.
- [ ] Consolidate the internal implementation of `parse_multi_language_value()`.
- [ ] Consolidate the original visual evidence of the PoC.
- [ ] Determine the CVSS score.
- [ ] Finalize advisory disclosure.

---

**Researcher:** Jaime Gama

**Organization:** RedScan Academy Research

**Area:** Offensive Security / Vulnerability Research

**Report Type:** Security Advisory
