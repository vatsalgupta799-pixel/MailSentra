# MAILSENTRA — STANDALONE ATTACHMENT PATCH SECURITY VERIFICATION REPORT

**Audit Date:** 2026-11-28  
**Auditor:** Independent Senior Application Security Reviewer  
**Repository Working Directory:** `C:\Users\vatsa\OneDrive\Desktop\MailSantra`  
**Review Target:** Standalone Attachment Evaluation Correction (`evaluator.py`, `adapters.py`, `test_standalone_attachment_evaluation.py`)  
**Audit Mode:** Strictly READ-ONLY  
**Report Identifier:** `MAILSENTRA-SEC-REV-2026-11-28-ATTACH-01`

---

## 1. Source Files Inspected

The following source, adapter, module, and test files were inspected directly on disk:

1. `backend/app/datasets/evaluator.py` ([lines 170–265](file:///C:/Users/vatsa/OneDrive/Desktop/MailSantra/backend/app/datasets/evaluator.py#L170-L265))
   - Implementation of `_extract_attachment_payload()`
   - Payload memory bounding logic
   - Construction of `AttachmentMetadata` with `raw_payload`
   - Test partition fallback (`eval_set = test_set if test_set else processed`)
2. `backend/app/datasets/adapters.py` ([lines 110–140](file:///C:/Users/vatsa/OneDrive/Desktop/MailSantra/backend/app/datasets/adapters.py#L110-L140))
   - `AttachmentDatasetAdapter.normalize_record()` payload preservation
3. `backend/app/modules/attachment_analysis/analyzer.py` ([lines 104–253](file:///C:/Users/vatsa/OneDrive/Desktop/MailSantra/backend/app/modules/attachment_analysis/analyzer.py#L104-L253))
   - `AttachmentAnalyzer.analyze_single_attachment()`
   - Magic bytes, MIME mismatch, RTLO, double extensions, and ZIP inspection
4. `backend/app/modules/parser/attachment_parser.py` ([lines 100–169](file:///C:/Users/vatsa/OneDrive/Desktop/MailSantra/backend/app/modules/parser/attachment_parser.py#L100-L169))
   - Email-level attachment extraction and `raw_payload` population
5. `backend/app/modules/contracts.py`
   - `AttachmentMetadata` Pydantic model (`raw_payload: Optional[bytes] = Field(default=None, repr=False, exclude=True)`)
6. `backend/tests/test_standalone_attachment_evaluation.py`
   - 7 newly added regression tests exercising standalone attachment evaluation

---

## 2. Oversized Payload Analysis

### 2.1 Declared Size vs. Actual Payload Size
- **Original Declared Size Preservation:**  
  In `evaluator.py` line 222, `size_bytes = rec.get("size_bytes")`. If the record provides `size_bytes`, this value is preserved and assigned to `att_meta.size_bytes`.
- **Inconsistent Size Discrepancy Vulnerability:**  
  If a record provides an adversarial or inconsistent declared size (e.g. `size_bytes = 500`), but the actual `payload_bytes` is 30 MB (exceeding `max_attachment_size_bytes = 25 MB`):
  1. `evaluator.py` lines 232–235 truncates `bounded_payload = payload_bytes[:25MB]`.
  2. `att_meta` is constructed with `size_bytes = 500` and `raw_payload = bounded_payload[:25MB]`.
  3. When `AttachmentAnalyzer.analyze_single_attachment(att_meta)` runs line 131:
     `if att.size_bytes > cfg.max_attachment_size_bytes:`
     Because `att.size_bytes` is `500`, the oversized check evaluates to `False`. The analyzer does **not** flag `SKIPPED_OVERSIZED`.
  4. Instead, the analyzer treats the truncated 25 MB slice as if it were a complete 500-byte file, analyzing the truncated buffer.
- **Truncation Point & Evidence Completeness:**  
  Truncation occurs in `evaluator.py` *before* `AttachmentMetadata` is constructed. Truncated data can be partially parsed (e.g., zip central directories or file footers may be sliced off), potentially causing parse errors rather than clean oversized rejections.
- **Analyzer Behavior When `size_bytes` is Omitted:**  
  When `size_bytes` is omitted from the record, line 225 derives `size_bytes = len(payload_bytes) = 30 MB`. In this scenario, `att.size_bytes` correctly exceeds 25 MB, and the analyzer reliably returns `finding.analysis_status = "SKIPPED_OVERSIZED"` and `finding.severity = "SUSPICIOUS"`.

---

## 3. Base64 and Memory Safety

### 3.1 Pre-Decode Size Bounding
- In `_extract_attachment_payload()`, when `raw_b64` is provided:
  ```python
  raw_b64 = rec.get("raw_base64") or rec.get("payload_base64")
  if raw_b64 and isinstance(raw_b64, str):
      decoded = base64.b64decode(raw_b64.strip(), validate=True)
  ```
  The string length of `raw_b64` is **not bounded prior to decoding**. A multi-hundred-megabyte string in a record will cause Python's `binascii` layer to allocate a corresponding buffer before any `max_limit` check is reached.

### 3.2 String Handling and Base64 Validation
- When `raw_bytes` contains a string, `base64.b64decode(stripped, validate=True)` is called.
- In Python, `b64decode(..., validate=True)` accepts any string composed of characters in `[A-Za-z0-9+/=]` whose length is a multiple of 4 (e.g., `"test"` decodes to `b'\xb5\xeb-'`). If an English word happens to match the base64 character set, it will be decoded into arbitrary binary bytes rather than triggering a validation rejection.
- However, if the string contains non-base64 characters, `validate=True` raises `binascii.Error`, which is safely caught and converted to `(None, "String provided for raw_bytes failed base64 validation")` without crashing.

### 3.3 Type Rejection & Precedence
- Non-binary and non-string types (such as `int`, `list`, `dict`) are deterministically rejected with `(None, f"Unsupported raw_bytes type: {type(raw_val).__name__}")`.
- Precedence is strictly deterministic:
  1. `rec["raw_bytes"]`
  2. `rec["raw_payload"]`
  3. `rec["raw_base64"]` / `rec["payload_base64"]`

### 3.4 Adapter Normalization Buffer Retention
- In `AttachmentDatasetAdapter.normalize_record()`, `raw_bytes` and `raw_base64` are copied directly into the normalized dictionary without bounding. If an oversized payload is ingested, it is preserved in memory across the pipeline.

---

## 4. Checksum and File Integrity

### 4.1 Checksum Calculation
- In `evaluator.py`:
  ```python
  sha256_hash = rec.get("file_sha256") or rec.get("sha256")
  if not sha256_hash and payload_bytes:
      sha256_hash = hashlib.sha256(payload_bytes).hexdigest()
  ```
  `sha256_hash` is computed from `payload_bytes` prior to truncation.
- In `AttachmentAnalyzer`:
  ```python
  actual_sha256 = hashlib.sha256(payload_bytes).hexdigest() if payload_bytes else att.sha256_hash
  ```
  In `AttachmentAnalyzer`, `payload_bytes` is `att.raw_payload` (which is the truncated buffer if oversized). Consequently, `finding.sha256_hash` reflects the truncated 25 MB prefix rather than the complete original file.
- **Hash Verification:**  
  If `rec` provides a `file_sha256`, `evaluator.py` passes it into `att_meta.sha256_hash`. `AttachmentAnalyzer` verifies/recomputes `actual_sha256` from `payload_bytes` whenever `payload_bytes` is present, avoiding blind trust in declared hashes.

---

## 5. Partition Fallback Analysis

### 5.1 Fallback Mechanism
In lines 210–211 of `evaluator.py`:
```python
train_set, test_set = self.pipeline.split_records(processed)
eval_set = test_set if test_set else processed
```

### 5.2 Security & Benchmark Implications
1. **Lack of Small-Dataset Scoping:**  
   The fallback is unconditional. It is not restricted to explicit unit-test environments or datasets with fewer than $N$ items.
2. **Accidental Training Data Leakage:**  
   In a production evaluation run, if `test_set` is empty (e.g. all record cluster hashes fall below the 70% threshold in a small campaign batch), records allocated to `train_set` are evaluated as test data.
3. **Metric Skew:**  
   If training records are evaluated as test data, the reported precision, recall, and F1 scores represent training-set accuracy rather than genuine out-of-sample generalization.
4. **Concealment of Split Failures:**  
   If the pipeline splitter fails, filters out records, or miscalculates cluster splits, the fallback silently substitutes `processed`, masking the underlying partition failure without logging a warning or telemetry indicator.

---

## 6. Regression Test Quality Review

All 7 new tests in `backend/tests/test_standalone_attachment_evaluation.py` were reviewed:

| Test Name | Behavior Asserted | Defect Caught Effectively? | Edge Case Limitations |
| :--- | :--- | :---: | :--- |
| `test_real_binary_attachment_bytes_reach_analyzer` | Verifies `raw_bytes` MZ header reaches analyzer and triggers `MALICIOUS`. | **Yes** | Uses minimal 16-byte DOS header; does not test full PE format. |
| `test_valid_zip_attachment_inspected_using_actual_bytes` | Generates real in-memory ZIP with `hidden_installer.exe` and verifies inner detection. | **Yes** | Excellent end-to-end archive analysis test. |
| `test_metadata_only_records_continue_to_work` | Evaluates records with no `raw_bytes`. Verifies double extension (.pdf.exe) and clean PDF. | **Yes** | Tests metadata-only fallback reliably. |
| `test_invalid_binary_representations_handled_safely` | Passes invalid base64 string and integer type. Verifies `payload_warning` is populated. | **Yes** | Does not test ASCII words that happen to be valid base64 (e.g. `"test"`). |
| `test_oversized_attachments_respect_existing_limits` | Tests declared 30 MB size against 25 MB limit. Verifies `SKIPPED_OVERSIZED`. | **Partial** | Only tests declared `size_bytes = 30MB` with small payload `b"A" * 1024`. Does not test 30 MB of actual payload bytes without declared size, nor declared 500 bytes with 30 MB payload. |
| `test_binary_content_cannot_bypass_magic_validation` | Disguised executable (.pdf with `application/pdf`) triggers `magic_byte_mismatch`. | **Yes** | Strong validation of magic-byte override. |
| `test_existing_email_level_attachment_evaluation_unchanged` | Verifies `evaluate_email_dataset` parses attachment and updates telemetry. | **Yes** | Confirms email-level evaluation parity. |

---

## 7. Missing Security Test Cases

1. **Declared Size Smaller Than Actual Binary:**  
   Missing a test where `rec["size_bytes"] = 100`, but `rec["raw_bytes"] = b"..."` (30 MB).
2. **Actual Oversized Payload (>25 MB) Without Declared Size:**  
   Missing a test where `rec["size_bytes"]` is `None` and `rec["raw_bytes"]` exceeds 25 MB.
3. **Oversized Base64 String Denial-of-Service:**  
   Missing a test verifying pre-decode string length bounding on `raw_base64`.
4. **Base64 String Collision with Plain Text:**  
   Missing a test where a plain text description that happens to be base64-valid is passed.
5. **Partition Fallback Telemetry Flag:**  
   Missing a test verifying that when `test_set` is empty and fallback activates, an explicit warning or telemetry flag is emitted.

---

## 8. Findings and Severity Table

| ID | Title | Severity | Impact |
| :--- | :--- | :---: | :--- |
| **FINDING-ATTACH-01** | Declared Size Overrides Actual Payload Length in Oversized Checks | **MEDIUM** | If `rec["size_bytes"]` is declared smaller than 25 MB but `payload_bytes` is 30 MB, `att_meta.size_bytes` bypasses `SKIPPED_OVERSIZED`. |
| **FINDING-ATTACH-02** | Unbounded Base64 Input Size Prior to Decoding | **MEDIUM** | Large base64 strings in dataset records are decoded in memory before checking configured attachment limits. |
| **FINDING-ATTACH-03** | Unconditional Partition Fallback Introduces Train/Test Leakage | **MEDIUM** | When `test_set` is empty, `eval_set` falls back to `processed` (evaluating training samples) without a warning or telemetry flag. |
| **FINDING-ATTACH-04** | Truncated Payload SHA-256 Divergence | **LOW** | When payloads >25 MB are truncated, `finding.sha256_hash` represents the 25 MB slice rather than the full file. |

---

## 9. Test Execution Record

The focused attachment test suites were executed independently during this review:

1. **Standalone Attachment Evaluation Suite:**
   ```powershell
   $env:PYTHONPATH=".;backend"; pytest backend/tests/test_standalone_attachment_evaluation.py -v
   ```
   - **Exit Code:** `0`
   - **Result:** `7 passed in 0.43s`
2. **Attachment Forensic Analyzer Suite:**
   ```powershell
   $env:PYTHONPATH=".;backend"; pytest backend/tests/test_attachment_analyzer.py -q
   ```
   - **Exit Code:** `0`
   - **Result:** `23 passed in 0.55s`

---

## 10. Final Verdict

### **`APPROVED WITH CONDITIONS`**

### Required Remediation Conditions (For Future Polish):
1. **Condition 1 (Size Reconciliation):** Set `size_bytes = max(rec.get("size_bytes") or 0, len(payload_bytes))` when `payload_bytes` is present, ensuring oversized payloads cannot evade `SKIPPED_OVERSIZED` via spoofed small declared sizes.
2. **Condition 2 (Base64 Guard):** Pre-check `len(raw_b64) <= (max_limit * 4 // 3) + 1024` prior to calling `base64.b64decode()`.
3. **Condition 3 (Fallback Transparency):** Add an explicit `fallback_to_processed: bool = False` flag or emit `"partition_fallback": True` in the evaluation results dictionary when the fallback occurs, preserving metric integrity.
