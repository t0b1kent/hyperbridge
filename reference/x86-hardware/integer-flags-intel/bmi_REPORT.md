# Class 9: observations from this run

## Coverage and C defined-semantics validation

Native CPUID.7.0:EBX=029c6fbf; {'BMI1': 1, 'BMI2': 1, 'ADX': 1}. Measured rows: 286616.
See bmi_CHECKS.txt for unchanged native C defined-semantics checks.
Unavailable features retain the original native SKIP comments and have zero measured rows.

## Measured rules, with support and contradiction counts

The following counts test the original AMD full-flags candidates against this capture.
A contradiction is an observation, not a failed assertion. No Intel rule is assumed.

| Op | Width | Rows | AMD candidate support | Contradictions | Status |
|---|---:|---:|---:|---:|---|
| ANDN | 32 | 968 | 332 | 636 | MEASURED |
| ANDN | 64 | 968 | 332 | 636 | MEASURED |
| BEXTR | 32 | 51832 | 0 | 51832 | MEASURED |
| BEXTR | 64 | 192632 | 0 | 192632 | MEASURED |
| BLSI | 32 | 44 | 34 | 10 | MEASURED |
| BLSI | 64 | 44 | 34 | 10 | MEASURED |
| BLSMSK | 32 | 44 | 26 | 18 | MEASURED |
| BLSMSK | 64 | 44 | 26 | 18 | MEASURED |
| BLSR | 32 | 44 | 18 | 26 | MEASURED |
| BLSR | 64 | 44 | 18 | 26 | MEASURED |
| BZHI | 32 | 968 | 298 | 670 | MEASURED |
| BZHI | 64 | 968 | 298 | 670 | MEASURED |
| MULX | 32 | 968 | 968 | 0 | MEASURED |
| MULX | 64 | 968 | 968 | 0 | MEASURED |
| PDEP | 32 | 968 | 968 | 0 | MEASURED |
| PDEP | 64 | 968 | 968 | 0 | MEASURED |
| PEXT | 32 | 968 | 968 | 0 | MEASURED |
| PEXT | 64 | 968 | 968 | 0 | MEASURED |
| RORX | 32 | 11264 | 11264 | 0 | MEASURED |
| RORX | 64 | 11264 | 11264 | 0 | MEASURED |
| SARX | 32 | 968 | 968 | 0 | MEASURED |
| SARX | 64 | 968 | 968 | 0 | MEASURED |
| SHLX | 32 | 968 | 968 | 0 | MEASURED |
| SHLX | 64 | 968 | 968 | 0 | MEASURED |
| SHRX | 32 | 968 | 968 | 0 | MEASURED |
| SHRX | 64 | 968 | 968 | 0 | MEASURED |
| ADCX | 32 | 968 | 968 | 0 | MEASURED |
| ADCX | 64 | 968 | 968 | 0 | MEASURED |
| ADOX | 32 | 968 | 968 | 0 | MEASURED |
| ADOX | 64 | 968 | 968 | 0 | MEASURED |

Full per-flag set/preserved counters are in bmi-audit.json.
