# Data Governance Report

## Executive Summary
This scan identified unmasked personal data in customer tables, posing a high compliance risk under DPDP. Immediate remediation is required before further data usage.

## Risk Overview
- High compliance risk: Apply masking or tokenization to protect sensitive data

## PII Exposure
| Table | Column | Exposure | Risk |
| --- | --- | --- | --- |
| public.customers | customer_name | Unprotected sensitive data | High compliance risk |
| public.customers | email | Unprotected sensitive data | High compliance risk |

## Data Quality
Profiled 2 table(s). Data quality score is 100.0.

## AI Insights
- Apply masking or tokenization to protect sensitive data
- Increase sample coverage and resolve profiling limitations
- Inferred relationships across 1 column pair(s) suggest shared identifiers that should be validated for lineage and access control.

## Recommendations
- Increase sample coverage and resolve profiling limitations
- Apply masking or tokenization to protect sensitive data