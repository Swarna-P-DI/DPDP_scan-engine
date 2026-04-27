# Data Governance Report

## Executive Summary
This scan identified unmasked personal data in customer tables, posing a high compliance risk under DPDP. Immediate remediation is required before further data usage.

## Risk Overview
- Critical compliance risk: Apply masking or tokenization to protect sensitive data
- High compliance risk: customer_email contains invalid email formats
- High compliance risk: email contains invalid email formats
- High compliance risk: Increase sample coverage and resolve profiling limitations
- High compliance risk: amount contains negative values
- High compliance risk: city has 66.67% null values
- Moderate compliance risk: customer_email has 20.0% null values
- Moderate compliance risk: dpdp_poor_quality.customer_imports has no primary key in source metadata.
- Moderate compliance risk: dpdp_poor_quality.payment_imports has no primary key in source metadata.
- Moderate compliance risk: email has 33.33% null values
- Moderate compliance risk: phone_number has 33.33% null values
- Moderate compliance risk: Increase sample coverage and resolve profiling limitations
- Moderate compliance risk: amount has 20.0% null values
- Moderate compliance risk: full_name has 33.33% null values
- Moderate compliance risk: status has 20.0% null values

## PII Exposure
| Table | Column | Exposure | Risk |
| --- | --- | --- | --- |
| dpdp_clean.customers | full_name | Unprotected sensitive data | High compliance risk |
| dpdp_clean.customers | email | Unprotected sensitive data | High compliance risk |
| dpdp_masked.communication_preferences | masked_contact | Partially protected sensitive data | Moderate compliance risk |
| dpdp_no_relationships.product_catalog | product_name | Unprotected sensitive data | High compliance risk |
| dpdp_pii_exposure.customer_profiles | full_name | Unprotected sensitive data | High compliance risk |
| dpdp_pii_exposure.customer_profiles | email | Unprotected sensitive data | High compliance risk |
| dpdp_pii_exposure.customer_profiles | phone_number | Unprotected sensitive data | High compliance risk |
| dpdp_pii_exposure.support_tickets | requester_email | Unprotected sensitive data | High compliance risk |
| dpdp_poor_quality.customer_imports | full_name | Unprotected sensitive data | High compliance risk |
| dpdp_poor_quality.customer_imports | email | Unprotected sensitive data | High compliance risk |
| dpdp_poor_quality.customer_imports | phone_number | Unprotected sensitive data | High compliance risk |
| dpdp_poor_quality.payment_imports | customer_email | Unprotected sensitive data | High compliance risk |
| public.customers | customer_name | Unprotected sensitive data | High compliance risk |
| public.customers | email | Unprotected sensitive data | High compliance risk |

## Data Quality
Profiled 13 table(s). Data quality score is 96.68.

## AI Insights
- Apply masking or tokenization to protect sensitive data
- Increase sample coverage and resolve profiling limitations
- 6 high-severity RAID risks were identified, indicating elevated governance exposure.
- Inferred relationships across 22 column pair(s) suggest shared identifiers that should be validated for lineage and access control.

## Recommendations
- Apply masking or tokenization to protect sensitive data
- Fix invalid formats and add validation rules for the affected dataset.
- Deduplicate records and enforce uniqueness rules for the affected dataset.
- Review and remediate: amount contains negative values.
- Define completeness rules and remediate null-heavy fields in 66.67%.
- Define completeness rules and remediate null-heavy fields in 20.0%.
- Define primary key or uniqueness controls for dpdp_poor_quality.customer_imports.
- Define primary key or uniqueness controls for dpdp_poor_quality.payment_imports.
- Define completeness rules and remediate null-heavy fields in 33.33%.
- Increase sample coverage and resolve profiling limitations