/*
 * support.cj
 *
 * Package anchor for ohos_app_cangjie_eudi_cjwallet_kit.wallet.support.
 *
 * S-003: every parent directory must contain at least one .cj file with the
 * corresponding package declaration, or child packages are invisible to the compiler.
 *
 * Owned by: wk_support (declared in target_architecture.json Layer 1 shared_files).
 *
 * This file intentionally has no public declarations; all public API lives in:
 *   secure_area_signer.cj    - SecureAreaSigner (JWT signing via SecureArea)
 *   sdjwt_utils.cj           - SdJwtUtils (SD-JWT parsing helpers)
 *   trusted_chain_validator.cj - TrustedChainValidator (x509 chain validation)
 *   document_status_service.cj - DocumentStatusService (statium status fetch)
 *   transaction_log.cj       - TransactionLog + TransactionLogUtils + log data types
 *   file_logging.cj          - FileLogging (HiLog-backed logging)
 *   dcql_queryable.cj        - DcqlQueryable interface + DefaultDcqlQueryable
 *   wrp_registration_core.cj - shared WRPRC token validation + binding
 */
package ohos_app_cangjie_eudi_cjwallet_kit.wallet.support
