/* Automatically generated from /root/fuzzing-openiked-portable/iked/ikev2.h, do not edit */
/*	$OpenBSD: ikev2.h,v 1.35 2023/06/28 14:10:24 tobhe Exp $	*/

/*
 * Copyright (c) 2019 Tobias Heider <tobias.heider@stusta.de>
 * Copyright (c) 2010-2013 Reyk Floeter <reyk@openbsd.org>
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

#include <sys/types.h>

#include "types.h"
#include "ikev2.h"

struct iked_constmap ikev2_state_map[] = {
	{ IKEV2_STATE_INIT, "INIT", "new IKE SA" },
	{ IKEV2_STATE_COOKIE, "COOKIE", "cookie requested" },
	{ IKEV2_STATE_SA_INIT, "SA_INIT", "init IKE SA" },
	{ IKEV2_STATE_EAP, "EAP", "EAP requested" },
	{ IKEV2_STATE_EAP_SUCCESS, "EAP_SUCCESS", "EAP succeeded" },
	{ IKEV2_STATE_AUTH_REQUEST, "AUTH_REQUEST", "auth received" },
	{ IKEV2_STATE_AUTH_SUCCESS, "AUTH_SUCCESS", "authenticated" },
	{ IKEV2_STATE_VALID, "VALID", "authenticated AND validated certs" },
	{ IKEV2_STATE_EAP_VALID, "EAP_VALID", "EAP validated" },
	{ IKEV2_STATE_ESTABLISHED, "ESTABLISHED", "active IKE SA" },
	{ IKEV2_STATE_CLOSING, "CLOSING", "expect delete for this SA" },
	{ IKEV2_STATE_CLOSED, "CLOSED", "delete this SA" },
	{ 0 }
};
struct iked_constmap ikev2_exchange_map[] = {
	{ IKEV2_EXCHANGE_IKE_SA_INIT, "IKE_SA_INIT", "Initial Exchange" },
	{ IKEV2_EXCHANGE_IKE_AUTH, "IKE_AUTH", "Authentication" },
	{ IKEV2_EXCHANGE_CREATE_CHILD_SA, "CREATE_CHILD_SA", "Create Child SA" },
	{ IKEV2_EXCHANGE_INFORMATIONAL, "INFORMATIONAL", "Informational" },
	{ IKEV2_EXCHANGE_IKE_SESSION_RESUME, "IKE_SESSION_RESUME", "RFC5723" },
	{ 0 }
};
struct iked_constmap ikev2_flag_map[] = {
	{ IKEV2_FLAG_INITIATOR, "INITIATOR", "Sent by the initiator" },
	{ IKEV2_FLAG_OLDVERSION, "OLDVERSION", "Supports a higher IKE version" },
	{ IKEV2_FLAG_RESPONSE, "RESPONSE", "Message is a response" },
	{ 0 }
};
struct iked_constmap ikev2_payload_map[] = {
	{ IKEV2_PAYLOAD_NONE, "NONE", "No payload" },
	{ IKEV2_PAYLOAD_SA, "SA", "Security Association" },
	{ IKEV2_PAYLOAD_KE, "KE", "Key Exchange" },
	{ IKEV2_PAYLOAD_IDi, "IDi", "Identification - Initiator" },
	{ IKEV2_PAYLOAD_IDr, "IDr", "Identification - Responder" },
	{ IKEV2_PAYLOAD_CERT, "CERT", "Certificate" },
	{ IKEV2_PAYLOAD_CERTREQ, "CERTREQ", "Certificate Request" },
	{ IKEV2_PAYLOAD_AUTH, "AUTH", "Authentication" },
	{ IKEV2_PAYLOAD_NONCE, "NONCE", "Nonce" },
	{ IKEV2_PAYLOAD_NOTIFY, "NOTIFY", "Notify" },
	{ IKEV2_PAYLOAD_DELETE, "DELETE", "Delete" },
	{ IKEV2_PAYLOAD_VENDOR, "VENDOR", "Vendor ID" },
	{ IKEV2_PAYLOAD_TSi, "TSi", "Traffic Selector - Initiator" },
	{ IKEV2_PAYLOAD_TSr, "TSr", "Traffic Selector - Responder" },
	{ IKEV2_PAYLOAD_SK, "SK", "Encrypted" },
	{ IKEV2_PAYLOAD_CP, "CP", "Configuration Payload" },
	{ IKEV2_PAYLOAD_EAP, "EAP", "Extensible Authentication" },
	{ IKEV2_PAYLOAD_GSPM, "GSPM", "RFC6467 Generic Secure Password" },
	{ IKEV2_PAYLOAD_SKF, "SKF", "RFC7383 Encrypted Fragment Payload" },
	{ 0 }
};
struct iked_constmap ikev2_saproto_map[] = {
	{ IKEV2_SAPROTO_NONE, "NONE", "None" },
	{ IKEV2_SAPROTO_IKE, "IKE", "IKEv2" },
	{ IKEV2_SAPROTO_AH, "AH", "AH" },
	{ IKEV2_SAPROTO_ESP, "ESP", "ESP" },
	{ IKEV2_SAPROTO_FC_ESP_HEADER, "FC_ESP_HEADER", "RFC4595" },
	{ IKEV2_SAPROTO_FC_CT_AUTH, "FC_CT_AUTH", "RFC4595" },
	{ IKEV2_SAPROTO_IPCOMP, "IPCOMP", "private, should be 4" },
	{ 0 }
};
struct iked_constmap ikev2_xformtype_map[] = {
	{ IKEV2_XFORMTYPE_ENCR, "ENCR", "Encryption" },
	{ IKEV2_XFORMTYPE_PRF, "PRF", "Pseudo-Random Function" },
	{ IKEV2_XFORMTYPE_INTEGR, "INTEGR", "Integrity Algorithm" },
	{ IKEV2_XFORMTYPE_DH, "DH", "Diffie-Hellman Group" },
	{ IKEV2_XFORMTYPE_ESN, "ESN", "Extended Sequence Numbers" },
#define IKEV2_XFORMTYPE_MAX		6
	{ 0 }
};
struct iked_constmap ikev2_xformencr_map[] = {
	{ IKEV2_XFORMENCR_NONE, "NONE", "None" },
	{ IKEV2_XFORMENCR_DES_IV64, "DES_IV64", "RFC1827" },
	{ IKEV2_XFORMENCR_DES, "DES", "RFC2405" },
	{ IKEV2_XFORMENCR_3DES, "3DES", "RFC2451" },
	{ IKEV2_XFORMENCR_RC5, "RC5", "RFC2451" },
	{ IKEV2_XFORMENCR_IDEA, "IDEA", "RFC2451" },
	{ IKEV2_XFORMENCR_CAST, "CAST", "RFC2451" },
	{ IKEV2_XFORMENCR_BLOWFISH, "BLOWFISH", "RFC2451" },
	{ IKEV2_XFORMENCR_3IDEA, "3IDEA", "RFC2451" },
	{ IKEV2_XFORMENCR_DES_IV32, "DES_IV32", "DESIV32" },
	{ IKEV2_XFORMENCR_RC4, "RC4", "RFC2451" },
	{ IKEV2_XFORMENCR_NULL, "NULL", "RFC2410" },
	{ IKEV2_XFORMENCR_AES_CBC, "AES_CBC", "RFC3602" },
	{ IKEV2_XFORMENCR_AES_CTR, "AES_CTR", "RFC3664" },
	{ IKEV2_XFORMENCR_AES_CCM_8, "AES_CCM_8", "RFC5282" },
	{ IKEV2_XFORMENCR_AES_CCM_12, "AES_CCM_12", "RFC5282" },
	{ IKEV2_XFORMENCR_AES_CCM_16, "AES_CCM_16", "RFC5282" },
	{ IKEV2_XFORMENCR_AES_GCM_8, "AES_GCM_8", "RFC5282" },
	{ IKEV2_XFORMENCR_AES_GCM_12, "AES_GCM_12", "RFC5282" },
	{ IKEV2_XFORMENCR_AES_GCM_16, "AES_GCM_16", "RFC5282" },
	{ IKEV2_XFORMENCR_NULL_AES_GMAC, "NULL_AES_GMAC", "RFC4543" },
	{ IKEV2_XFORMENCR_XTS_AES, "XTS_AES", "IEEE P1619" },
	{ IKEV2_XFORMENCR_CAMELLIA_CBC, "CAMELLIA_CBC", "RFC5529" },
	{ IKEV2_XFORMENCR_CAMELLIA_CTR, "CAMELLIA_CTR", "RFC5529" },
	{ IKEV2_XFORMENCR_CAMELLIA_CCM_8, "CAMELLIA_CCM_8", "RFC5529" },
	{ IKEV2_XFORMENCR_CAMELLIA_CCM_12, "CAMELLIA_CCM_12", "RFC5529" },
	{ IKEV2_XFORMENCR_CAMELLIA_CCM_16, "CAMELLIA_CCM_16", "RFC5529" },
	{ IKEV2_XFORMENCR_CHACHA20_POLY1305, "CHACHA20_POLY1305", "RFC7634" },
	{ 0 }
};
struct iked_constmap ikev2_ipcomp_map[] = {
	{ IKEV2_IPCOMP_OUI, "OUI", "UNSPECIFIED" },
	{ IKEV2_IPCOMP_DEFLATE, "DEFLATE", "RFC2394" },
	{ IKEV2_IPCOMP_LZS, "LZS", "RFC2395" },
	{ IKEV2_IPCOMP_LZJH, "LZJH", "RFC3051" },
	{ 0 }
};
struct iked_constmap ikev2_xformprf_map[] = {
	{ IKEV2_XFORMPRF_HMAC_MD5, "HMAC_MD5", "RFC2104" },
	{ IKEV2_XFORMPRF_HMAC_SHA1, "HMAC_SHA1", "RFC2104" },
	{ IKEV2_XFORMPRF_HMAC_TIGER, "HMAC_TIGER", "RFC2104" },
	{ IKEV2_XFORMPRF_AES128_XCBC, "AES128_XCBC", "RFC3664" },
	{ IKEV2_XFORMPRF_HMAC_SHA2_256, "HMAC_SHA2_256", "RFC4868" },
	{ IKEV2_XFORMPRF_HMAC_SHA2_384, "HMAC_SHA2_384", "RFC4868" },
	{ IKEV2_XFORMPRF_HMAC_SHA2_512, "HMAC_SHA2_512", "RFC4868" },
	{ IKEV2_XFORMPRF_AES128_CMAC, "AES128_CMAC", "RFC4615" },
	{ 0 }
};
struct iked_constmap ikev2_xformauth_map[] = {
	{ IKEV2_XFORMAUTH_NONE, "NONE", "No Authentication" },
	{ IKEV2_XFORMAUTH_HMAC_MD5_96, "HMAC_MD5_96", "RFC2403" },
	{ IKEV2_XFORMAUTH_HMAC_SHA1_96, "HMAC_SHA1_96", "RFC2404" },
	{ IKEV2_XFORMAUTH_DES_MAC, "DES_MAC", "DES-MAC" },
	{ IKEV2_XFORMAUTH_KPDK_MD5, "KPDK_MD5", "RFC1826" },
	{ IKEV2_XFORMAUTH_AES_XCBC_96, "AES_XCBC_96", "RFC3566" },
	{ IKEV2_XFORMAUTH_HMAC_MD5_128, "HMAC_MD5_128", "RFC4595" },
	{ IKEV2_XFORMAUTH_HMAC_SHA1_160, "HMAC_SHA1_160", "RFC4595" },
	{ IKEV2_XFORMAUTH_AES_CMAC_96, "AES_CMAC_96", "RFC4494" },
	{ IKEV2_XFORMAUTH_AES_128_GMAC, "AES_128_GMAC", "RFC4543" },
	{ IKEV2_XFORMAUTH_AES_192_GMAC, "AES_192_GMAC", "RFC4543" },
	{ IKEV2_XFORMAUTH_AES_256_GMAC, "AES_256_GMAC", "RFC4543" },
	{ IKEV2_XFORMAUTH_HMAC_SHA2_256_128, "HMAC_SHA2_256_128", "RFC4868" },
	{ IKEV2_XFORMAUTH_HMAC_SHA2_384_192, "HMAC_SHA2_384_192", "RFC4868" },
	{ IKEV2_XFORMAUTH_HMAC_SHA2_512_256, "HMAC_SHA2_512_256", "RFC4868" },
	{ IKEV2_XFORMAUTH_AES_GCM_8, "AES_GCM_8", "internal" },
	{ IKEV2_XFORMAUTH_AES_GCM_12, "AES_GCM_12", "internal" },
	{ IKEV2_XFORMAUTH_AES_GCM_16, "AES_GCM_16", "internal" },
	{ 0 }
};
struct iked_constmap ikev2_xformdh_map[] = {
	{ IKEV2_XFORMDH_NONE, "NONE", "No DH" },
	{ IKEV2_XFORMDH_MODP_768, "MODP_768", "DH Group 1" },
	{ IKEV2_XFORMDH_MODP_1024, "MODP_1024", "DH Group 2" },
	{ IKEV2_XFORMDH_MODP_1536, "MODP_1536", "DH Group 5" },
	{ IKEV2_XFORMDH_MODP_2048, "MODP_2048", "DH Group 14" },
	{ IKEV2_XFORMDH_MODP_3072, "MODP_3072", "DH Group 15" },
	{ IKEV2_XFORMDH_MODP_4096, "MODP_4096", "DH Group 16" },
	{ IKEV2_XFORMDH_MODP_6144, "MODP_6144", "DH Group 17" },
	{ IKEV2_XFORMDH_MODP_8192, "MODP_8192", "DH Group 18" },
	{ IKEV2_XFORMDH_ECP_256, "ECP_256", "RFC5114" },
	{ IKEV2_XFORMDH_ECP_384, "ECP_384", "RFC5114" },
	{ IKEV2_XFORMDH_ECP_521, "ECP_521", "RFC5114" },
	{ IKEV2_XFORMDH_ECP_192, "ECP_192", "RFC5114" },
	{ IKEV2_XFORMDH_ECP_224, "ECP_224", "RFC5114" },
	{ IKEV2_XFORMDH_BRAINPOOL_P224R1, "BRAINPOOL_P224R1", "RFC6954" },
	{ IKEV2_XFORMDH_BRAINPOOL_P256R1, "BRAINPOOL_P256R1", "RFC6954" },
	{ IKEV2_XFORMDH_BRAINPOOL_P384R1, "BRAINPOOL_P384R1", "RFC6954" },
	{ IKEV2_XFORMDH_BRAINPOOL_P512R1, "BRAINPOOL_P512R1", "RFC6954" },
	{ IKEV2_XFORMDH_CURVE25519, "CURVE25519", "RFC8031" },
	{ IKEV2_XFORMDH_X_SNTRUP761X25519, "X_SNTRUP761X25519", "private" },
	{ 0 }
};
struct iked_constmap ikev2_xformesn_map[] = {
	{ IKEV2_XFORMESN_NONE, "NONE", "No ESN" },
	{ IKEV2_XFORMESN_ESN, "ESN", "ESN" },
	{ 0 }
};
struct iked_constmap ikev2_attrtype_map[] = {
	{ IKEV2_ATTRTYPE_KEY_LENGTH, "KEY_LENGTH", "Key length" },
	{ 0 }
};
struct iked_constmap ikev2_n_map[] = {
	{ IKEV2_N_UNSUPPORTED_CRITICAL_PAYLOAD, "UNSUPPORTED_CRITICAL_PAYLOAD", "RFC7296" },
	{ IKEV2_N_INVALID_IKE_SPI, "INVALID_IKE_SPI", "RFC7296" },
	{ IKEV2_N_INVALID_MAJOR_VERSION, "INVALID_MAJOR_VERSION", "RFC7296" },
	{ IKEV2_N_INVALID_SYNTAX, "INVALID_SYNTAX", "RFC7296" },
	{ IKEV2_N_INVALID_MESSAGE_ID, "INVALID_MESSAGE_ID", "RFC7296" },
	{ IKEV2_N_INVALID_SPI, "INVALID_SPI", "RFC7296" },
	{ IKEV2_N_NO_PROPOSAL_CHOSEN, "NO_PROPOSAL_CHOSEN", "RFC7296" },
	{ IKEV2_N_INVALID_KE_PAYLOAD, "INVALID_KE_PAYLOAD", "RFC7296" },
	{ IKEV2_N_AUTHENTICATION_FAILED, "AUTHENTICATION_FAILED", "RFC7296" },
	{ IKEV2_N_SINGLE_PAIR_REQUIRED, "SINGLE_PAIR_REQUIRED", "RFC7296" },
	{ IKEV2_N_NO_ADDITIONAL_SAS, "NO_ADDITIONAL_SAS", "RFC7296" },
	{ IKEV2_N_INTERNAL_ADDRESS_FAILURE, "INTERNAL_ADDRESS_FAILURE", "RFC7296" },
	{ IKEV2_N_FAILED_CP_REQUIRED, "FAILED_CP_REQUIRED", "RFC7296" },
	{ IKEV2_N_TS_UNACCEPTABLE, "TS_UNACCEPTABLE", "RFC7296" },
	{ IKEV2_N_INVALID_SELECTORS, "INVALID_SELECTORS", "RFC7296" },
	{ IKEV2_N_UNACCEPTABLE_ADDRESSES, "UNACCEPTABLE_ADDRESSES", "RFC4555" },
	{ IKEV2_N_UNEXPECTED_NAT_DETECTED, "UNEXPECTED_NAT_DETECTED", "RFC4555" },
	{ IKEV2_N_USE_ASSIGNED_HoA, "USE_ASSIGNED_HoA", "RFC5026" },
	{ IKEV2_N_TEMPORARY_FAILURE, "TEMPORARY_FAILURE", "RFC7296" },
	{ IKEV2_N_CHILD_SA_NOT_FOUND, "CHILD_SA_NOT_FOUND", "RFC7296" },
	{ IKEV2_N_INITIAL_CONTACT, "INITIAL_CONTACT", "RFC7296" },
	{ IKEV2_N_SET_WINDOW_SIZE, "SET_WINDOW_SIZE", "RFC7296" },
	{ IKEV2_N_ADDITIONAL_TS_POSSIBLE, "ADDITIONAL_TS_POSSIBLE", "RFC7296" },
	{ IKEV2_N_IPCOMP_SUPPORTED, "IPCOMP_SUPPORTED", "RFC7296" },
	{ IKEV2_N_NAT_DETECTION_SOURCE_IP, "NAT_DETECTION_SOURCE_IP", "RFC7296" },
	{ IKEV2_N_NAT_DETECTION_DESTINATION_IP, "NAT_DETECTION_DESTINATION_IP", "RFC7296" },
	{ IKEV2_N_COOKIE, "COOKIE", "RFC7296" },
	{ IKEV2_N_USE_TRANSPORT_MODE, "USE_TRANSPORT_MODE", "RFC7296" },
	{ IKEV2_N_HTTP_CERT_LOOKUP_SUPPORTED, "HTTP_CERT_LOOKUP_SUPPORTED", "RFC7296" },
	{ IKEV2_N_REKEY_SA, "REKEY_SA", "RFC7296" },
	{ IKEV2_N_ESP_TFC_PADDING_NOT_SUPPORTED, "ESP_TFC_PADDING_NOT_SUPPORTED", "RFC7296" },
	{ IKEV2_N_NON_FIRST_FRAGMENTS_ALSO, "NON_FIRST_FRAGMENTS_ALSO", "RFC7296" },
	{ IKEV2_N_MOBIKE_SUPPORTED, "MOBIKE_SUPPORTED", "RFC4555" },
	{ IKEV2_N_ADDITIONAL_IP4_ADDRESS, "ADDITIONAL_IP4_ADDRESS", "RFC4555" },
	{ IKEV2_N_ADDITIONAL_IP6_ADDRESS, "ADDITIONAL_IP6_ADDRESS", "RFC4555" },
	{ IKEV2_N_NO_ADDITIONAL_ADDRESSES, "NO_ADDITIONAL_ADDRESSES", "RFC4555" },
	{ IKEV2_N_UPDATE_SA_ADDRESSES, "UPDATE_SA_ADDRESSES", "RFC4555" },
	{ IKEV2_N_COOKIE2, "COOKIE2", "RFC4555" },
	{ IKEV2_N_NO_NATS_ALLOWED, "NO_NATS_ALLOWED", "RFC4555" },
	{ IKEV2_N_AUTH_LIFETIME, "AUTH_LIFETIME", "RFC4478" },
	{ IKEV2_N_MULTIPLE_AUTH_SUPPORTED, "MULTIPLE_AUTH_SUPPORTED", "RFC4739" },
	{ IKEV2_N_ANOTHER_AUTH_FOLLOWS, "ANOTHER_AUTH_FOLLOWS", "RFC4739" },
	{ IKEV2_N_REDIRECT_SUPPORTED, "REDIRECT_SUPPORTED", "RFC5685" },
	{ IKEV2_N_REDIRECT, "REDIRECT", "RFC5685" },
	{ IKEV2_N_REDIRECTED_FROM, "REDIRECTED_FROM", "RFC5685" },
	{ IKEV2_N_TICKET_LT_OPAQUE, "TICKET_LT_OPAQUE", "RFC5723" },
	{ IKEV2_N_TICKET_REQUEST, "TICKET_REQUEST", "RFC5723" },
	{ IKEV2_N_TICKET_ACK, "TICKET_ACK", "RFC5723" },
	{ IKEV2_N_TICKET_NACK, "TICKET_NACK", "RFC5723" },
	{ IKEV2_N_TICKET_OPAQUE, "TICKET_OPAQUE", "RFC5723" },
	{ IKEV2_N_LINK_ID, "LINK_ID", "RFC5739" },
	{ IKEV2_N_USE_WESP_MODE, "USE_WESP_MODE", "RFC5415" },
	{ IKEV2_N_ROHC_SUPPORTED, "ROHC_SUPPORTED", "RFC5857" },
	{ IKEV2_N_EAP_ONLY_AUTHENTICATION, "EAP_ONLY_AUTHENTICATION", "RFC5998" },
	{ IKEV2_N_CHILDLESS_IKEV2_SUPPORTED, "CHILDLESS_IKEV2_SUPPORTED", "RFC6023" },
	{ IKEV2_N_QUICK_CRASH_DETECTION, "QUICK_CRASH_DETECTION", "RFC6290" },
	{ IKEV2_N_IKEV2_MESSAGE_ID_SYNC_SUPPORTED, "IKEV2_MESSAGE_ID_SYNC_SUPPORTED", "RFC6311" },
	{ IKEV2_N_IPSEC_REPLAY_CTR_SYNC_SUPPORTED, "IPSEC_REPLAY_CTR_SYNC_SUPPORTED", "RFC6311" },
	{ IKEV2_N_IKEV2_MESSAGE_ID_SYNC, "IKEV2_MESSAGE_ID_SYNC", "RFC6311" },
	{ IKEV2_N_IPSEC_REPLAY_CTR_SYNC, "IPSEC_REPLAY_CTR_SYNC", "RFC6311" },
	{ IKEV2_N_SECURE_PASSWORD_METHODS, "SECURE_PASSWORD_METHODS", "RFC6467" },
	{ IKEV2_N_PSK_PERSIST, "PSK_PERSIST", "RFC6631" },
	{ IKEV2_N_PSK_CONFIRM, "PSK_CONFIRM", "RFC6631" },
	{ IKEV2_N_ERX_SUPPORTED, "ERX_SUPPORTED", "RFC6867" },
	{ IKEV2_N_IFOM_CAPABILITY, "IFOM_CAPABILITY", "OA3GPP" },
	{ IKEV2_N_FRAGMENTATION_SUPPORTED, "FRAGMENTATION_SUPPORTED", "RFC7383" },
	{ IKEV2_N_SIGNATURE_HASH_ALGORITHMS, "SIGNATURE_HASH_ALGORITHMS", "RFC7427" },
	{ 0 }
};
struct iked_constmap ikev2_id_map[] = {
	{ IKEV2_ID_NONE, "NONE", "No ID" },
	{ IKEV2_ID_IPV4, "IPV4", "RFC7296 (ID_IPV4_ADDR)" },
	{ IKEV2_ID_FQDN, "FQDN", "RFC7296" },
	{ IKEV2_ID_UFQDN, "UFQDN", "RFC7296 (ID_RFC822_ADDR)" },
	{ IKEV2_ID_IPV6, "IPV6", "RFC7296 (ID_IPV6_ADDR)" },
	{ IKEV2_ID_ASN1_DN, "ASN1_DN", "RFC7296" },
	{ IKEV2_ID_ASN1_GN, "ASN1_GN", "RFC7296" },
	{ IKEV2_ID_KEY_ID, "KEY_ID", "RFC7296" },
	{ IKEV2_ID_FC_NAME, "FC_NAME", "RFC4595" },
	{ 0 }
};
struct iked_constmap ikev2_cert_map[] = {
	{ IKEV2_CERT_NONE, "NONE", "None" },
	{ IKEV2_CERT_X509_PKCS7, "X509_PKCS7", "UNSPECIFIED" },
	{ IKEV2_CERT_PGP, "PGP", "UNSPECIFIED" },
	{ IKEV2_CERT_DNS_SIGNED_KEY, "DNS_SIGNED_KEY", "UNSPECIFIED" },
	{ IKEV2_CERT_X509_CERT, "X509_CERT", "RFC7296" },
	{ IKEV2_CERT_KERBEROS_TOKEN, "KERBEROS_TOKEN", "UNSPECIFIED" },
	{ IKEV2_CERT_CRL, "CRL", "RFC7296" },
	{ IKEV2_CERT_ARL, "ARL", "UNSPECIFIED" },
	{ IKEV2_CERT_SPKI, "SPKI", "UNSPECIFIED" },
	{ IKEV2_CERT_X509_ATTR, "X509_ATTR", "UNSPECIFIED" },
	{ IKEV2_CERT_RSA_KEY, "RSA_KEY", "RFC7296" },
	{ IKEV2_CERT_HASHURL_X509, "HASHURL_X509", "RFC7296" },
	{ IKEV2_CERT_HASHURL_X509_BUNDLE, "HASHURL_X509_BUNDLE", "RFC7296" },
	{ IKEV2_CERT_OCSP, "OCSP", "RFC4806" },
	{ IKEV2_CERT_ECDSA, "ECDSA", "Private" },
	{ IKEV2_CERT_BUNDLE, "BUNDLE", "Private" },
	{ 0 }
};
struct iked_constmap ikev2_ts_map[] = {
	{ IKEV2_TS_IPV4_ADDR_RANGE, "IPV4_ADDR_RANGE", "RFC7296" },
	{ IKEV2_TS_IPV6_ADDR_RANGE, "IPV6_ADDR_RANGE", "RFC7296" },
	{ IKEV2_TS_FC_ADDR_RANGE, "FC_ADDR_RANGE", "RFC4595" },
	{ 0 }
};
struct iked_constmap ikev2_auth_map[] = {
	{ IKEV2_AUTH_NONE, "NONE", "None" },
	{ IKEV2_AUTH_RSA_SIG, "RSA_SIG", "RFC7296" },
	{ IKEV2_AUTH_SHARED_KEY_MIC, "SHARED_KEY_MIC", "RFC7296" },
	{ IKEV2_AUTH_DSS_SIG, "DSS_SIG", "RFC7296" },
	{ IKEV2_AUTH_ECDSA_256, "ECDSA_256", "RFC4754" },
	{ IKEV2_AUTH_ECDSA_384, "ECDSA_384", "RFC4754" },
	{ IKEV2_AUTH_ECDSA_521, "ECDSA_521", "RFC4754" },
	{ IKEV2_AUTH_GSPM, "GSPM", "RFC6467" },
	{ IKEV2_AUTH_NULL, "NULL", "RFC7619" },
	{ IKEV2_AUTH_SIG, "SIG", "RFC7427" },
	{ IKEV2_AUTH_SIG_ANY, "SIG_ANY", "Internal (any signature)" },
/* Notifications used together with IKEV2_AUTH_SIG */
	{ 0 }
};
struct iked_constmap ikev2_sighash_map[] = {
	{ IKEV2_SIGHASH_RESERVED, "RESERVED", "RFC7427" },
	{ IKEV2_SIGHASH_SHA1, "SHA1", "RFC7427" },
	{ IKEV2_SIGHASH_SHA2_256, "SHA2_256", "RFC7427" },
	{ IKEV2_SIGHASH_SHA2_384, "SHA2_384", "RFC7427" },
	{ IKEV2_SIGHASH_SHA2_512, "SHA2_512", "RFC7427" },
	{ 0 }
};
struct iked_constmap ikev2_cp_map[] = {
	{ IKEV2_CP_REQUEST, "REQUEST", "CFG-Request" },
	{ IKEV2_CP_REPLY, "REPLY", "CFG-Reply" },
	{ IKEV2_CP_SET, "SET", "CFG-SET" },
	{ IKEV2_CP_ACK, "ACK", "CFG-ACK" },
	{ 0 }
};
struct iked_constmap ikev2_cfg_map[] = {
	{ IKEV2_CFG_INTERNAL_IP4_ADDRESS, "INTERNAL_IP4_ADDRESS", "RFC7296" },
	{ IKEV2_CFG_INTERNAL_IP4_NETMASK, "INTERNAL_IP4_NETMASK", "RFC7296" },
	{ IKEV2_CFG_INTERNAL_IP4_DNS, "INTERNAL_IP4_DNS", "RFC7296" },
	{ IKEV2_CFG_INTERNAL_IP4_NBNS, "INTERNAL_IP4_NBNS", "RFC7296" },
	{ IKEV2_CFG_INTERNAL_ADDRESS_EXPIRY, "INTERNAL_ADDRESS_EXPIRY", "RFC4306" },
	{ IKEV2_CFG_INTERNAL_IP4_DHCP, "INTERNAL_IP4_DHCP", "RFC7296" },
	{ IKEV2_CFG_APPLICATION_VERSION, "APPLICATION_VERSION", "RFC7296" },
	{ IKEV2_CFG_INTERNAL_IP6_ADDRESS, "INTERNAL_IP6_ADDRESS", "RFC7296" },
	{ IKEV2_CFG_INTERNAL_IP6_DNS, "INTERNAL_IP6_DNS", "RFC7296" },
	{ IKEV2_CFG_INTERNAL_IP6_NBNS, "INTERNAL_IP6_NBNS", "RFC4306" },
	{ IKEV2_CFG_INTERNAL_IP6_DHCP, "INTERNAL_IP6_DHCP", "RFC7296" },
	{ IKEV2_CFG_INTERNAL_IP4_SUBNET, "INTERNAL_IP4_SUBNET", "RFC7296" },
	{ IKEV2_CFG_SUPPORTED_ATTRIBUTES, "SUPPORTED_ATTRIBUTES", "RFC7296" },
	{ IKEV2_CFG_INTERNAL_IP6_SUBNET, "INTERNAL_IP6_SUBNET", "RFC7296" },
	{ IKEV2_CFG_MIP6_HOME_PREFIX, "MIP6_HOME_PREFIX", "RFC5026" },
	{ IKEV2_CFG_INTERNAL_IP6_LINK, "INTERNAL_IP6_LINK", "RFC5739" },
	{ IKEV2_CFG_INTERNAL_IP6_PREFIX, "INTERNAL_IP6_PREFIX", "RFC5739" },
	{ IKEV2_CFG_HOME_AGENT_ADDRESS, "HOME_AGENT_ADDRESS", "http://www.3gpp.org/ftp/Specs/html-info/24302.htm" },
	{ IKEV2_CFG_INTERNAL_IP4_SERVER, "INTERNAL_IP4_SERVER", "MS-IKEE" },
	{ IKEV2_CFG_INTERNAL_IP6_SERVER, "INTERNAL_IP6_SERVER", "MS-IKEE" },
	{ 0 }
};
