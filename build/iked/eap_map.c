/* Automatically generated from /root/fuzzing-openiked-portable/iked/eap.h, do not edit */
/*	$OpenBSD: eap.h,v 1.6 2020/09/16 21:37:35 tobhe Exp $	*/

/*
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
#include "eap.h"

struct iked_constmap eap_code_map[] = {
	{ EAP_CODE_REQUEST, "REQUEST", "Request" },
	{ EAP_CODE_RESPONSE, "RESPONSE", "Response" },
	{ EAP_CODE_SUCCESS, "SUCCESS", "Success" },
	{ EAP_CODE_FAILURE, "FAILURE", "Failure" },
	{ 0 }
};
struct iked_constmap eap_type_map[] = {
	{ EAP_TYPE_NONE, "NONE", "NONE" },
	{ EAP_TYPE_IDENTITY, "IDENTITY", "RFC3748" },
	{ EAP_TYPE_NOTIFICATION, "NOTIFICATION", "RFC3748" },
	{ EAP_TYPE_NAK, "NAK", "RFC3748" },
	{ EAP_TYPE_MD5, "MD5", "RFC3748" },
	{ EAP_TYPE_OTP, "OTP", "RFC3748" },
	{ EAP_TYPE_GTC, "GTC", "RFC3748" },
	{ EAP_TYPE_RSA, "RSA", "Whelan" },
	{ EAP_TYPE_DSS, "DSS", "Nace" },
	{ EAP_TYPE_KEA, "KEA", "Nace" },
	{ EAP_TYPE_KEA_VALIDATE, "KEA_VALIDATE", "Nace" },
	{ EAP_TYPE_TLS, "TLS", "RFC5216" },
	{ EAP_TYPE_AXENT, "AXENT", "Rosselli" },
	{ EAP_TYPE_SECURID, "SECURID", "Nystrm" },
	{ EAP_TYPE_ARCOT, "ARCOT", "Jerdonek" },
	{ EAP_TYPE_CISCO, "CISCO", "Norman" },
	{ EAP_TYPE_SIM, "SIM", "RFC4186" },
	{ EAP_TYPE_SRP_SHA1, "SRP_SHA1", "Carlson" },
	{ EAP_TYPE_TTLS, "TTLS", "Funk" },
	{ EAP_TYPE_RAS, "RAS", "Fields" },
	{ EAP_TYPE_OAAKA, "OAAKA", "RFC4187" },
	{ EAP_TYPE_3COM, "3COM", "Young" },
	{ EAP_TYPE_PEAP, "PEAP", "Palekar" },
	{ EAP_TYPE_MSCHAP_V2, "MSCHAP_V2", "Palekar" },
	{ EAP_TYPE_MAKE, "MAKE", "Berrendonner" },
	{ EAP_TYPE_CRYPTOCARD, "CRYPTOCARD", "Webb" },
	{ EAP_TYPE_MSCHAP_V2_2, "MSCHAP_V2_2", "Potter" },
	{ EAP_TYPE_DYNAMID, "DYNAMID", "Merlin" },
	{ EAP_TYPE_ROB, "ROB", "Ullah" },
	{ EAP_TYPE_POTP, "POTP", "RFC4794" },
	{ EAP_TYPE_MS_TLV, "MS_TLV", "Palekar" },
	{ EAP_TYPE_SENTRINET, "SENTRINET", "Kelleher" },
	{ EAP_TYPE_ACTIONTEC, "ACTIONTEC", "Chang" },
	{ EAP_TYPE_BIOMETRICS, "BIOMETRICS", "Xiong" },
	{ EAP_TYPE_AIRFORTRESS, "AIRFORTRESS", "Hibbard" },
	{ EAP_TYPE_HTTP_DIGEST, "HTTP_DIGEST", "Tavakoli" },
	{ EAP_TYPE_SECURESUITE, "SECURESUITE", "Clements" },
	{ EAP_TYPE_DEVICECONNECT, "DEVICECONNECT", "Pitard" },
	{ EAP_TYPE_SPEKE, "SPEKE", "Zick" },
	{ EAP_TYPE_MOBAC, "MOBAC", "Rixom" },
	{ EAP_TYPE_FAST, "FAST", "Cam-Winget" },
	{ EAP_TYPE_ZLX, "ZLX", "Bogue" },
	{ EAP_TYPE_LINK, "LINK", "Zick" },
	{ EAP_TYPE_PAX, "PAX", "Clancy" },
	{ EAP_TYPE_PSK, "PSK", "RFC-bersani-eap-psk-11.txt" },
	{ EAP_TYPE_SAKE, "SAKE", "RFC-vanderveen-eap-sake-02.txt" },
	{ EAP_TYPE_IKEV2, "IKEV2", "RFC5106" },
	{ EAP_TYPE_AKA2, "AKA2", "RFC5448" },
	{ EAP_TYPE_GPSK, "GPSK", "RFC5106" },
	{ EAP_TYPE_PWD, "PWD", "RFC-harkins-emu-eap-pwd-12.txt" },
	{ EAP_TYPE_EXPANDED_TYPE, "EXPANDED_TYPE", "RFC3748" },
	{ EAP_TYPE_EXPERIMENTAL, "EXPERIMENTAL", "RFC3748" },
	{ 0 }
};
struct iked_constmap eap_msopcode_map[] = {
	{ EAP_MSOPCODE_CHALLENGE, "CHALLENGE", "Challenge" },
	{ EAP_MSOPCODE_RESPONSE, "RESPONSE", "Response" },
	{ EAP_MSOPCODE_SUCCESS, "SUCCESS", "Success" },
	{ EAP_MSOPCODE_FAILURE, "FAILURE", "Failure" },
	{ EAP_MSOPCODE_CHANGE_PASSWORD, "CHANGE_PASSWORD", "Change Password" },
	{ 0 }
};
struct iked_constmap eap_mserror_map[] = {
	{ EAP_MSERROR_RESTRICTED_LOGON_HOURS, "RESTRICTED_LOGON_HOURS", "eap-mschapv2" },
	{ EAP_MSERROR_ACCT_DISABLED, "ACCT_DISABLED", "eap-mschapv2" },
	{ EAP_MSERROR_PASSWD_EXPIRED, "PASSWD_EXPIRED", "eap-mschapv2" },
	{ EAP_MSERROR_NO_DIALIN_PERMISSION, "NO_DIALIN_PERMISSION", "eap-mschapv2" },
	{ EAP_MSERROR_AUTHENTICATION_FAILURE, "AUTHENTICATION_FAILURE", "eap-mschapv2" },
	{ EAP_MSERROR_CHANGING_PASSWORD, "CHANGING_PASSWORD", "eap-mschapv2" },
	{ 0 }
};
