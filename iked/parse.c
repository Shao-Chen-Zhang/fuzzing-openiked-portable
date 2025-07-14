/* original parser id follows */
/* yysccsid[] = "@(#)yaccpar	1.9 (Berkeley) 02/21/93" */
/* (use YYMAJOR/YYMINOR for ifdefs dependent on parser version) */

#define YYBYACC 1
#define YYMAJOR 2
#define YYMINOR 0
#define YYPATCH 20230201

#define YYEMPTY        (-1)
#define yyclearin      (yychar = YYEMPTY)
#define yyerrok        (yyerrflag = 0)
#define YYRECOVERING() (yyerrflag != 0)
#define YYENOMEM       (-2)
#define YYEOF          0
#define YYPREFIX "yy"

#define YYPURE 0

#line 26 "parse.y"
#include <sys/types.h>
#include <sys/ioctl.h>
#include <sys/queue.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <net/if.h>
#include <netinet/in.h>
#include <netinet/ip_ipsp.h>
#include <arpa/inet.h>

#include <ctype.h>
#include <err.h>
#include <errno.h>
#include <fcntl.h>
#include <ifaddrs.h>
#include <limits.h>
#include <netdb.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <unistd.h>
#include <event.h>

#include <net/pfkeyv2.h>

#include "iked.h"
#include "ikev2.h"
#include "eap.h"

TAILQ_HEAD(files, file)		 files = TAILQ_HEAD_INITIALIZER(files);
static struct file {
	TAILQ_ENTRY(file)	 entry;
	FILE			*stream;
	char			*name;
	size_t			 ungetpos;
	size_t			 ungetsize;
	u_char			*ungetbuf;
	int			 eof_reached;
	int			 lineno;
	int			 errors;
} *file, *topfile;
struct file	*pushfile(const char *, int);
int		 popfile(void);
int		 check_file_secrecy(int, const char *);
int		 yyparse(void);
int		 yylex(void);
int		 yyerror(const char *, ...)
    __attribute__((__format__ (printf, 1, 2)))
    __attribute__((__nonnull__ (1)));
int		 kw_cmp(const void *, const void *);
int		 lookup(char *);
int		 igetc(void);
int		 lgetc(int);
void		 lungetc(int);
int		 findeol(void);

TAILQ_HEAD(symhead, sym)	 symhead = TAILQ_HEAD_INITIALIZER(symhead);
struct sym {
	TAILQ_ENTRY(sym)	 entry;
	int			 used;
	int			 persist;
	char			*nam;
	char			*val;
};
int		 symset(const char *, const char *, int);
char		*symget(const char *);

#define KEYSIZE_LIMIT	1024

static struct iked	*env = NULL;
static int		 debug = 0;
static int		 rules = 0;
static int		 passive = 0;
static int		 decouple = 0;
static int		 mobike = 1;
static int		 enforcesingleikesa = 0;
static int		 stickyaddress = 0;
static int		 fragmentation = 0;
static int		 vendorid = 1;
static int		 dpd_interval = IKED_IKE_SA_ALIVE_TIMEOUT;
static char		*ocsp_url = NULL;
static long		 ocsp_tolerate = 0;
static long		 ocsp_maxage = -1;
static int		 cert_partial_chain = 0;

struct iked_transform ikev2_default_ike_transforms[] = {
	{ IKEV2_XFORMTYPE_ENCR, IKEV2_XFORMENCR_AES_CBC, 256 },
	{ IKEV2_XFORMTYPE_ENCR, IKEV2_XFORMENCR_AES_CBC, 192 },
	{ IKEV2_XFORMTYPE_ENCR, IKEV2_XFORMENCR_AES_CBC, 128 },
	{ IKEV2_XFORMTYPE_ENCR, IKEV2_XFORMENCR_3DES },
	{ IKEV2_XFORMTYPE_PRF,	IKEV2_XFORMPRF_HMAC_SHA2_256 },
	{ IKEV2_XFORMTYPE_PRF,	IKEV2_XFORMPRF_HMAC_SHA2_384 },
	{ IKEV2_XFORMTYPE_PRF,	IKEV2_XFORMPRF_HMAC_SHA2_512 },
	{ IKEV2_XFORMTYPE_PRF,	IKEV2_XFORMPRF_HMAC_SHA1 },
	{ IKEV2_XFORMTYPE_INTEGR, IKEV2_XFORMAUTH_HMAC_SHA2_256_128 },
	{ IKEV2_XFORMTYPE_INTEGR, IKEV2_XFORMAUTH_HMAC_SHA2_384_192 },
	{ IKEV2_XFORMTYPE_INTEGR, IKEV2_XFORMAUTH_HMAC_SHA2_512_256 },
	{ IKEV2_XFORMTYPE_INTEGR, IKEV2_XFORMAUTH_HMAC_SHA1_96 },
	{ IKEV2_XFORMTYPE_DH,	IKEV2_XFORMDH_CURVE25519 },
	{ IKEV2_XFORMTYPE_DH,	IKEV2_XFORMDH_ECP_521 },
	{ IKEV2_XFORMTYPE_DH,	IKEV2_XFORMDH_ECP_384 },
	{ IKEV2_XFORMTYPE_DH,	IKEV2_XFORMDH_ECP_256 },
	{ IKEV2_XFORMTYPE_DH,	IKEV2_XFORMDH_MODP_4096 },
	{ IKEV2_XFORMTYPE_DH,	IKEV2_XFORMDH_MODP_3072 },
	{ IKEV2_XFORMTYPE_DH,	IKEV2_XFORMDH_MODP_2048 },
	{ IKEV2_XFORMTYPE_DH,	IKEV2_XFORMDH_MODP_1536 },
	{ IKEV2_XFORMTYPE_DH,	IKEV2_XFORMDH_MODP_1024 },
	{ 0 }
};
size_t ikev2_default_nike_transforms = ((sizeof(ikev2_default_ike_transforms) /
    sizeof(ikev2_default_ike_transforms[0])) - 1);

struct iked_transform ikev2_default_ike_transforms_noauth[] = {
	{ IKEV2_XFORMTYPE_ENCR,	IKEV2_XFORMENCR_AES_GCM_16, 128 },
	{ IKEV2_XFORMTYPE_ENCR,	IKEV2_XFORMENCR_AES_GCM_16, 256 },
	{ IKEV2_XFORMTYPE_PRF,	IKEV2_XFORMPRF_HMAC_SHA2_256 },
	{ IKEV2_XFORMTYPE_PRF,	IKEV2_XFORMPRF_HMAC_SHA2_384 },
	{ IKEV2_XFORMTYPE_PRF,	IKEV2_XFORMPRF_HMAC_SHA2_512 },
	{ IKEV2_XFORMTYPE_PRF,	IKEV2_XFORMPRF_HMAC_SHA1 },
	{ IKEV2_XFORMTYPE_DH,	IKEV2_XFORMDH_CURVE25519 },
	{ IKEV2_XFORMTYPE_DH,	IKEV2_XFORMDH_ECP_521 },
	{ IKEV2_XFORMTYPE_DH,	IKEV2_XFORMDH_ECP_384 },
	{ IKEV2_XFORMTYPE_DH,	IKEV2_XFORMDH_ECP_256 },
	{ IKEV2_XFORMTYPE_DH,	IKEV2_XFORMDH_MODP_4096 },
	{ IKEV2_XFORMTYPE_DH,	IKEV2_XFORMDH_MODP_3072 },
	{ IKEV2_XFORMTYPE_DH,	IKEV2_XFORMDH_MODP_2048 },
	{ IKEV2_XFORMTYPE_DH,	IKEV2_XFORMDH_MODP_1536 },
	{ IKEV2_XFORMTYPE_DH,	IKEV2_XFORMDH_MODP_1024 },
	{ 0 }
};
size_t ikev2_default_nike_transforms_noauth =
    ((sizeof(ikev2_default_ike_transforms_noauth) /
    sizeof(ikev2_default_ike_transforms_noauth[0])) - 1);

struct iked_transform ikev2_default_esp_transforms[] = {
	{ IKEV2_XFORMTYPE_ENCR, IKEV2_XFORMENCR_AES_CBC, 256 },
	{ IKEV2_XFORMTYPE_ENCR, IKEV2_XFORMENCR_AES_CBC, 192 },
	{ IKEV2_XFORMTYPE_ENCR, IKEV2_XFORMENCR_AES_CBC, 128 },
	/* XXX: Linux uses a non-standard truncated SHA256 with pfkey */
#if !defined(HAVE_LINUX_PFKEY_H)
	{ IKEV2_XFORMTYPE_INTEGR, IKEV2_XFORMAUTH_HMAC_SHA2_256_128 },
#endif
	{ IKEV2_XFORMTYPE_INTEGR, IKEV2_XFORMAUTH_HMAC_SHA2_384_192 },
	{ IKEV2_XFORMTYPE_INTEGR, IKEV2_XFORMAUTH_HMAC_SHA2_512_256 },
	{ IKEV2_XFORMTYPE_INTEGR, IKEV2_XFORMAUTH_HMAC_SHA1_96 },
	{ IKEV2_XFORMTYPE_DH,	IKEV2_XFORMDH_NONE },
#if defined(SADB_X_SAFLAGS_ESN) && !defined(HAVE_APPLE_NATT)
	{ IKEV2_XFORMTYPE_ESN,	IKEV2_XFORMESN_ESN },
#endif
	{ IKEV2_XFORMTYPE_ESN,	IKEV2_XFORMESN_NONE },
	{ 0 }
};
size_t ikev2_default_nesp_transforms = ((sizeof(ikev2_default_esp_transforms) /
    sizeof(ikev2_default_esp_transforms[0])) - 1);

struct iked_transform ikev2_default_esp_transforms_noauth[] = {
	{ IKEV2_XFORMTYPE_ENCR,	IKEV2_XFORMENCR_AES_GCM_16, 128 },
	{ IKEV2_XFORMTYPE_ENCR,	IKEV2_XFORMENCR_AES_GCM_16, 256 },
	{ IKEV2_XFORMTYPE_DH,	IKEV2_XFORMDH_NONE },
#if defined(SADB_X_SAFLAGS_ESN) && !defined(HAVE_APPLE_NATT)
	{ IKEV2_XFORMTYPE_ESN,	IKEV2_XFORMESN_ESN },
#endif
	{ IKEV2_XFORMTYPE_ESN,	IKEV2_XFORMESN_NONE },
	{ 0 }
};
size_t ikev2_default_nesp_transforms_noauth =
    ((sizeof(ikev2_default_esp_transforms_noauth) /
    sizeof(ikev2_default_esp_transforms_noauth[0])) - 1);

const struct ipsec_xf authxfs[] = {
	{ "hmac-md5",		IKEV2_XFORMAUTH_HMAC_MD5_96,		16 },
	{ "hmac-sha1",		IKEV2_XFORMAUTH_HMAC_SHA1_96,		20 },
	{ "hmac-sha2-256",	IKEV2_XFORMAUTH_HMAC_SHA2_256_128,	32 },
	{ "hmac-sha2-384",	IKEV2_XFORMAUTH_HMAC_SHA2_384_192,	48 },
	{ "hmac-sha2-512",	IKEV2_XFORMAUTH_HMAC_SHA2_512_256,	64 },
	{ NULL }
};

const struct ipsec_xf prfxfs[] = {
	{ "hmac-md5",		IKEV2_XFORMPRF_HMAC_MD5,	16 },
	{ "hmac-sha1",		IKEV2_XFORMPRF_HMAC_SHA1,	20 },
	{ "hmac-sha2-256",	IKEV2_XFORMPRF_HMAC_SHA2_256,	32 },
	{ "hmac-sha2-384",	IKEV2_XFORMPRF_HMAC_SHA2_384,	48 },
	{ "hmac-sha2-512",	IKEV2_XFORMPRF_HMAC_SHA2_512,	64 },
	{ NULL }
};

const struct ipsec_xf *encxfs = NULL;

const struct ipsec_xf ikeencxfs[] = {
	{ "3des",		IKEV2_XFORMENCR_3DES,		24 },
	{ "3des-cbc",		IKEV2_XFORMENCR_3DES,		24 },
	{ "aes-128",		IKEV2_XFORMENCR_AES_CBC,	16, 16 },
	{ "aes-192",		IKEV2_XFORMENCR_AES_CBC,	24, 24 },
	{ "aes-256",		IKEV2_XFORMENCR_AES_CBC,	32, 32 },
	{ "aes-128-gcm",	IKEV2_XFORMENCR_AES_GCM_16,	16, 16, 4, 1 },
	{ "aes-256-gcm",	IKEV2_XFORMENCR_AES_GCM_16,	32, 32, 4, 1 },
	{ "aes-128-gcm-12",	IKEV2_XFORMENCR_AES_GCM_12,	16, 16, 4, 1 },
	{ "aes-256-gcm-12",	IKEV2_XFORMENCR_AES_GCM_12,	32, 32, 4, 1 },
	{ NULL }
};

const struct ipsec_xf ipsecencxfs[] = {
	{ "3des",		IKEV2_XFORMENCR_3DES,		24 },
	{ "3des-cbc",		IKEV2_XFORMENCR_3DES,		24 },
	{ "aes-128",		IKEV2_XFORMENCR_AES_CBC,	16, 16 },
	{ "aes-192",		IKEV2_XFORMENCR_AES_CBC,	24, 24 },
	{ "aes-256",		IKEV2_XFORMENCR_AES_CBC,	32, 32 },
	{ "aes-128-ctr",	IKEV2_XFORMENCR_AES_CTR,	16, 16, 4 },
	{ "aes-192-ctr",	IKEV2_XFORMENCR_AES_CTR,	24, 24, 4 },
	{ "aes-256-ctr",	IKEV2_XFORMENCR_AES_CTR,	32, 32, 4 },
	{ "aes-128-gcm",	IKEV2_XFORMENCR_AES_GCM_16,	16, 16, 4, 1 },
	{ "aes-192-gcm",	IKEV2_XFORMENCR_AES_GCM_16,	24, 24, 4, 1 },
	{ "aes-256-gcm",	IKEV2_XFORMENCR_AES_GCM_16,	32, 32, 4, 1 },
	{ "aes-128-gmac",	IKEV2_XFORMENCR_NULL_AES_GMAC,	16, 16, 4, 1 },
	{ "aes-192-gmac",	IKEV2_XFORMENCR_NULL_AES_GMAC,	24, 24, 4, 1 },
	{ "aes-256-gmac",	IKEV2_XFORMENCR_NULL_AES_GMAC,	32, 32, 4, 1 },
	{ "blowfish",		IKEV2_XFORMENCR_BLOWFISH,	20, 20 },
	{ "cast",		IKEV2_XFORMENCR_CAST,		16, 16 },
	{ "chacha20-poly1305",	IKEV2_XFORMENCR_CHACHA20_POLY1305,
								32, 32, 4, 1 },
	{ "null",		IKEV2_XFORMENCR_NULL,		0, 0 },
	{ NULL }
};

const struct ipsec_xf groupxfs[] = {
	{ "none",		IKEV2_XFORMDH_NONE },
	{ "modp768",		IKEV2_XFORMDH_MODP_768 },
	{ "grp1",		IKEV2_XFORMDH_MODP_768 },
	{ "modp1024",		IKEV2_XFORMDH_MODP_1024 },
	{ "grp2",		IKEV2_XFORMDH_MODP_1024 },
	{ "modp1536",		IKEV2_XFORMDH_MODP_1536 },
	{ "grp5",		IKEV2_XFORMDH_MODP_1536 },
	{ "modp2048",		IKEV2_XFORMDH_MODP_2048 },
	{ "grp14",		IKEV2_XFORMDH_MODP_2048 },
	{ "modp3072",		IKEV2_XFORMDH_MODP_3072 },
	{ "grp15",		IKEV2_XFORMDH_MODP_3072 },
	{ "modp4096",		IKEV2_XFORMDH_MODP_4096 },
	{ "grp16",		IKEV2_XFORMDH_MODP_4096 },
	{ "modp6144",		IKEV2_XFORMDH_MODP_6144 },
	{ "grp17",		IKEV2_XFORMDH_MODP_6144 },
	{ "modp8192",		IKEV2_XFORMDH_MODP_8192 },
	{ "grp18",		IKEV2_XFORMDH_MODP_8192 },
	{ "ecp256",		IKEV2_XFORMDH_ECP_256 },
	{ "grp19",		IKEV2_XFORMDH_ECP_256 },
	{ "ecp384",		IKEV2_XFORMDH_ECP_384 },
	{ "grp20",		IKEV2_XFORMDH_ECP_384 },
	{ "ecp521",		IKEV2_XFORMDH_ECP_521 },
	{ "grp21",		IKEV2_XFORMDH_ECP_521 },
	{ "ecp192",		IKEV2_XFORMDH_ECP_192 },
	{ "grp25",		IKEV2_XFORMDH_ECP_192 },
	{ "ecp224",		IKEV2_XFORMDH_ECP_224 },
	{ "grp26",		IKEV2_XFORMDH_ECP_224 },
	{ "brainpool224",	IKEV2_XFORMDH_BRAINPOOL_P224R1 },
	{ "grp27",		IKEV2_XFORMDH_BRAINPOOL_P224R1 },
	{ "brainpool256",	IKEV2_XFORMDH_BRAINPOOL_P256R1 },
	{ "grp28",		IKEV2_XFORMDH_BRAINPOOL_P256R1 },
	{ "brainpool384",	IKEV2_XFORMDH_BRAINPOOL_P384R1 },
	{ "grp29",		IKEV2_XFORMDH_BRAINPOOL_P384R1 },
	{ "brainpool512",	IKEV2_XFORMDH_BRAINPOOL_P512R1 },
	{ "grp30",		IKEV2_XFORMDH_BRAINPOOL_P512R1 },
	{ "curve25519",		IKEV2_XFORMDH_CURVE25519 },
	{ "grp31",		IKEV2_XFORMDH_CURVE25519 },
	{ "sntrup761x25519",	IKEV2_XFORMDH_X_SNTRUP761X25519 },
	{ NULL }
};

const struct ipsec_xf esnxfs[] = {
	{ "esn",		IKEV2_XFORMESN_ESN },
	{ "noesn",		IKEV2_XFORMESN_NONE },
	{ NULL }
};

const struct ipsec_xf methodxfs[] = {
	{ "none",		IKEV2_AUTH_NONE },
	{ "rsa",		IKEV2_AUTH_RSA_SIG },
	{ "ecdsa256",		IKEV2_AUTH_ECDSA_256 },
	{ "ecdsa384",		IKEV2_AUTH_ECDSA_384 },
	{ "ecdsa521",		IKEV2_AUTH_ECDSA_521 },
	{ "rfc7427",		IKEV2_AUTH_SIG },
	{ "signature",		IKEV2_AUTH_SIG_ANY },
	{ NULL }
};

const struct ipsec_xf saxfs[] = {
	{ "esp",		IKEV2_SAPROTO_ESP },
	{ "ah",			IKEV2_SAPROTO_AH },
	{ NULL }
};

const struct ipsec_xf cpxfs[] = {
	{ "address", IKEV2_CFG_INTERNAL_IP4_ADDRESS,		AF_INET },
	{ "netmask", IKEV2_CFG_INTERNAL_IP4_NETMASK,		AF_INET },
	{ "name-server", IKEV2_CFG_INTERNAL_IP4_DNS,		AF_INET },
	{ "netbios-server", IKEV2_CFG_INTERNAL_IP4_NBNS,	AF_INET },
	{ "dhcp-server", IKEV2_CFG_INTERNAL_IP4_DHCP,		AF_INET },
	{ "address", IKEV2_CFG_INTERNAL_IP6_ADDRESS,		AF_INET6 },
	{ "name-server", IKEV2_CFG_INTERNAL_IP6_DNS,		AF_INET6 },
	{ "netbios-server", IKEV2_CFG_INTERNAL_IP6_NBNS,	AF_INET6 },
	{ "dhcp-server", IKEV2_CFG_INTERNAL_IP6_DHCP,		AF_INET6 },
	{ "protected-subnet", IKEV2_CFG_INTERNAL_IP4_SUBNET,	AF_INET },
	{ "protected-subnet", IKEV2_CFG_INTERNAL_IP6_SUBNET,	AF_INET6 },
	{ "access-server", IKEV2_CFG_INTERNAL_IP4_SERVER,	AF_INET },
	{ "access-server", IKEV2_CFG_INTERNAL_IP6_SERVER,	AF_INET6 },
	{ NULL }
};

const struct iked_lifetime deflifetime = {
	IKED_LIFETIME_BYTES,
	IKED_LIFETIME_SECONDS
};

#define IPSEC_ADDR_ANY		(0x1)
#define IPSEC_ADDR_DYNAMIC	(0x2)

struct ipsec_addr_wrap {
	struct sockaddr_storage	 address;
	uint8_t			 mask;
	int			 netaddress;
	sa_family_t		 af;
	unsigned int		 type;
	unsigned int		 action;
	uint16_t		 port;
	char			*name;
	struct ipsec_addr_wrap	*next;
	struct ipsec_addr_wrap	*tail;
	struct ipsec_addr_wrap	*srcnat;
};

struct ipsec_hosts {
	struct ipsec_addr_wrap	*src;
	struct ipsec_addr_wrap	*dst;
};

struct ipsec_filters {
	char			*tag;
	unsigned int		 tap;
};

void			 copy_sockaddrtoipa(struct ipsec_addr_wrap *,
			    struct sockaddr *);
struct ipsec_addr_wrap	*host(const char *);
struct ipsec_addr_wrap	*host_ip(const char *, int);
struct ipsec_addr_wrap	*host_dns(const char *, int);
struct ipsec_addr_wrap	*host_if(const char *, int);
struct ipsec_addr_wrap	*host_any(void);
struct ipsec_addr_wrap	*host_dynamic(void);
void			 ifa_load(void);
int			 ifa_exists(const char *);
struct ipsec_addr_wrap	*ifa_lookup(const char *ifa_name);
struct ipsec_addr_wrap	*ifa_grouplookup(const char *);
void			 set_ipmask(struct ipsec_addr_wrap *, int);
const struct ipsec_xf	*parse_xf(const char *, unsigned int,
			    const struct ipsec_xf *);
void			 copy_transforms(unsigned int,
			    const struct ipsec_xf **, unsigned int,
			    struct iked_transform **, unsigned int *,
			    struct iked_transform *, size_t);
int			 create_ike(char *, int, struct ipsec_addr_wrap *,
			    int, struct ipsec_hosts *,
			    struct ipsec_hosts *, struct ipsec_mode *,
			    struct ipsec_mode *, uint8_t,
			    unsigned int, char *, char *,
			    uint32_t, struct iked_lifetime *,
			    struct iked_auth *, struct ipsec_filters *,
			    struct ipsec_addr_wrap *, char *);
int			 create_user(const char *, const char *);
int			 get_id_type(char *);
uint8_t			 x2i(unsigned char *);
int			 parsekey(unsigned char *, size_t, struct iked_auth *);
int			 parsekeyfile(char *, struct iked_auth *);
void			 iaw_free(struct ipsec_addr_wrap *);
static int		 create_flow(struct iked_policy *pol, int, struct ipsec_addr_wrap *ipa,
			    struct ipsec_addr_wrap *ipb);
static int		 expand_flows(struct iked_policy *, int, struct ipsec_addr_wrap *,
			    struct ipsec_addr_wrap *);
static struct ipsec_addr_wrap *
			 expand_keyword(struct ipsec_addr_wrap *);

struct ipsec_transforms *ipsec_transforms;
struct ipsec_filters *ipsec_filters;
struct ipsec_mode *ipsec_mode;
/* interface lookup routintes */
struct ipsec_addr_wrap	*iftab;

typedef struct {
	union {
		int64_t			 number;
		unsigned int		 ikemode;
		uint8_t			 dir;
		uint8_t			 satype;
		char			*string;
		uint16_t		 port;
		struct ipsec_hosts	*hosts;
		struct ipsec_hosts	 peers;
		struct ipsec_addr_wrap	*anyhost;
		struct ipsec_addr_wrap	*host;
		struct ipsec_addr_wrap	*cfg;
		struct ipsec_addr_wrap	*proto;
		struct {
			char		*srcid;
			char		*dstid;
		} ids;
		char			*id;
		uint8_t			 type;
		struct iked_lifetime	 lifetime;
		struct iked_auth	 ikeauth;
		struct iked_auth	 ikekey;
		struct ipsec_transforms	*transforms;
		struct ipsec_filters	*filters;
		struct ipsec_mode	*mode;
	} v;
	int lineno;
} YYSTYPE;

#line 439 "parse.c"

/* compatibility with bison */
#ifdef YYPARSE_PARAM
/* compatibility with FreeBSD */
# ifdef YYPARSE_PARAM_TYPE
#  define YYPARSE_DECL() yyparse(YYPARSE_PARAM_TYPE YYPARSE_PARAM)
# else
#  define YYPARSE_DECL() yyparse(void *YYPARSE_PARAM)
# endif
#else
# define YYPARSE_DECL() yyparse(void)
#endif

/* Parameters sent to lex. */
#ifdef YYLEX_PARAM
# define YYLEX_DECL() yylex(void *YYLEX_PARAM)
# define YYLEX yylex(YYLEX_PARAM)
#else
# define YYLEX_DECL() yylex(void)
# define YYLEX yylex()
#endif

#if !(defined(yylex) || defined(YYSTATE))
int YYLEX_DECL();
#endif

/* Parameters sent to yyerror. */
#ifndef YYERROR_DECL
#define YYERROR_DECL() yyerror(const char *s)
#endif
#ifndef YYERROR_CALL
#define YYERROR_CALL(msg) yyerror(msg)
#endif

extern int YYPARSE_DECL();

#define FROM 257
#define ESP 258
#define AH 259
#define IN 260
#define PEER 261
#define ON 262
#define OUT 263
#define TO 264
#define SRCID 265
#define DSTID 266
#define PSK 267
#define PORT 268
#define FILENAME 269
#define AUTHXF 270
#define PRFXF 271
#define ENCXF 272
#define ERROR 273
#define IKEV2 274
#define IKESA 275
#define CHILDSA 276
#define ESN 277
#define NOESN 278
#define PASSIVE 279
#define ACTIVE 280
#define ANY 281
#define TAG 282
#define TAP 283
#define PROTO 284
#define LOCAL 285
#define GROUP 286
#define NAME 287
#define CONFIG 288
#define EAP 289
#define USER 290
#define IKEV1 291
#define FLOW 292
#define SA 293
#define TCPMD5 294
#define TUNNEL 295
#define TRANSPORT 296
#define COUPLE 297
#define DECOUPLE 298
#define SET 299
#define INCLUDE 300
#define LIFETIME 301
#define BYTES 302
#define INET 303
#define INET6 304
#define QUICK 305
#define SKIP 306
#define DEFAULT 307
#define IPCOMP 308
#define OCSP 309
#define IKELIFETIME 310
#define MOBIKE 311
#define NOMOBIKE 312
#define RDOMAIN 313
#define FRAGMENTATION 314
#define NOFRAGMENTATION 315
#define DPD_CHECK_INTERVAL 316
#define ENFORCESINGLEIKESA 317
#define NOENFORCESINGLEIKESA 318
#define STICKYADDRESS 319
#define NOSTICKYADDRESS 320
#define VENDORID 321
#define NOVENDORID 322
#define TOLERATE 323
#define MAXAGE 324
#define DYNAMIC 325
#define CERTPARTIALCHAIN 326
#define REQUEST 327
#define IFACE 328
#define NATT 329
#define STRING 330
#define NUMBER 331
#define YYERRCODE 256
typedef int YYINT;
static const YYINT yylhs[] = {                           -1,
    0,    0,    0,    0,    0,    0,    0,    0,    0,   47,
   47,   40,   41,   41,   41,   41,   41,   41,   41,   41,
   41,   41,   41,   41,   41,   41,   41,   41,   41,   41,
   41,   42,   43,   37,   37,   38,   38,   36,   36,   34,
   34,    2,    2,    2,   10,   10,   10,    3,    3,    3,
    4,    4,    5,    5,   11,   11,    7,    7,    6,    6,
    8,    8,    9,    9,   12,   12,   12,   12,   12,   13,
   13,   15,   15,   14,   14,   14,   14,   16,   16,   16,
   16,   17,   49,   18,   18,   48,   48,   50,   50,   50,
   50,   50,   39,   39,   52,   28,   28,   51,   51,   54,
   53,   56,   29,   29,   55,   55,   58,   57,   20,   21,
   21,   21,   21,   22,   22,   22,   23,   23,   24,   24,
   24,   25,   25,   26,   26,   26,   26,   31,   31,   32,
   32,   30,   30,   30,   33,   33,   27,   27,   60,   19,
   19,   59,   59,   61,   61,   35,   35,    1,    1,   44,
   45,   45,   45,   45,   62,   62,   62,   62,   62,   46,
};
static const YYINT yylen[] = {                            2,
    0,    3,    2,    3,    3,    3,    3,    4,    3,    1,
    0,    2,    2,    2,    2,    2,    2,    2,    2,    2,
    2,    2,    2,    2,    2,    2,    3,    5,    7,    2,
    3,    3,   18,    0,    1,    1,    2,    3,    3,    0,
    1,    0,    1,    1,    0,    1,    1,    0,    2,    4,
    1,    3,    1,    1,    0,    2,    1,    3,    6,    6,
    0,    2,    1,    1,    0,    4,    4,    2,    2,    1,
    1,    1,    3,    1,    4,    1,    1,    0,    4,    2,
    2,    1,    0,    2,    0,    2,    1,    2,    2,    2,
    2,    1,    1,    1,    0,    2,    0,    2,    1,    0,
    3,    0,    2,    0,    2,    1,    0,    3,    5,    0,
    1,    1,    1,    0,    1,    1,    0,    1,    0,    1,
    1,    0,    1,    0,    2,    2,    1,    1,    1,    1,
    1,    0,    2,    4,    0,    2,    1,    2,    0,    2,
    0,    2,    1,    2,    2,    0,    2,    2,    1,    3,
    1,    1,    1,    1,    1,    1,    1,    1,    1,    0,
};
static const YYINT yydefred[] = {                         1,
    0,    0,  156,  157,    0,    0,  151,  153,  155,  154,
  158,  159,    0,    0,    0,    3,    0,    0,    0,    0,
    0,  160,  152,    9,   41,    0,    0,   14,   13,   15,
   16,    0,   19,   20,   17,   18,    0,   23,   24,   25,
   26,   21,   22,   30,   12,    0,    2,    4,    5,    6,
    7,    0,  111,  112,  113,    0,    0,   32,    0,   31,
  149,    0,    8,   43,   44,    0,  115,  116,    0,    0,
  148,   46,   47,    0,  118,    0,  131,  130,    0,    0,
    0,  120,  121,    0,    0,   53,   54,    0,   49,    0,
    0,  123,  109,   29,    0,   51,   56,    0,    0,   57,
    0,   10,   50,    0,   76,   77,    0,    0,    0,    0,
    0,    0,    0,    0,   52,    0,    0,    0,    0,    0,
   71,    0,   70,    0,    0,    0,   58,   73,   63,   64,
   62,    0,    0,    0,    0,    0,    0,    0,  100,    0,
   99,    0,   75,    0,   66,   67,    0,    0,    0,  107,
    0,  106,    0,   98,   59,   60,   82,    0,   81,    0,
    0,    0,  105,  101,    0,    0,  136,    0,    0,  108,
    0,    0,    0,   93,   94,    0,   92,    0,   87,   79,
    0,    0,    0,  127,    0,   88,   90,   89,   91,   86,
    0,    0,  137,  125,  126,    0,    0,   36,    0,    0,
  129,  128,  134,  138,    0,    0,    0,    0,   37,   38,
   39,  147,   33,    0,    0,    0,    0,  143,  144,  145,
  142,
};
static const YYINT yydgoto[] = {                          1,
   62,   66,   81,   95,   89,  100,  101,  118,  131,   74,
   91,  113,  122,  108,  123,  149,  158,  164,  213,   56,
   57,   69,   76,   84,   93,  185,  194,  125,  137,  169,
  203,   79,  161,   26,  208,  198,  199,  200,  177,   17,
   18,   19,   20,   21,   22,   52,  104,  178,  165,  179,
  140,  126,  141,  153,  151,  138,  152,  162,  217,  214,
  218,   23,
};
static const YYINT yysindex[] = {                         0,
  207,   18,    0,    0, -297, -271,    0,    0,    0,    0,
    0,    0,  530, -265,    7,    0,   66,   70,   76,   86,
   89,    0,    0,    0,    0, -253, -221,    0,    0,    0,
    0, -218,    0,    0,    0,    0, -229,    0,    0,    0,
    0,    0,    0,    0,    0, -196,    0,    0,    0,    0,
    0,  107,    0,    0,    0, -235, -201,    0, -183,    0,
    0, -187,    0,    0,    0, -189,    0,    0, -162, -212,
    0,    0,    0, -136,    0, -172,    0,    0, -173, -121,
 -155,    0,    0, -166, -212,    0,    0, -202,    0, -167,
 -246,    0,    0,    0,  -37,    0,    0, -268, -268,    0,
  -43,    0,    0, -202,    0,    0,  118, -100,  129, -100,
 -266, -266,    0, -246,    0, -161, -199,  -92, -157,  -80,
    0, -106,    0,  -81,    0,  -93,    0,    0,    0,    0,
    0, -268,  140, -268, -266, -266, -130,  -86,    0,  -93,
    0, -100,    0, -100,    0,    0, -147, -147, -117,    0,
  -86,    0,    0,    0,    0,    0,    0,  -69,    0, -212,
 -105,    0,    0,    0,  -71, -147,    0, -212, -257,    0,
 -135, -132, -128,    0,    0, -125,    0,  -71,    0,    0,
  -99, -261, -122,    0, -269,    0,    0,    0,    0,    0,
 -192, -118,    0,    0,    0, -114, -111,    0, -115, -269,
    0,    0,    0,    0, -157, -266, -110,    0,    0,    0,
    0,    0,    0, -127, -108, -107, -127,    0,    0,    0,
    0,
};
static const YYINT yyrindex[] = {                         0,
    0,    0,    0,    0, -213,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0, -154,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0, -243, -151,    0,  211,    0,
    0,  214,    0,    0,    0, -228,    0,    0,  -70,    0,
    0,    0,    0, -215,    0, -137,    0,    0,  217,    0,
 -209,    0,    0,  -73,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0, -170,    0,    0,    0,    0,    0,
  194,    0,    0,    0,    0,    0,  -10,  -36,   40,  -28,
    0,    0,  243,    0,    0,    0,    0,    0,    0,    0,
    0,  273,    0,  322,  389,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,  478,    0,    0,  422,
    0,  127,    0,  127,    0,    0,    0,    0,   10,    0,
  474,    0,   77,    0,    0,    0,    0,  510,    0,    0,
   91,  164,    0,    0,    0,    0,    0,    0,   -1,    0,
    0,    0,    0,    0,    0,    0,    0,  352,    0,    0,
  403,    0,    0,    0,    2,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,   12,    6,
    0,    0,    0,    0,    0,    0,    0,   27,    0,    0,
    0,    0,    0,    0,    0,    0,  222,    0,    0,    0,
    0,
};
static const YYINT yygindex[] = {                         0,
    0,    0,    0,    0,  -41,  121,    0,  -67,    0,    0,
    0,    0, -109,  -60,  -94,    0, -131,   74,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,  -79,    0,    0,    0,   37,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,  137,    0,    0,   61,
    0,    0,  101,    0,    0,    0,   93,    0,    0,    0,
   28,    0,
};
#define YYTABLESIZE 856
static const YYINT yytable[] = {                         72,
  102,   88,  124,  109,  109,   94,  102,  192,  124,  182,
   98,   34,  105,   42,  121,   35,  159,   99,  196,  135,
   42,  146,   64,   65,  133,  145,  146,   24,   45,   72,
   72,  183,   25,   72,  180,   45,  141,  109,  110,  109,
   42,   48,  120,   40,   40,   40,   96,   55,   48,   74,
   40,   53,   54,   55,   55,   45,  106,  197,   27,   42,
   42,  107,  115,  107,   45,   40,   40,   46,  193,   42,
   40,  142,  184,  144,  155,   47,  156,   67,   68,   48,
  167,   40,   40,   74,   45,   49,   85,  103,  181,   40,
   40,   40,   40,   40,   40,   50,  211,   48,   51,   40,
  132,   60,  110,  110,  110,  114,  114,  114,   58,  110,
  210,   59,  114,   72,   73,   40,   63,   77,   78,  119,
  119,  119,   82,   83,  110,  110,  119,   86,   87,  110,
  129,  130,  114,   61,  147,  148,   61,  201,  202,   70,
  110,  110,   71,  114,  114,   75,  119,   80,  110,  110,
   85,  114,  114,  110,  215,  216,  114,   90,  110,   11,
   11,  114,   92,   97,  116,  119,  119,  117,  119,  128,
   61,  132,  107,   85,  110,  119,  134,  114,  135,  136,
  143,  139,  157,  122,  122,  122,  117,  117,  117,  150,
  122,  119,  160,  117,  186,  168,  166,  187,  171,  172,
  173,  188,  191,   65,  189,  174,  175,  195,   86,   87,
  122,  204,  207,  117,  176,  205,   16,  111,  206,  212,
   27,  219,  220,  150,  117,  117,   28,   61,   61,  122,
  122,  140,  117,  117,  127,  170,  209,  114,  190,  122,
  154,  112,  117,  163,  221,    0,   72,    0,    0,    0,
   72,    0,   97,   72,   72,   72,   72,   72,  117,    0,
    0,    0,    0,    0,   72,   72,    0,    0,    0,    0,
    0,   72,   72,    0,   72,    0,  135,   72,   72,    0,
  124,  124,   68,   34,   34,    0,  124,   35,   35,    0,
   72,  135,  135,  146,  146,    0,   74,  135,  135,   72,
   74,    0,    0,   74,   74,   74,   74,   74,  139,  139,
  135,    0,    0,    0,   74,   74,   72,   72,    0,   72,
    0,   74,   74,    0,   74,  124,  124,   74,   74,   34,
    0,   69,    0,   35,    0,    0,  135,  135,    0,  135,
   74,   85,   85,   85,    0,    0,   83,   83,   83,   74,
    0,   85,   85,   83,   83,    0,    0,  132,   85,   85,
    0,   84,   83,    0,   85,   85,   74,   74,    0,   74,
    0,    0,  132,  132,    0,    0,    0,   85,  132,  132,
    0,    0,    0,   61,    0,    0,   85,   61,    0,    0,
   61,   61,   61,   61,    0,    0,    0,    0,  104,    0,
    0,   61,   61,   85,   85,    0,   85,    0,   61,   61,
    0,   61,  133,    0,   61,   61,    0,  132,  132,    0,
  132,    0,    0,    0,    0,    0,    0,   61,   85,   85,
   85,   96,    0,   83,   83,   83,   61,    0,    0,   85,
   83,   83,    0,    0,    0,   85,   85,    0,    0,   83,
   11,   85,   85,   61,   61,    0,   61,   11,   65,   65,
   65,    0,    2,    3,   85,    0,    0,    0,   65,   65,
    4,    0,    0,   85,    0,   65,   65,    0,    0,    0,
    5,   65,   65,  103,    0,    0,    0,   78,    0,    0,
   85,   85,    0,   85,   65,    0,    6,    7,    8,    9,
   10,   11,   12,   65,    0,   13,   14,   97,   97,   97,
    0,    0,    0,    0,    0,    0,    0,   95,   97,   80,
   65,   65,    0,   65,   97,   97,    0,    0,    0,    0,
   97,   97,    0,    0,    0,    0,   15,   68,   68,   68,
    0,    0,    0,   97,    0,    0,    0,   68,   68,    0,
    0,    0,   97,    0,   68,   68,    0,    0,    0,    0,
   68,   68,    0,    0,    0,    0,    0,    0,    0,   97,
   97,    0,   97,   68,    0,    0,    0,    0,    0,    0,
    0,    0,   68,    0,    0,    0,   69,   69,   69,    0,
    0,    0,    0,    0,    0,    0,   69,   69,    0,   68,
   68,    0,   68,   69,   69,    0,    0,    0,    0,   69,
   69,    0,    0,    0,    0,    0,   84,   84,   84,    0,
    0,    0,   69,    0,    0,    0,   84,   84,    0,    0,
    0,   69,    0,   84,   84,    0,    0,    0,    0,   84,
   84,    0,    0,    0,    0,    0,    0,    0,   69,   69,
    0,   69,   84,  104,  104,  104,    0,    0,    0,    0,
    0,   84,    0,    0,  102,    0,    0,    0,    0,  133,
  104,  104,    0,    0,    0,    0,  104,  104,   84,   84,
    0,   84,    0,    0,  133,  133,   96,   96,   96,  104,
  133,  133,    0,    0,    0,    0,    0,   96,  104,    0,
    0,    0,    0,   96,   96,    0,    0,    0,    0,   96,
   96,    0,    0,    0,    0,  104,  104,    0,  104,    0,
    0,    0,   96,    0,    0,    0,    0,    0,    0,  133,
  133,   96,  133,    0,    0,    0,    0,    0,  103,  103,
  103,    0,    0,    0,   78,    0,    0,    0,   96,   96,
    0,   96,    0,    0,    0,  103,  103,    0,    0,   78,
   78,  103,  103,    0,    0,   78,   78,    0,    0,    0,
    0,    0,    0,    0,  103,    0,   80,    0,   78,    0,
    0,    0,    0,  103,    0,    0,    0,   78,    0,    0,
    0,   80,   80,    0,    0,    0,    0,   80,   80,    0,
  103,  103,    0,  103,   78,   78,    0,   78,   28,   29,
   80,    0,    0,    0,    0,    0,    0,    0,    0,   80,
    0,    0,    0,    0,    0,    0,   30,   31,    0,    0,
    0,    0,    0,    0,    0,    0,   80,   80,   32,   80,
   33,   34,    0,   35,   36,   37,   38,   39,   40,   41,
   42,   43,    0,    0,    0,   44,
};
static const YYINT yycheck[] = {                         10,
   44,  123,  112,   98,   99,   85,   44,  269,   10,  267,
  257,   10,  281,  257,  281,   10,  148,  264,  288,   10,
  264,   10,  258,  259,  119,  135,  136,   10,  257,   40,
   41,  289,  330,   44,  166,  264,   10,  132,   99,  134,
  284,  257,  110,  257,  258,  259,   88,  257,  264,   10,
  264,  305,  306,  307,  264,  284,  325,  327,  330,  303,
  304,  330,  104,  330,  330,  279,  280,   61,  330,  313,
  284,  132,  330,  134,  142,   10,  144,  279,  280,   10,
  160,  295,  296,   44,  313,   10,   10,  125,  168,  303,
  304,  305,  306,  307,  308,   10,  206,  313,   10,  313,
   10,  331,  257,  258,  259,  257,  258,  259,  330,  264,
  205,  330,  264,  303,  304,  329,   10,  330,  331,  257,
  258,  259,  295,  296,  279,  280,  264,  330,  331,  284,
  330,  331,  284,  330,  265,  266,   10,  330,  331,  323,
  295,  296,  330,  295,  296,  308,  284,  284,  303,  304,
  324,  303,  304,  308,  282,  283,  308,  313,  313,  330,
  331,  313,  329,  331,   47,  303,  304,  268,   40,  331,
   44,  264,  330,   10,  329,  313,  257,  329,  285,  261,
   41,  275,  330,  257,  258,  259,  257,  258,  259,  276,
  264,  329,  310,  264,  330,  301,  266,  330,  270,  271,
  272,  330,  302,   10,  330,  277,  278,  330,  330,  331,
  284,  330,  328,  284,  286,  330,   10,  261,  330,  330,
   10,  330,  330,   10,  295,  296,   10,  264,  257,  303,
  304,   10,  303,  304,  114,  162,  200,  101,  178,  313,
  140,  285,  313,  151,  217,   -1,  257,   -1,   -1,   -1,
  261,   -1,   10,  264,  265,  266,  267,  268,  329,   -1,
   -1,   -1,   -1,   -1,  275,  276,   -1,   -1,   -1,   -1,
   -1,  282,  283,   -1,  285,   -1,  267,  288,  289,   -1,
  282,  283,   10,  282,  283,   -1,  288,  282,  283,   -1,
  301,  282,  283,  282,  283,   -1,  257,  288,  289,  310,
  261,   -1,   -1,  264,  265,  266,  267,  268,  282,  283,
  301,   -1,   -1,   -1,  275,  276,  327,  328,   -1,  330,
   -1,  282,  283,   -1,  285,  327,  328,  288,  289,  328,
   -1,   10,   -1,  328,   -1,   -1,  327,  328,   -1,  330,
  301,  265,  266,  267,   -1,   -1,  270,  271,  272,  310,
   -1,  275,  276,  277,  278,   -1,   -1,  267,  282,  283,
   -1,   10,  286,   -1,  288,  289,  327,  328,   -1,  330,
   -1,   -1,  282,  283,   -1,   -1,   -1,  301,  288,  289,
   -1,   -1,   -1,  257,   -1,   -1,  310,  261,   -1,   -1,
  264,  265,  266,  267,   -1,   -1,   -1,   -1,   10,   -1,
   -1,  275,  276,  327,  328,   -1,  330,   -1,  282,  283,
   -1,  285,   10,   -1,  288,  289,   -1,  327,  328,   -1,
  330,   -1,   -1,   -1,   -1,   -1,   -1,  301,  265,  266,
  267,   10,   -1,  270,  271,  272,  310,   -1,   -1,  276,
  277,  278,   -1,   -1,   -1,  282,  283,   -1,   -1,  286,
  257,  288,  289,  327,  328,   -1,  330,  264,  265,  266,
  267,   -1,  256,  257,  301,   -1,   -1,   -1,  275,  276,
  264,   -1,   -1,  310,   -1,  282,  283,   -1,   -1,   -1,
  274,  288,  289,   10,   -1,   -1,   -1,   10,   -1,   -1,
  327,  328,   -1,  330,  301,   -1,  290,  291,  292,  293,
  294,  295,  296,  310,   -1,  299,  300,  265,  266,  267,
   -1,   -1,   -1,   -1,   -1,   -1,   -1,  275,  276,   10,
  327,  328,   -1,  330,  282,  283,   -1,   -1,   -1,   -1,
  288,  289,   -1,   -1,   -1,   -1,  330,  265,  266,  267,
   -1,   -1,   -1,  301,   -1,   -1,   -1,  275,  276,   -1,
   -1,   -1,  310,   -1,  282,  283,   -1,   -1,   -1,   -1,
  288,  289,   -1,   -1,   -1,   -1,   -1,   -1,   -1,  327,
  328,   -1,  330,  301,   -1,   -1,   -1,   -1,   -1,   -1,
   -1,   -1,  310,   -1,   -1,   -1,  265,  266,  267,   -1,
   -1,   -1,   -1,   -1,   -1,   -1,  275,  276,   -1,  327,
  328,   -1,  330,  282,  283,   -1,   -1,   -1,   -1,  288,
  289,   -1,   -1,   -1,   -1,   -1,  265,  266,  267,   -1,
   -1,   -1,  301,   -1,   -1,   -1,  275,  276,   -1,   -1,
   -1,  310,   -1,  282,  283,   -1,   -1,   -1,   -1,  288,
  289,   -1,   -1,   -1,   -1,   -1,   -1,   -1,  327,  328,
   -1,  330,  301,  265,  266,  267,   -1,   -1,   -1,   -1,
   -1,  310,   -1,   -1,  276,   -1,   -1,   -1,   -1,  267,
  282,  283,   -1,   -1,   -1,   -1,  288,  289,  327,  328,
   -1,  330,   -1,   -1,  282,  283,  265,  266,  267,  301,
  288,  289,   -1,   -1,   -1,   -1,   -1,  276,  310,   -1,
   -1,   -1,   -1,  282,  283,   -1,   -1,   -1,   -1,  288,
  289,   -1,   -1,   -1,   -1,  327,  328,   -1,  330,   -1,
   -1,   -1,  301,   -1,   -1,   -1,   -1,   -1,   -1,  327,
  328,  310,  330,   -1,   -1,   -1,   -1,   -1,  265,  266,
  267,   -1,   -1,   -1,  267,   -1,   -1,   -1,  327,  328,
   -1,  330,   -1,   -1,   -1,  282,  283,   -1,   -1,  282,
  283,  288,  289,   -1,   -1,  288,  289,   -1,   -1,   -1,
   -1,   -1,   -1,   -1,  301,   -1,  267,   -1,  301,   -1,
   -1,   -1,   -1,  310,   -1,   -1,   -1,  310,   -1,   -1,
   -1,  282,  283,   -1,   -1,   -1,   -1,  288,  289,   -1,
  327,  328,   -1,  330,  327,  328,   -1,  330,  279,  280,
  301,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,  310,
   -1,   -1,   -1,   -1,   -1,   -1,  297,  298,   -1,   -1,
   -1,   -1,   -1,   -1,   -1,   -1,  327,  328,  309,  330,
  311,  312,   -1,  314,  315,  316,  317,  318,  319,  320,
  321,  322,   -1,   -1,   -1,  326,
};
#define YYFINAL 1
#ifndef YYDEBUG
#define YYDEBUG 0
#endif
#define YYMAXTOKEN 331
#define YYUNDFTOKEN 396
#define YYTRANSLATE(a) ((a) > YYMAXTOKEN ? YYUNDFTOKEN : (a))
#if YYDEBUG
static const char *const yyname[] = {

"end-of-file",0,0,0,0,0,0,0,0,0,"'\\n'",0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
0,0,0,0,0,0,0,0,0,"'('","')'",0,0,"','",0,0,"'/'",0,0,0,0,0,0,0,0,0,0,0,0,0,
"'='",0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,"'{'",0,"'}'",0,0,0,0,0,0,0,0,0,
0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
0,0,"FROM","ESP","AH","IN","PEER","ON","OUT","TO","SRCID","DSTID","PSK","PORT",
"FILENAME","AUTHXF","PRFXF","ENCXF","ERROR","IKEV2","IKESA","CHILDSA","ESN",
"NOESN","PASSIVE","ACTIVE","ANY","TAG","TAP","PROTO","LOCAL","GROUP","NAME",
"CONFIG","EAP","USER","IKEV1","FLOW","SA","TCPMD5","TUNNEL","TRANSPORT",
"COUPLE","DECOUPLE","SET","INCLUDE","LIFETIME","BYTES","INET","INET6","QUICK",
"SKIP","DEFAULT","IPCOMP","OCSP","IKELIFETIME","MOBIKE","NOMOBIKE","RDOMAIN",
"FRAGMENTATION","NOFRAGMENTATION","DPD_CHECK_INTERVAL","ENFORCESINGLEIKESA",
"NOENFORCESINGLEIKESA","STICKYADDRESS","NOSTICKYADDRESS","VENDORID",
"NOVENDORID","TOLERATE","MAXAGE","DYNAMIC","CERTPARTIALCHAIN","REQUEST","IFACE",
"NATT","STRING","NUMBER",0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
"illegal-symbol",
};
static const char *const yyrule[] = {
"$accept : grammar",
"grammar :",
"grammar : grammar include '\\n'",
"grammar : grammar '\\n'",
"grammar : grammar set '\\n'",
"grammar : grammar user '\\n'",
"grammar : grammar ikev2rule '\\n'",
"grammar : grammar varset '\\n'",
"grammar : grammar otherrule skipline '\\n'",
"grammar : grammar error '\\n'",
"comma : ','",
"comma :",
"include : INCLUDE STRING",
"set : SET ACTIVE",
"set : SET PASSIVE",
"set : SET COUPLE",
"set : SET DECOUPLE",
"set : SET FRAGMENTATION",
"set : SET NOFRAGMENTATION",
"set : SET MOBIKE",
"set : SET NOMOBIKE",
"set : SET VENDORID",
"set : SET NOVENDORID",
"set : SET ENFORCESINGLEIKESA",
"set : SET NOENFORCESINGLEIKESA",
"set : SET STICKYADDRESS",
"set : SET NOSTICKYADDRESS",
"set : SET OCSP STRING",
"set : SET OCSP STRING TOLERATE time_spec",
"set : SET OCSP STRING TOLERATE time_spec MAXAGE time_spec",
"set : SET CERTPARTIALCHAIN",
"set : SET DPD_CHECK_INTERVAL NUMBER",
"user : USER STRING STRING",
"ikev2rule : IKEV2 name ikeflags satype af proto rdomain hosts_list peers ike_sas child_sas ids ikelifetime lifetime ikeauth ikecfg iface filters",
"ikecfg :",
"ikecfg : ikecfgvals",
"ikecfgvals : cfg",
"ikecfgvals : ikecfgvals cfg",
"cfg : CONFIG STRING host_spec",
"cfg : REQUEST STRING anyhost",
"name :",
"name : STRING",
"satype :",
"satype : ESP",
"satype : AH",
"af :",
"af : INET",
"af : INET6",
"proto :",
"proto : PROTO protoval",
"proto : PROTO '{' proto_list '}'",
"proto_list : protoval",
"proto_list : proto_list comma protoval",
"protoval : STRING",
"protoval : NUMBER",
"rdomain :",
"rdomain : RDOMAIN NUMBER",
"hosts_list : hosts",
"hosts_list : hosts_list comma hosts",
"hosts : FROM host port TO host port",
"hosts : TO host port FROM host port",
"port :",
"port : PORT portval",
"portval : STRING",
"portval : NUMBER",
"peers :",
"peers : PEER anyhost LOCAL anyhost",
"peers : LOCAL anyhost PEER anyhost",
"peers : PEER anyhost",
"peers : LOCAL anyhost",
"anyhost : host_spec",
"anyhost : ANY",
"host_spec : STRING",
"host_spec : STRING '/' NUMBER",
"host : host_spec",
"host : host_spec '(' host_spec ')'",
"host : ANY",
"host : DYNAMIC",
"ids :",
"ids : SRCID id DSTID id",
"ids : SRCID id",
"ids : DSTID id",
"id : STRING",
"$$1 :",
"transforms : $$1 transforms_l",
"transforms :",
"transforms_l : transforms_l transform",
"transforms_l : transform",
"transform : AUTHXF STRING",
"transform : ENCXF STRING",
"transform : PRFXF STRING",
"transform : GROUP STRING",
"transform : transform_esn",
"transform_esn : ESN",
"transform_esn : NOESN",
"$$2 :",
"ike_sas : $$2 ike_sas_l",
"ike_sas :",
"ike_sas_l : ike_sas_l ike_sa",
"ike_sas_l : ike_sa",
"$$3 :",
"ike_sa : IKESA $$3 transforms",
"$$4 :",
"child_sas : $$4 child_sas_l",
"child_sas :",
"child_sas_l : child_sas_l child_sa",
"child_sas_l : child_sa",
"$$5 :",
"child_sa : CHILDSA $$5 transforms",
"ikeflags : ikematch ikemode ipcomp tmode natt_force",
"ikematch :",
"ikematch : QUICK",
"ikematch : SKIP",
"ikematch : DEFAULT",
"ikemode :",
"ikemode : PASSIVE",
"ikemode : ACTIVE",
"ipcomp :",
"ipcomp : IPCOMP",
"tmode :",
"tmode : TUNNEL",
"tmode : TRANSPORT",
"natt_force :",
"natt_force : NATT",
"ikeauth :",
"ikeauth : PSK keyspec",
"ikeauth : EAP STRING",
"ikeauth : STRING",
"byte_spec : NUMBER",
"byte_spec : STRING",
"time_spec : NUMBER",
"time_spec : STRING",
"lifetime :",
"lifetime : LIFETIME time_spec",
"lifetime : LIFETIME time_spec BYTES byte_spec",
"ikelifetime :",
"ikelifetime : IKELIFETIME time_spec",
"keyspec : STRING",
"keyspec : FILENAME STRING",
"$$6 :",
"filters : $$6 filters_l",
"filters :",
"filters_l : filters_l filter",
"filters_l : filter",
"filter : TAG STRING",
"filter : TAP STRING",
"iface :",
"iface : IFACE STRING",
"string : string STRING",
"string : STRING",
"varset : STRING '=' string",
"otherrule : IKEV1",
"otherrule : sarule",
"otherrule : FLOW",
"otherrule : TCPMD5",
"sarule : SA",
"sarule : FROM",
"sarule : TO",
"sarule : TUNNEL",
"sarule : TRANSPORT",
"skipline :",

};
#endif

#if YYDEBUG
int      yydebug;
#endif

int      yyerrflag;
int      yychar;
YYSTYPE  yyval;
YYSTYPE  yylval;
int      yynerrs;

/* define the initial stack-sizes */
#ifdef YYSTACKSIZE
#undef YYMAXDEPTH
#define YYMAXDEPTH  YYSTACKSIZE
#else
#ifdef YYMAXDEPTH
#define YYSTACKSIZE YYMAXDEPTH
#else
#define YYSTACKSIZE 10000
#define YYMAXDEPTH  10000
#endif
#endif

#define YYINITSTACKSIZE 200

typedef struct {
    unsigned stacksize;
    YYINT    *s_base;
    YYINT    *s_mark;
    YYINT    *s_last;
    YYSTYPE  *l_base;
    YYSTYPE  *l_mark;
} YYSTACKDATA;
/* variables for the parser stack */
static YYSTACKDATA yystack;
#line 1321 "parse.y"

struct keywords {
	const char	*k_name;
	int		 k_val;
};

void
copy_sockaddrtoipa(struct ipsec_addr_wrap *ipa, struct sockaddr *sa)
{
	if (sa->sa_family == AF_INET6)
		memcpy(&ipa->address, sa, sizeof(struct sockaddr_in6));
	else if (sa->sa_family == AF_INET)
		memcpy(&ipa->address, sa, sizeof(struct sockaddr_in));
	else
		warnx("unhandled af %d", sa->sa_family);
}

int
yyerror(const char *fmt, ...)
{
	va_list		 ap;

	file->errors++;
	va_start(ap, fmt);
	fprintf(stderr, "%s: %d: ", file->name, yylval.lineno);
	vfprintf(stderr, fmt, ap);
	fprintf(stderr, "\n");
	va_end(ap);
	return (0);
}

int
kw_cmp(const void *k, const void *e)
{
	return (strcmp(k, ((const struct keywords *)e)->k_name));
}

int
lookup(char *s)
{
	/* this has to be sorted always */
	static const struct keywords keywords[] = {
		{ "active",		ACTIVE },
		{ "ah",			AH },
		{ "any",		ANY },
		{ "auth",		AUTHXF },
		{ "bytes",		BYTES },
		{ "cert_partial_chain",	CERTPARTIALCHAIN },
		{ "childsa",		CHILDSA },
		{ "config",		CONFIG },
		{ "couple",		COUPLE },
		{ "decouple",		DECOUPLE },
		{ "default",		DEFAULT },
		{ "dpd_check_interval",	DPD_CHECK_INTERVAL },
		{ "dstid",		DSTID },
		{ "dynamic",		DYNAMIC },
		{ "eap",		EAP },
		{ "enc",		ENCXF },
		{ "enforcesingleikesa",	ENFORCESINGLEIKESA },
		{ "esn",		ESN },
		{ "esp",		ESP },
		{ "file",		FILENAME },
		{ "flow",		FLOW },
		{ "fragmentation",	FRAGMENTATION },
		{ "from",		FROM },
		{ "group",		GROUP },
		{ "iface",		IFACE },
		{ "ike",		IKEV1 },
		{ "ikelifetime",	IKELIFETIME },
		{ "ikesa",		IKESA },
		{ "ikev2",		IKEV2 },
		{ "include",		INCLUDE },
		{ "inet",		INET },
		{ "inet6",		INET6 },
		{ "ipcomp",		IPCOMP },
		{ "lifetime",		LIFETIME },
		{ "local",		LOCAL },
		{ "maxage",		MAXAGE },
		{ "mobike",		MOBIKE },
		{ "name",		NAME },
		{ "natt",		NATT },
		{ "noenforcesingleikesa",	NOENFORCESINGLEIKESA },
		{ "noesn",		NOESN },
		{ "nofragmentation",	NOFRAGMENTATION },
		{ "nomobike",		NOMOBIKE },
		{ "nostickyaddress",	NOSTICKYADDRESS },
		{ "novendorid",		NOVENDORID },
		{ "ocsp",		OCSP },
		{ "passive",		PASSIVE },
		{ "peer",		PEER },
		{ "port",		PORT },
		{ "prf",		PRFXF },
		{ "proto",		PROTO },
		{ "psk",		PSK },
		{ "quick",		QUICK },
		{ "rdomain",		RDOMAIN },
		{ "request",		REQUEST },
		{ "sa",			SA },
		{ "set",		SET },
		{ "skip",		SKIP },
		{ "srcid",		SRCID },
		{ "stickyaddress",	STICKYADDRESS },
		{ "tag",		TAG },
		{ "tap",		TAP },
		{ "tcpmd5",		TCPMD5 },
		{ "to",			TO },
		{ "tolerate",		TOLERATE },
		{ "transport",		TRANSPORT },
		{ "tunnel",		TUNNEL },
		{ "user",		USER },
		{ "vendorid",		VENDORID }
	};
	const struct keywords	*p;

	p = bsearch(s, keywords, sizeof(keywords)/sizeof(keywords[0]),
	    sizeof(keywords[0]), kw_cmp);

	if (p) {
		if (debug > 1)
			fprintf(stderr, "%s: %d\n", s, p->k_val);
		return (p->k_val);
	} else {
		if (debug > 1)
			fprintf(stderr, "string: %s\n", s);
		return (STRING);
	}
}

#define START_EXPAND	1
#define DONE_EXPAND	2

static int	expanding;

int
igetc(void)
{
	int	c;

	while (1) {
		if (file->ungetpos > 0)
			c = file->ungetbuf[--file->ungetpos];
		else
			c = getc(file->stream);

		if (c == START_EXPAND)
			expanding = 1;
		else if (c == DONE_EXPAND)
			expanding = 0;
		else
			break;
	}
	return (c);
}

int
lgetc(int quotec)
{
	int		c, next;

	if (quotec) {
		if ((c = igetc()) == EOF) {
			yyerror("reached end of file while parsing "
			    "quoted string");
			if (file == topfile || popfile() == EOF)
				return (EOF);
			return (quotec);
		}
		return (c);
	}

	while ((c = igetc()) == '\\') {
		next = igetc();
		if (next != '\n') {
			c = next;
			break;
		}
		yylval.lineno = file->lineno;
		file->lineno++;
	}

	while (c == EOF) {
		/*
		 * Fake EOL when hit EOF for the first time. This gets line
		 * count right if last line in included file is syntactically
		 * invalid and has no newline.
		 */
		if (file->eof_reached == 0) {
			file->eof_reached = 1;
			return ('\n');
		}
		while (c == EOF) {
			if (file == topfile || popfile() == EOF)
				return (EOF);
			c = igetc();
		}
	}
	return (c);
}

void
lungetc(int c)
{
	if (c == EOF)
		return;

	if (file->ungetpos >= file->ungetsize) {
		void *p = reallocarray(file->ungetbuf, file->ungetsize, 2);
		if (p == NULL)
			err(1, "lungetc");
		file->ungetbuf = p;
		file->ungetsize *= 2;
	}
	file->ungetbuf[file->ungetpos++] = c;
}

int
findeol(void)
{
	int	c;

	/* skip to either EOF or the first real EOL */
	while (1) {
		c = lgetc(0);
		if (c == '\n') {
			file->lineno++;
			break;
		}
		if (c == EOF)
			break;
	}
	return (ERROR);
}

int
yylex(void)
{
	char	 buf[8096];
	char	*p, *val;
	int	 quotec, next, c;
	int	 token;

top:
	p = buf;
	while ((c = lgetc(0)) == ' ' || c == '\t')
		; /* nothing */

	yylval.lineno = file->lineno;
	if (c == '#')
		while ((c = lgetc(0)) != '\n' && c != EOF)
			; /* nothing */
	if (c == '$' && !expanding) {
		while (1) {
			if ((c = lgetc(0)) == EOF)
				return (0);

			if (p + 1 >= buf + sizeof(buf) - 1) {
				yyerror("string too long");
				return (findeol());
			}
			if (isalnum(c) || c == '_') {
				*p++ = c;
				continue;
			}
			*p = '\0';
			lungetc(c);
			break;
		}
		val = symget(buf);
		if (val == NULL) {
			yyerror("macro '%s' not defined", buf);
			return (findeol());
		}
		p = val + strlen(val) - 1;
		lungetc(DONE_EXPAND);
		while (p >= val) {
			lungetc((unsigned char)*p);
			p--;
		}
		lungetc(START_EXPAND);
		goto top;
	}

	switch (c) {
	case '\'':
	case '"':
		quotec = c;
		while (1) {
			if ((c = lgetc(quotec)) == EOF)
				return (0);
			if (c == '\n') {
				file->lineno++;
				continue;
			} else if (c == '\\') {
				if ((next = lgetc(quotec)) == EOF)
					return (0);
				if (next == quotec || next == ' ' ||
				    next == '\t')
					c = next;
				else if (next == '\n') {
					file->lineno++;
					continue;
				} else
					lungetc(next);
			} else if (c == quotec) {
				*p = '\0';
				break;
			} else if (c == '\0') {
				yyerror("syntax error");
				return (findeol());
			}
			if (p + 1 >= buf + sizeof(buf) - 1) {
				yyerror("string too long");
				return (findeol());
			}
			*p++ = c;
		}
		yylval.v.string = strdup(buf);
		if (yylval.v.string == NULL)
			err(1, "%s", __func__);
		return (STRING);
	}

#define allowed_to_end_number(x) \
	(isspace(x) || x == ')' || x ==',' || x == '/' || x == '}' || x == '=')

	if (c == '-' || isdigit(c)) {
		do {
			*p++ = c;
			if ((size_t)(p-buf) >= sizeof(buf)) {
				yyerror("string too long");
				return (findeol());
			}
		} while ((c = lgetc(0)) != EOF && isdigit(c));
		lungetc(c);
		if (p == buf + 1 && buf[0] == '-')
			goto nodigits;
		if (c == EOF || allowed_to_end_number(c)) {
			const char *errstr = NULL;

			*p = '\0';
			yylval.v.number = strtonum(buf, LLONG_MIN,
			    LLONG_MAX, &errstr);
			if (errstr) {
				yyerror("\"%s\" invalid number: %s",
				    buf, errstr);
				return (findeol());
			}
			return (NUMBER);
		} else {
nodigits:
			while (p > buf + 1)
				lungetc((unsigned char)*--p);
			c = (unsigned char)*--p;
			if (c == '-')
				return (c);
		}
	}

#define allowed_in_string(x) \
	(isalnum(x) || (ispunct(x) && x != '(' && x != ')' && \
	x != '{' && x != '}' && x != '<' && x != '>' && \
	x != '!' && x != '=' && x != '/' && x != '#' && \
	x != ','))

	if (isalnum(c) || c == ':' || c == '_' || c == '*') {
		do {
			*p++ = c;
			if ((size_t)(p-buf) >= sizeof(buf)) {
				yyerror("string too long");
				return (findeol());
			}
		} while ((c = lgetc(0)) != EOF && (allowed_in_string(c)));
		lungetc(c);
		*p = '\0';
		if ((token = lookup(buf)) == STRING)
			if ((yylval.v.string = strdup(buf)) == NULL)
				err(1, "%s", __func__);
		return (token);
	}
	if (c == '\n') {
		yylval.lineno = file->lineno;
		file->lineno++;
	}
	if (c == EOF)
		return (0);
	return (c);
}

int
check_file_secrecy(int fd, const char *fname)
{
	struct stat	st;

	if (fstat(fd, &st)) {
		warn("cannot stat %s", fname);
		return (-1);
	}
	if (st.st_uid != 0 && st.st_uid != getuid()) {
		warnx("%s: owner not root or current user", fname);
		return (-1);
	}
	if (st.st_mode & (S_IWGRP | S_IXGRP | S_IRWXO)) {
		warnx("%s: group writable or world read/writable", fname);
		return (-1);
	}
	return (0);
}

struct file *
pushfile(const char *name, int secret)
{
	struct file	*nfile;

	if ((nfile = calloc(1, sizeof(struct file))) == NULL) {
		warn("%s", __func__);
		return (NULL);
	}
	if ((nfile->name = strdup(name)) == NULL) {
		warn("%s", __func__);
		free(nfile);
		return (NULL);
	}
	if (TAILQ_FIRST(&files) == NULL && strcmp(nfile->name, "-") == 0) {
		nfile->stream = stdin;
		free(nfile->name);
		if ((nfile->name = strdup("stdin")) == NULL) {
			warn("%s", __func__);
			free(nfile);
			return (NULL);
		}
	} else if ((nfile->stream = fopen(nfile->name, "r")) == NULL) {
		warn("%s: %s", __func__, nfile->name);
		free(nfile->name);
		free(nfile);
		return (NULL);
	} else if (secret &&
	    check_file_secrecy(fileno(nfile->stream), nfile->name)) {
		fclose(nfile->stream);
		free(nfile->name);
		free(nfile);
		return (NULL);
	}
	nfile->lineno = TAILQ_EMPTY(&files) ? 1 : 0;
	nfile->ungetsize = 16;
	nfile->ungetbuf = malloc(nfile->ungetsize);
	if (nfile->ungetbuf == NULL) {
		warn("%s", __func__);
		fclose(nfile->stream);
		free(nfile->name);
		free(nfile);
		return (NULL);
	}
	TAILQ_INSERT_TAIL(&files, nfile, entry);
	return (nfile);
}

int
popfile(void)
{
	struct file	*prev;

	if ((prev = TAILQ_PREV(file, files, entry)) != NULL)
		prev->errors += file->errors;

	TAILQ_REMOVE(&files, file, entry);
	fclose(file->stream);
	free(file->name);
	free(file->ungetbuf);
	free(file);
	file = prev;

	return (file ? 0 : EOF);
}

int
parse_config(const char *filename, struct iked *x_env)
{
	struct sym	*sym;
	int		 errors = 0;

	env = x_env;
	rules = 0;

	if ((file = pushfile(filename, 1)) == NULL)
		return (-1);
	topfile = file;

	free(ocsp_url);

	mobike = 1;
	enforcesingleikesa = stickyaddress = 0;
	cert_partial_chain = decouple = passive = 0;
	ocsp_tolerate = 0;
	ocsp_url = NULL;
	ocsp_maxage = -1;
	fragmentation = 0;
	dpd_interval = IKED_IKE_SA_ALIVE_TIMEOUT;
	decouple = passive = 0;
	ocsp_url = NULL;

	if (env->sc_opts & IKED_OPT_PASSIVE)
		passive = 1;

	yyparse();
	errors = file->errors;
	popfile();

	env->sc_passive = passive ? 1 : 0;
	env->sc_decoupled = decouple ? 1 : 0;
	env->sc_mobike = mobike;
	env->sc_enforcesingleikesa = enforcesingleikesa;
	env->sc_stickyaddress = stickyaddress;
	env->sc_frag = fragmentation;
	env->sc_alive_timeout = dpd_interval;
	env->sc_ocsp_url = ocsp_url;
	env->sc_ocsp_tolerate = ocsp_tolerate;
	env->sc_ocsp_maxage = ocsp_maxage;
	env->sc_cert_partial_chain = cert_partial_chain;
	env->sc_vendorid = vendorid;

	if (!rules)
		log_warnx("%s: no valid configuration rules found",
		    filename);
	else
		log_debug("%s: loaded %d configuration rules",
		    filename, rules);

	/* Free macros and check which have not been used. */
	while ((sym = TAILQ_FIRST(&symhead))) {
		if (!sym->used)
			log_debug("warning: macro '%s' not "
			    "used\n", sym->nam);
		free(sym->nam);
		free(sym->val);
		TAILQ_REMOVE(&symhead, sym, entry);
		free(sym);
	}

	iaw_free(iftab);
	iftab = NULL;

	return (errors ? -1 : 0);
}

int
symset(const char *nam, const char *val, int persist)
{
	struct sym	*sym;

	TAILQ_FOREACH(sym, &symhead, entry) {
		if (strcmp(nam, sym->nam) == 0)
			break;
	}

	if (sym != NULL) {
		if (sym->persist == 1)
			return (0);
		else {
			free(sym->nam);
			free(sym->val);
			TAILQ_REMOVE(&symhead, sym, entry);
			free(sym);
		}
	}
	if ((sym = calloc(1, sizeof(*sym))) == NULL)
		return (-1);

	sym->nam = strdup(nam);
	if (sym->nam == NULL) {
		free(sym);
		return (-1);
	}
	sym->val = strdup(val);
	if (sym->val == NULL) {
		free(sym->nam);
		free(sym);
		return (-1);
	}
	sym->used = 0;
	sym->persist = persist;
	TAILQ_INSERT_TAIL(&symhead, sym, entry);
	return (0);
}

int
cmdline_symset(char *s)
{
	char	*sym, *val;
	int	ret;

	if ((val = strrchr(s, '=')) == NULL)
		return (-1);

	sym = strndup(s, val - s);
	if (sym == NULL)
		err(1, "%s", __func__);
	ret = symset(sym, val + 1, 1);
	free(sym);

	return (ret);
}

char *
symget(const char *nam)
{
	struct sym	*sym;

	TAILQ_FOREACH(sym, &symhead, entry) {
		if (strcmp(nam, sym->nam) == 0) {
			sym->used = 1;
			return (sym->val);
		}
	}
	return (NULL);
}

uint8_t
x2i(unsigned char *s)
{
	char	ss[3];

	ss[0] = s[0];
	ss[1] = s[1];
	ss[2] = 0;

	if (!isxdigit(s[0]) || !isxdigit(s[1])) {
		yyerror("keys need to be specified in hex digits");
		return (-1);
	}
	return ((uint8_t)strtoul(ss, NULL, 16));
}

int
parsekey(unsigned char *hexkey, size_t len, struct iked_auth *auth)
{
	unsigned int	  i;

	bzero(auth, sizeof(*auth));
	if ((len / 2) > sizeof(auth->auth_data))
		return (-1);
	auth->auth_length = len / 2;

	for (i = 0; i < auth->auth_length; i++)
		auth->auth_data[i] = x2i(hexkey + 2 * i);

	return (0);
}

int
parsekeyfile(char *filename, struct iked_auth *auth)
{
	struct stat	 sb;
	int		 fd, ret;
	unsigned char	*hex;

	if ((fd = open(filename, O_RDONLY)) == -1)
		err(1, "open %s", filename);
	if (check_file_secrecy(fd, filename) == -1)
		exit(1);
	if (fstat(fd, &sb) == -1)
		err(1, "parsekeyfile: stat %s", filename);
	if ((sb.st_size > KEYSIZE_LIMIT) || (sb.st_size == 0))
		errx(1, "%s: key too %s", filename, sb.st_size ? "large" :
		    "small");
	if ((hex = calloc(sb.st_size, sizeof(unsigned char))) == NULL)
		err(1, "parsekeyfile: calloc");
	if (read(fd, hex, sb.st_size) < sb.st_size)
		err(1, "parsekeyfile: read");
	close(fd);
	ret = parsekey(hex, sb.st_size, auth);
	free(hex);
	return (ret);
}

int
get_id_type(char *string)
{
	struct in6_addr ia;

	if (string == NULL)
		return (IKEV2_ID_NONE);

	if (*string == '/')
		return (IKEV2_ID_ASN1_DN);
	else if (inet_pton(AF_INET, string, &ia) == 1)
		return (IKEV2_ID_IPV4);
	else if (inet_pton(AF_INET6, string, &ia) == 1)
		return (IKEV2_ID_IPV6);
	else if (strchr(string, '@'))
		return (IKEV2_ID_UFQDN);
	else
		return (IKEV2_ID_FQDN);
}

struct ipsec_addr_wrap *
host(const char *s)
{
	struct ipsec_addr_wrap	*ipa = NULL;
	int			 mask = -1;
	char			*p, *ps;
	const char		*errstr;

	if ((ps = strdup(s)) == NULL)
		err(1, "%s: strdup", __func__);

	if ((p = strchr(ps, '/')) != NULL) {
		mask = strtonum(p+1, 0, 128, &errstr);
		if (errstr) {
			fprintf(stderr, "netmask is %s: %s\n", errstr, p);
			goto error;
		}
		p[0] = '\0';
	}

	if ((ipa = host_if(ps, mask)) == NULL &&
	    (ipa = host_ip(ps, mask)) == NULL &&
	    (ipa = host_dns(ps, mask)) == NULL)
		fprintf(stderr, "no IP address found for %s\n", s);

error:
	free(ps);
	return (ipa);
}

struct ipsec_addr_wrap *
host_ip(const char *s, int mask)
{
	struct ipsec_addr_wrap	*ipa = NULL;
	struct addrinfo		 hints, *res;
	char			 hbuf[NI_MAXHOST];

	bzero(&hints, sizeof(struct addrinfo));
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_DGRAM; /*dummy*/
	hints.ai_flags = AI_NUMERICHOST;
	if (getaddrinfo(s, NULL, &hints, &res))
		return (NULL);
	if (res->ai_next)
		err(1, "%s: %s expanded to multiple item", __func__, s);

	ipa = calloc(1, sizeof(struct ipsec_addr_wrap));
	if (ipa == NULL)
		err(1, "%s", __func__);
	ipa->af = res->ai_family;
	copy_sockaddrtoipa(ipa, res->ai_addr);
	ipa->next = NULL;
	ipa->tail = ipa;

	set_ipmask(ipa, mask);
	if (getnameinfo(res->ai_addr, res->ai_addrlen,
	    hbuf, sizeof(hbuf), NULL, 0, NI_NUMERICHOST)) {
		errx(1, "could not get a numeric hostname");
	}

	if (mask > -1) {
		ipa->netaddress = 1;
		if (asprintf(&ipa->name, "%s/%d", hbuf, mask) == -1)
			err(1, "%s", __func__);
	} else {
		if ((ipa->name = strdup(hbuf)) == NULL)
			err(1, "%s", __func__);
	}

	freeaddrinfo(res);

	return (ipa);
}

struct ipsec_addr_wrap *
host_dns(const char *s, int mask)
{
	struct ipsec_addr_wrap	*ipa = NULL, *head = NULL;
	struct addrinfo		 hints, *res0, *res;
	int			 error;
	char			 hbuf[NI_MAXHOST];

	bzero(&hints, sizeof(struct addrinfo));
	hints.ai_family = PF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_flags = AI_ADDRCONFIG;
	error = getaddrinfo(s, NULL, &hints, &res0);
	if (error)
		return (NULL);

	for (res = res0; res; res = res->ai_next) {
		if (res->ai_family != AF_INET && res->ai_family != AF_INET6)
			continue;

		ipa = calloc(1, sizeof(struct ipsec_addr_wrap));
		if (ipa == NULL)
			err(1, "%s", __func__);
		copy_sockaddrtoipa(ipa, res->ai_addr);
		error = getnameinfo(res->ai_addr, res->ai_addrlen, hbuf,
		    sizeof(hbuf), NULL, 0, NI_NUMERICHOST);
		if (error)
			err(1, "host_dns: getnameinfo");
		ipa->name = strdup(hbuf);
		if (ipa->name == NULL)
			err(1, "%s", __func__);
		ipa->af = res->ai_family;
		ipa->next = NULL;
		ipa->tail = ipa;
		if (head == NULL)
			head = ipa;
		else {
			head->tail->next = ipa;
			head->tail = ipa;
		}

		/*
		 * XXX for now, no netmask support for IPv6.
		 * but since there's no way to specify address family, once you
		 * have IPv6 address on a host, you cannot use dns/netmask
		 * syntax.
		 */
		if (ipa->af == AF_INET)
			set_ipmask(ipa, mask == -1 ? 32 : mask);
		else
			if (mask != -1)
				err(1, "host_dns: cannot apply netmask "
				    "on non-IPv4 address");
	}
	freeaddrinfo(res0);

	return (head);
}

struct ipsec_addr_wrap *
host_if(const char *s, int mask)
{
	struct ipsec_addr_wrap *ipa = NULL;

	if (ifa_exists(s))
		ipa = ifa_lookup(s);

	return (ipa);
}

struct ipsec_addr_wrap *
host_any(void)
{
	struct ipsec_addr_wrap	*ipa;

	ipa = calloc(1, sizeof(struct ipsec_addr_wrap));
	if (ipa == NULL)
		err(1, "%s", __func__);
	ipa->af = AF_UNSPEC;
	ipa->netaddress = 1;
	ipa->tail = ipa;
	ipa->type = IPSEC_ADDR_ANY;
	return (ipa);
}

struct ipsec_addr_wrap *
host_dynamic(void)
{
	struct ipsec_addr_wrap	*ipa;

	ipa = calloc(1, sizeof(struct ipsec_addr_wrap));
	if (ipa == NULL)
		err(1, "%s", __func__);
	ipa->af = AF_UNSPEC;
	ipa->tail = ipa;
	ipa->type = IPSEC_ADDR_DYNAMIC;
	return (ipa);
}

void
ifa_load(void)
{
	struct ifaddrs		*ifap, *ifa;
	struct ipsec_addr_wrap	*n = NULL, *h = NULL;
	struct sockaddr_in	*sa_in;
	struct sockaddr_in6	*sa_in6;

	if (getifaddrs(&ifap) == -1)
		err(1, "ifa_load: getifaddrs");

	for (ifa = ifap; ifa; ifa = ifa->ifa_next) {
		if (ifa->ifa_addr == NULL ||
		    !(ifa->ifa_addr->sa_family == AF_INET ||
		    ifa->ifa_addr->sa_family == AF_INET6 ||
		    ifa->ifa_addr->sa_family == AF_LINK))
			continue;
		n = calloc(1, sizeof(struct ipsec_addr_wrap));
		if (n == NULL)
			err(1, "%s", __func__);
		n->af = ifa->ifa_addr->sa_family;
		if ((n->name = strdup(ifa->ifa_name)) == NULL)
			err(1, "%s", __func__);
		if (n->af == AF_INET) {
			sa_in = (struct sockaddr_in *)ifa->ifa_addr;
			memcpy(&n->address, sa_in, sizeof(*sa_in));
			sa_in = (struct sockaddr_in *)ifa->ifa_netmask;
			n->mask = mask2prefixlen((struct sockaddr *)sa_in);
		} else if (n->af == AF_INET6) {
			sa_in6 = (struct sockaddr_in6 *)ifa->ifa_addr;
			memcpy(&n->address, sa_in6, sizeof(*sa_in6));
			sa_in6 = (struct sockaddr_in6 *)ifa->ifa_netmask;
			n->mask = mask2prefixlen6((struct sockaddr *)sa_in6);
		}
		n->next = NULL;
		n->tail = n;
		if (h == NULL)
			h = n;
		else {
			h->tail->next = n;
			h->tail = n;
		}
	}

	iftab = h;
	freeifaddrs(ifap);
}

int
ifa_exists(const char *ifa_name)
{
	struct ipsec_addr_wrap	*n;
#ifdef __OpenBSD__
	struct ifgroupreq	 ifgr;
#endif
	int			 s;

	if (iftab == NULL)
		ifa_load();

	/* check wether this is a group */
	if ((s = socket(AF_INET, SOCK_DGRAM, 0)) == -1)
		err(1, "ifa_exists: socket");
#ifdef __OpenBSD__
	bzero(&ifgr, sizeof(ifgr));
	strlcpy(ifgr.ifgr_name, ifa_name, sizeof(ifgr.ifgr_name));
	if (ioctl(s, SIOCGIFGMEMB, (caddr_t)&ifgr) == 0) {
		close(s);
		return (1);
	}
#endif
	close(s);

	for (n = iftab; n; n = n->next) {
		if (n->af == AF_LINK && !strncmp(n->name, ifa_name,
		    IFNAMSIZ))
			return (1);
	}

	return (0);
}

#ifdef __OpenBSD__
struct ipsec_addr_wrap *
ifa_grouplookup(const char *ifa_name)
{
	struct ifg_req		*ifg;
	struct ifgroupreq	 ifgr;
	int			 s;
	size_t			 len;
	struct ipsec_addr_wrap	*n, *h = NULL, *hn;

	if ((s = socket(AF_INET, SOCK_DGRAM, 0)) == -1)
		err(1, "socket");
	bzero(&ifgr, sizeof(ifgr));
	strlcpy(ifgr.ifgr_name, ifa_name, sizeof(ifgr.ifgr_name));
	if (ioctl(s, SIOCGIFGMEMB, (caddr_t)&ifgr) == -1) {
		close(s);
		return (NULL);
	}

	len = ifgr.ifgr_len;
	if ((ifgr.ifgr_groups = calloc(1, len)) == NULL)
		err(1, "%s", __func__);
	if (ioctl(s, SIOCGIFGMEMB, (caddr_t)&ifgr) == -1)
		err(1, "ioctl");

	for (ifg = ifgr.ifgr_groups; ifg && len >= sizeof(struct ifg_req);
	    ifg++) {
		len -= sizeof(struct ifg_req);
		if ((n = ifa_lookup(ifg->ifgrq_member)) == NULL)
			continue;
		if (h == NULL)
			h = n;
		else {
			for (hn = h; hn->next != NULL; hn = hn->next)
				;	/* nothing */
			hn->next = n;
			n->tail = hn;
		}
	}
	free(ifgr.ifgr_groups);
	close(s);

	return (h);
}
#endif

struct ipsec_addr_wrap *
ifa_lookup(const char *ifa_name)
{
	struct ipsec_addr_wrap	*p = NULL, *h = NULL, *n = NULL;
	struct sockaddr_in6	*in6;
	uint8_t			*s6;

	if (iftab == NULL)
		ifa_load();

#ifdef __OpenBSD__
	if ((n = ifa_grouplookup(ifa_name)) != NULL)
		return (n);
#endif

	for (p = iftab; p; p = p->next) {
		if (p->af != AF_INET && p->af != AF_INET6)
			continue;
		if (strncmp(p->name, ifa_name, IFNAMSIZ))
			continue;
		n = calloc(1, sizeof(struct ipsec_addr_wrap));
		if (n == NULL)
			err(1, "%s", __func__);
		memcpy(n, p, sizeof(struct ipsec_addr_wrap));
		if ((n->name = strdup(p->name)) == NULL)
			err(1, "%s", __func__);
		switch (n->af) {
		case AF_INET:
			set_ipmask(n, 32);
			break;
		case AF_INET6:
			in6 = (struct sockaddr_in6 *)&n->address;
			s6 = (uint8_t *)&in6->sin6_addr.s6_addr;

			/* route/show.c and bgpd/util.c give KAME credit */
			if (IN6_IS_ADDR_LINKLOCAL(&in6->sin6_addr)) {
				uint16_t	 tmp16;

				/* for now we can not handle link local,
				 * therefore bail for now
				 */
				free(n->name);
				free(n);
				continue;

				memcpy(&tmp16, &s6[2], sizeof(tmp16));
				/* use this when we support link-local
				 * n->??.scopeid = ntohs(tmp16);
				 */
				s6[2] = 0;
				s6[3] = 0;
			}
			set_ipmask(n, 128);
			break;
		}

		n->next = NULL;
		n->tail = n;
		if (h == NULL)
			h = n;
		else {
			h->tail->next = n;
			h->tail = n;
		}
	}

	return (h);
}

void
set_ipmask(struct ipsec_addr_wrap *address, int b)
{
	if (b == -1)
		address->mask = address->af == AF_INET ? 32 : 128;
	else
		address->mask = b;
}

const struct ipsec_xf *
parse_xf(const char *name, unsigned int length, const struct ipsec_xf xfs[])
{
	int		i;

	for (i = 0; xfs[i].name != NULL; i++) {
		if (strncmp(name, xfs[i].name, strlen(name)))
			continue;
		if (length == 0 || length == xfs[i].length)
			return &xfs[i];
	}
	return (NULL);
}

int
encxf_noauth(unsigned int id)
{
	int i;

	for (i = 0; ikeencxfs[i].name != NULL; i++)
		if (ikeencxfs[i].id == id)
			return ikeencxfs[i].noauth;
	return (0);
}

size_t
keylength_xf(unsigned int saproto, unsigned int type, unsigned int id)
{
	int			 i;
	const struct ipsec_xf	*xfs;

	switch (type) {
	case IKEV2_XFORMTYPE_ENCR:
		if (saproto == IKEV2_SAPROTO_IKE)
			xfs = ikeencxfs;
		else
			xfs = ipsecencxfs;
		break;
	case IKEV2_XFORMTYPE_INTEGR:
		xfs = authxfs;
		break;
	default:
		return (0);
	}

	for (i = 0; xfs[i].name != NULL; i++) {
		if (xfs[i].id == id)
			return (xfs[i].length * 8);
	}
	return (0);
}

size_t
noncelength_xf(unsigned int type, unsigned int id)
{
	const struct ipsec_xf	*xfs = ipsecencxfs;
	int			 i;

	if (type != IKEV2_XFORMTYPE_ENCR)
		return (0);

	for (i = 0; xfs[i].name != NULL; i++)
		if (xfs[i].id == id)
			return (xfs[i].nonce * 8);
	return (0);
}

void
copy_transforms(unsigned int type,
    const struct ipsec_xf **xfs, unsigned int nxfs,
    struct iked_transform **dst, unsigned int *ndst,
    struct iked_transform *src, size_t nsrc)
{
	unsigned int		 i;
	struct iked_transform	*a, *b;
	const struct ipsec_xf	*xf;

	if (nxfs) {
		for (i = 0; i < nxfs; i++) {
			xf = xfs[i];
			*dst = recallocarray(*dst, *ndst,
			    *ndst + 1, sizeof(struct iked_transform));
			if (*dst == NULL)
				err(1, "%s", __func__);
			b = *dst + (*ndst)++;

			b->xform_type = type;
			b->xform_id = xf->id;
			b->xform_keylength = xf->length * 8;
			b->xform_length = xf->keylength * 8;
		}
		return;
	}

	for (i = 0; i < nsrc; i++) {
		a = src + i;
		if (a->xform_type != type)
			continue;
		*dst = recallocarray(*dst, *ndst,
		    *ndst + 1, sizeof(struct iked_transform));
		if (*dst == NULL)
			err(1, "%s", __func__);
		b = *dst + (*ndst)++;
		memcpy(b, a, sizeof(*b));
	}
}

int
create_ike(char *name, int af, struct ipsec_addr_wrap *ipproto,
    int rdomain, struct ipsec_hosts *hosts,
    struct ipsec_hosts *peers, struct ipsec_mode *ike_sa,
    struct ipsec_mode *ipsec_sa, uint8_t saproto,
    unsigned int flags, char *srcid, char *dstid,
    uint32_t ikelifetime, struct iked_lifetime *lt,
    struct iked_auth *authtype, struct ipsec_filters *filter,
    struct ipsec_addr_wrap *ikecfg, char *iface)
{
	char			 idstr[IKED_ID_SIZE];
	struct ipsec_addr_wrap	*ipa, *ipb, *ipp;
	struct iked_auth	*ikeauth;
	struct iked_policy	 pol;
	struct iked_proposal	*p, *ptmp;
	struct iked_transform	*xf;
	unsigned int		 i, j, xfi, noauth, auth;
	unsigned int		 ikepropid = 1, ipsecpropid = 1;
	struct iked_flow	*flow, *ftmp;
	static unsigned int	 policy_id = 0;
	struct iked_cfg		*cfg;
	int			 ret = -1;

	bzero(&pol, sizeof(pol));
	bzero(idstr, sizeof(idstr));

	pol.pol_id = ++policy_id;
	pol.pol_certreqtype = env->sc_certreqtype;
	pol.pol_af = af;
	pol.pol_saproto = saproto;
	for (i = 0, ipp = ipproto; ipp; ipp = ipp->next, i++) {
		if (i >= IKED_IPPROTO_MAX) {
			yyerror("too many protocols");
			return (-1);
		}
		pol.pol_ipproto[i] = ipp->type;
		pol.pol_nipproto++;
	}

	pol.pol_flags = flags;
	pol.pol_rdomain = rdomain;
	memcpy(&pol.pol_auth, authtype, sizeof(struct iked_auth));
	explicit_bzero(authtype, sizeof(*authtype));

	if (name != NULL) {
		if (strlcpy(pol.pol_name, name,
		    sizeof(pol.pol_name)) >= sizeof(pol.pol_name)) {
			yyerror("name too long");
			return (-1);
		}
	} else {
		snprintf(pol.pol_name, sizeof(pol.pol_name),
		    "policy%d", policy_id);
	}

	if (iface != NULL) {
		/* sec(4) */
		if (strncmp("sec", iface, strlen("sec")) == 0)
			pol.pol_flags |= IKED_POLICY_ROUTING;

		pol.pol_iface = if_nametoindex(iface);
		if (pol.pol_iface == 0) {
			yyerror("invalid iface");
			return (-1);
		}
	}

	if (srcid) {
		pol.pol_localid.id_type = get_id_type(srcid);
		pol.pol_localid.id_length = strlen(srcid);
		if (strlcpy((char *)pol.pol_localid.id_data,
		    srcid, IKED_ID_SIZE) >= IKED_ID_SIZE) {
			yyerror("srcid too long");
			return (-1);
		}
	}
	if (dstid) {
		pol.pol_peerid.id_type = get_id_type(dstid);
		pol.pol_peerid.id_length = strlen(dstid);
		if (strlcpy((char *)pol.pol_peerid.id_data,
		    dstid, IKED_ID_SIZE) >= IKED_ID_SIZE) {
			yyerror("dstid too long");
			return (-1);
		}
	}

	if (filter != NULL) {
		if (filter->tag)
			strlcpy(pol.pol_tag, filter->tag, sizeof(pol.pol_tag));
		pol.pol_tap = filter->tap;
	}

	if (peers == NULL) {
		if (pol.pol_flags & IKED_POLICY_ACTIVE) {
			yyerror("active mode requires peer specification");
			return (-1);
		}
		pol.pol_flags |= IKED_POLICY_DEFAULT|IKED_POLICY_SKIP;
	}

	if (peers && peers->src && peers->dst &&
	    (peers->src->af != AF_UNSPEC) && (peers->dst->af != AF_UNSPEC) &&
	    (peers->src->af != peers->dst->af))
		fatalx("create_ike: peer address family mismatch");

	if (peers && (pol.pol_af != AF_UNSPEC) &&
	    ((peers->src && (peers->src->af != AF_UNSPEC) &&
	    (peers->src->af != pol.pol_af)) ||
	    (peers->dst && (peers->dst->af != AF_UNSPEC) &&
	    (peers->dst->af != pol.pol_af))))
		fatalx("create_ike: policy address family mismatch");

	ipa = ipb = NULL;
	if (peers) {
		if (peers->src)
			ipa = peers->src;
		if (peers->dst)
			ipb = peers->dst;
		if (ipa == NULL && ipb == NULL) {
			if (hosts->src && hosts->src->next == NULL)
				ipa = hosts->src;
			if (hosts->dst && hosts->dst->next == NULL)
				ipb = hosts->dst;
		}
	}
	if (ipa == NULL && ipb == NULL) {
		yyerror("could not get local/peer specification");
		return (-1);
	}
	if (pol.pol_flags & IKED_POLICY_ACTIVE) {
		if (ipb == NULL || ipb->netaddress ||
		    (ipa != NULL && ipa->netaddress)) {
			yyerror("active mode requires local/peer address");
			return (-1);
		}
	}
	if (ipa) {
		memcpy(&pol.pol_local.addr, &ipa->address,
		    sizeof(ipa->address));
		pol.pol_local.addr_af = ipa->af;
		pol.pol_local.addr_mask = ipa->mask;
		pol.pol_local.addr_net = ipa->netaddress;
		if (pol.pol_af == AF_UNSPEC)
			pol.pol_af = ipa->af;
	}
	if (ipb) {
		memcpy(&pol.pol_peer.addr, &ipb->address,
		    sizeof(ipb->address));
		pol.pol_peer.addr_af = ipb->af;
		pol.pol_peer.addr_mask = ipb->mask;
		pol.pol_peer.addr_net = ipb->netaddress;
		if (pol.pol_af == AF_UNSPEC)
			pol.pol_af = ipb->af;
	}

	if (ikelifetime)
		pol.pol_rekey = ikelifetime;

	if (lt)
		pol.pol_lifetime = *lt;
	else
		pol.pol_lifetime = deflifetime;

	TAILQ_INIT(&pol.pol_proposals);
	RB_INIT(&pol.pol_flows);

	if (ike_sa == NULL || ike_sa->nxfs == 0) {
		/* AES-GCM proposal */
		if ((p = calloc(1, sizeof(*p))) == NULL)
			err(1, "%s", __func__);
		p->prop_id = ikepropid++;
		p->prop_protoid = IKEV2_SAPROTO_IKE;
		p->prop_nxforms = ikev2_default_nike_transforms_noauth;
		p->prop_xforms = ikev2_default_ike_transforms_noauth;
		TAILQ_INSERT_TAIL(&pol.pol_proposals, p, prop_entry);
		pol.pol_nproposals++;

		/* Non GCM proposal */
		if ((p = calloc(1, sizeof(*p))) == NULL)
			err(1, "%s", __func__);
		p->prop_id = ikepropid++;
		p->prop_protoid = IKEV2_SAPROTO_IKE;
		p->prop_nxforms = ikev2_default_nike_transforms;
		p->prop_xforms = ikev2_default_ike_transforms;
		TAILQ_INSERT_TAIL(&pol.pol_proposals, p, prop_entry);
		pol.pol_nproposals++;
	} else {
		for (i = 0; i < ike_sa->nxfs; i++) {
			noauth = auth = 0;
			for (j = 0; j < ike_sa->xfs[i]->nencxf; j++) {
				if (ike_sa->xfs[i]->encxf[j]->noauth)
					noauth++;
				else
					auth++;
			}
			for (j = 0; j < ike_sa->xfs[i]->ngroupxf; j++) {
				if (ike_sa->xfs[i]->groupxf[j]->id
				    == IKEV2_XFORMDH_NONE) {
					yyerror("IKE group can not be \"none\".");
					goto done;
				}
			}
			if (ike_sa->xfs[i]->nauthxf)
				auth++;

			if (ike_sa->xfs[i]->nesnxf) {
				yyerror("cannot use ESN with ikesa.");
				goto done;
			}
			if (noauth && noauth != ike_sa->xfs[i]->nencxf) {
				yyerror("cannot mix encryption transforms with "
				    "implicit and non-implicit authentication");
				goto done;
			}
			if (noauth && ike_sa->xfs[i]->nauthxf) {
				yyerror("authentication is implicit for given "
				    "encryption transforms");
				goto done;
			}

			if (!auth) {
				if ((p = calloc(1, sizeof(*p))) == NULL)
					err(1, "%s", __func__);

				xf = NULL;
				xfi = 0;
				copy_transforms(IKEV2_XFORMTYPE_ENCR,
				    ike_sa->xfs[i]->encxf,
				    ike_sa->xfs[i]->nencxf, &xf, &xfi,
				    ikev2_default_ike_transforms_noauth,
				    ikev2_default_nike_transforms_noauth);
				copy_transforms(IKEV2_XFORMTYPE_DH,
				    ike_sa->xfs[i]->groupxf,
				    ike_sa->xfs[i]->ngroupxf, &xf, &xfi,
				    ikev2_default_ike_transforms_noauth,
				    ikev2_default_nike_transforms_noauth);
				copy_transforms(IKEV2_XFORMTYPE_PRF,
				    ike_sa->xfs[i]->prfxf,
				    ike_sa->xfs[i]->nprfxf, &xf, &xfi,
				    ikev2_default_ike_transforms_noauth,
				    ikev2_default_nike_transforms_noauth);

				p->prop_id = ikepropid++;
				p->prop_protoid = IKEV2_SAPROTO_IKE;
				p->prop_xforms = xf;
				p->prop_nxforms = xfi;
				TAILQ_INSERT_TAIL(&pol.pol_proposals, p, prop_entry);
				pol.pol_nproposals++;
			}
			if (!noauth) {
				if ((p = calloc(1, sizeof(*p))) == NULL)
					err(1, "%s", __func__);

				xf = NULL;
				xfi = 0;
				copy_transforms(IKEV2_XFORMTYPE_INTEGR,
				    ike_sa->xfs[i]->authxf,
				    ike_sa->xfs[i]->nauthxf, &xf, &xfi,
				    ikev2_default_ike_transforms,
				    ikev2_default_nike_transforms);
				copy_transforms(IKEV2_XFORMTYPE_ENCR,
				    ike_sa->xfs[i]->encxf,
				    ike_sa->xfs[i]->nencxf, &xf, &xfi,
				    ikev2_default_ike_transforms,
				    ikev2_default_nike_transforms);
				copy_transforms(IKEV2_XFORMTYPE_DH,
				    ike_sa->xfs[i]->groupxf,
				    ike_sa->xfs[i]->ngroupxf, &xf, &xfi,
				    ikev2_default_ike_transforms,
				    ikev2_default_nike_transforms);
				copy_transforms(IKEV2_XFORMTYPE_PRF,
				    ike_sa->xfs[i]->prfxf,
				    ike_sa->xfs[i]->nprfxf, &xf, &xfi,
				    ikev2_default_ike_transforms,
				    ikev2_default_nike_transforms);

				p->prop_id = ikepropid++;
				p->prop_protoid = IKEV2_SAPROTO_IKE;
				p->prop_xforms = xf;
				p->prop_nxforms = xfi;
				TAILQ_INSERT_TAIL(&pol.pol_proposals, p, prop_entry);
				pol.pol_nproposals++;
			}
		}
	}

	if (ipsec_sa == NULL || ipsec_sa->nxfs == 0) {
	/* XXX: Linux pfkey does not support AES-GCM */
#if !defined(HAVE_LINUX_PFKEY_H)
		if ((p = calloc(1, sizeof(*p))) == NULL)
			err(1, "%s", __func__);
		p->prop_id = ipsecpropid++;
		p->prop_protoid = saproto;
		p->prop_nxforms = ikev2_default_nesp_transforms_noauth;
		p->prop_xforms = ikev2_default_esp_transforms_noauth;
		TAILQ_INSERT_TAIL(&pol.pol_proposals, p, prop_entry);
		pol.pol_nproposals++;
#endif

		if ((p = calloc(1, sizeof(*p))) == NULL)
			err(1, "%s", __func__);
		p->prop_id = ipsecpropid++;
		p->prop_protoid = saproto;
		p->prop_nxforms = ikev2_default_nesp_transforms;
		p->prop_xforms = ikev2_default_esp_transforms;
		TAILQ_INSERT_TAIL(&pol.pol_proposals, p, prop_entry);
		pol.pol_nproposals++;
	} else {
		for (i = 0; i < ipsec_sa->nxfs; i++) {
			noauth = auth = 0;
			for (j = 0; j < ipsec_sa->xfs[i]->nencxf; j++) {
				if (ipsec_sa->xfs[i]->encxf[j]->noauth)
					noauth++;
				else
					auth++;
			}
			if (ipsec_sa->xfs[i]->nauthxf)
				auth++;

			if (noauth && noauth != ipsec_sa->xfs[i]->nencxf) {
				yyerror("cannot mix encryption transforms with "
				    "implicit and non-implicit authentication");
				goto done;
			}
			if (noauth && ipsec_sa->xfs[i]->nauthxf) {
				yyerror("authentication is implicit for given "
				    "encryption transforms");
				goto done;
			}

			if (!auth) {
#if !defined(HAVE_LINUX_PFKEY_H)
				if ((p = calloc(1, sizeof(*p))) == NULL)
					err(1, "%s", __func__);

				xf = NULL;
				xfi = 0;
				copy_transforms(IKEV2_XFORMTYPE_ENCR,
				    ipsec_sa->xfs[i]->encxf,
				    ipsec_sa->xfs[i]->nencxf, &xf, &xfi,
				    ikev2_default_esp_transforms_noauth,
				    ikev2_default_nesp_transforms_noauth);
				copy_transforms(IKEV2_XFORMTYPE_DH,
				    ipsec_sa->xfs[i]->groupxf,
				    ipsec_sa->xfs[i]->ngroupxf, &xf, &xfi,
				    ikev2_default_esp_transforms_noauth,
				    ikev2_default_nesp_transforms_noauth);
				copy_transforms(IKEV2_XFORMTYPE_ESN,
				    ipsec_sa->xfs[i]->esnxf,
				    ipsec_sa->xfs[i]->nesnxf, &xf, &xfi,
				    ikev2_default_esp_transforms_noauth,
				    ikev2_default_nesp_transforms_noauth);

				p->prop_id = ipsecpropid++;
				p->prop_protoid = saproto;
				p->prop_xforms = xf;
				p->prop_nxforms = xfi;
				TAILQ_INSERT_TAIL(&pol.pol_proposals, p, prop_entry);
				pol.pol_nproposals++;
#endif
			}
			if (!noauth) {
				if ((p = calloc(1, sizeof(*p))) == NULL)
					err(1, "%s", __func__);

				xf = NULL;
				xfi = 0;
				copy_transforms(IKEV2_XFORMTYPE_INTEGR,
				    ipsec_sa->xfs[i]->authxf,
				    ipsec_sa->xfs[i]->nauthxf, &xf, &xfi,
				    ikev2_default_esp_transforms,
				    ikev2_default_nesp_transforms);
				copy_transforms(IKEV2_XFORMTYPE_ENCR,
				    ipsec_sa->xfs[i]->encxf,
				    ipsec_sa->xfs[i]->nencxf, &xf, &xfi,
				    ikev2_default_esp_transforms,
				    ikev2_default_nesp_transforms);
				copy_transforms(IKEV2_XFORMTYPE_DH,
				    ipsec_sa->xfs[i]->groupxf,
				    ipsec_sa->xfs[i]->ngroupxf, &xf, &xfi,
				    ikev2_default_esp_transforms,
				    ikev2_default_nesp_transforms);
				copy_transforms(IKEV2_XFORMTYPE_ESN,
				    ipsec_sa->xfs[i]->esnxf,
				    ipsec_sa->xfs[i]->nesnxf, &xf, &xfi,
				    ikev2_default_esp_transforms,
				    ikev2_default_nesp_transforms);

				p->prop_id = ipsecpropid++;
				p->prop_protoid = saproto;
				p->prop_xforms = xf;
				p->prop_nxforms = xfi;
				TAILQ_INSERT_TAIL(&pol.pol_proposals, p, prop_entry);
				pol.pol_nproposals++;
			}
		}
	}

	for (ipa = hosts->src, ipb = hosts->dst; ipa && ipb;
	    ipa = ipa->next, ipb = ipb->next) {
		for (j = 0; j < pol.pol_nipproto; j++)
			if (expand_flows(&pol, pol.pol_ipproto[j], ipa, ipb))
				fatalx("create_ike: invalid flow");
		if (pol.pol_nipproto == 0)
			if (expand_flows(&pol, 0, ipa, ipb))
				fatalx("create_ike: invalid flow");
	}

	for (j = 0, ipa = ikecfg; ipa; ipa = ipa->next, j++) {
		if (j >= IKED_CFG_MAX)
			break;
		cfg = &pol.pol_cfg[j];
		pol.pol_ncfg++;

		cfg->cfg_action = ipa->action;
		cfg->cfg_type = ipa->type;
		memcpy(&cfg->cfg.address.addr, &ipa->address,
		    sizeof(ipa->address));
		cfg->cfg.address.addr_mask = ipa->mask;
		cfg->cfg.address.addr_net = ipa->netaddress;
		cfg->cfg.address.addr_af = ipa->af;
	}

	if (dstid)
		strlcpy(idstr, dstid, sizeof(idstr));
	else if (!pol.pol_peer.addr_net)
		strlcpy(idstr, print_addr(&pol.pol_peer.addr), sizeof(idstr));

	ikeauth = &pol.pol_auth;
	switch (ikeauth->auth_method) {
	case IKEV2_AUTH_RSA_SIG:
		pol.pol_certreqtype = IKEV2_CERT_RSA_KEY;
		break;
	case IKEV2_AUTH_ECDSA_256:
	case IKEV2_AUTH_ECDSA_384:
	case IKEV2_AUTH_ECDSA_521:
		pol.pol_certreqtype = IKEV2_CERT_ECDSA;
		break;
	default:
		pol.pol_certreqtype = IKEV2_CERT_NONE;
		break;
	}

	log_debug("%s: using %s for peer %s", __func__,
	    print_xf(ikeauth->auth_method, 0, methodxfs), idstr);

	config_setpolicy(env, &pol, PROC_IKEV2);
	config_setflow(env, &pol, PROC_IKEV2);

	rules++;
	ret = 0;

done:
	if (ike_sa) {
		for (i = 0; i < ike_sa->nxfs; i++) {
			free(ike_sa->xfs[i]->authxf);
			free(ike_sa->xfs[i]->encxf);
			free(ike_sa->xfs[i]->groupxf);
			free(ike_sa->xfs[i]->prfxf);
			free(ike_sa->xfs[i]);
		}
		free(ike_sa->xfs);
		free(ike_sa);
	}
	if (ipsec_sa) {
		for (i = 0; i < ipsec_sa->nxfs; i++) {
			free(ipsec_sa->xfs[i]->authxf);
			free(ipsec_sa->xfs[i]->encxf);
			free(ipsec_sa->xfs[i]->groupxf);
			free(ipsec_sa->xfs[i]->prfxf);
			free(ipsec_sa->xfs[i]->esnxf);
			free(ipsec_sa->xfs[i]);
		}
		free(ipsec_sa->xfs);
		free(ipsec_sa);
	}
	TAILQ_FOREACH_SAFE(p, &pol.pol_proposals, prop_entry, ptmp) {
		if (p->prop_xforms != ikev2_default_ike_transforms &&
		    p->prop_xforms != ikev2_default_ike_transforms_noauth &&
		    p->prop_xforms != ikev2_default_esp_transforms &&
		    p->prop_xforms != ikev2_default_esp_transforms_noauth)
			free(p->prop_xforms);
		free(p);
	}
	if (peers != NULL) {
		iaw_free(peers->src);
		iaw_free(peers->dst);
		/* peers is static, cannot be freed */
	}
	if (hosts != NULL) {
		iaw_free(hosts->src);
		iaw_free(hosts->dst);
		free(hosts);
	}
	iaw_free(ikecfg);
	iaw_free(ipproto);
	RB_FOREACH_SAFE(flow, iked_flows, &pol.pol_flows, ftmp) {
		RB_REMOVE(iked_flows, &pol.pol_flows, flow);
		free(flow);
	}
	free(name);
	free(srcid);
	free(dstid);
	return (ret);
}

static int
create_flow(struct iked_policy *pol, int proto, struct ipsec_addr_wrap *ipa,
    struct ipsec_addr_wrap *ipb)
{
	struct iked_flow	*flow;
	struct ipsec_addr_wrap	*ippn;

	if (ipa->af != ipb->af) {
		yyerror("cannot mix different address families.");
		return (-1);
	}

	if ((flow = calloc(1, sizeof(struct iked_flow))) == NULL)
		fatalx("%s: failed to alloc flow.", __func__);

	memcpy(&flow->flow_src.addr, &ipa->address,
	    sizeof(ipa->address));
	flow->flow_src.addr_af = ipa->af;
	flow->flow_src.addr_mask = ipa->mask;
	flow->flow_src.addr_net = ipa->netaddress;
	flow->flow_src.addr_port = ipa->port;

	memcpy(&flow->flow_dst.addr, &ipb->address,
	    sizeof(ipb->address));
	flow->flow_dst.addr_af = ipb->af;
	flow->flow_dst.addr_mask = ipb->mask;
	flow->flow_dst.addr_net = ipb->netaddress;
	flow->flow_dst.addr_port = ipb->port;

	ippn = ipa->srcnat;
	if (ippn) {
		memcpy(&flow->flow_prenat.addr, &ippn->address,
		    sizeof(ippn->address));
		flow->flow_prenat.addr_af = ippn->af;
		flow->flow_prenat.addr_mask = ippn->mask;
		flow->flow_prenat.addr_net = ippn->netaddress;
	} else {
		flow->flow_prenat.addr_af = 0;
	}

	flow->flow_dir = IPSP_DIRECTION_OUT;
	flow->flow_ipproto = proto;
	flow->flow_saproto = pol->pol_saproto;
	flow->flow_rdomain = pol->pol_rdomain;
	flow->flow_transport = pol->pol_flags & IKED_POLICY_TRANSPORT;

	if (RB_INSERT(iked_flows, &pol->pol_flows, flow) == NULL)
		pol->pol_nflows++;
	else {
		warnx("create_ike: duplicate flow");
		free(flow);
	}

	return (0);
}

static int
expand_flows(struct iked_policy *pol, int proto, struct ipsec_addr_wrap *src,
    struct ipsec_addr_wrap *dst)
{
	struct ipsec_addr_wrap	*ipa = NULL, *ipb = NULL;
	int			 ret = -1;
	int			 srcaf, dstaf;

	srcaf = src->af;
	dstaf = dst->af;

	if (src->af == AF_UNSPEC &&
	    dst->af == AF_UNSPEC) {
		/* Need both IPv4 and IPv6 flows */
		src->af = dst->af = AF_INET;
		ipa = expand_keyword(src);
		ipb = expand_keyword(dst);
		if (!ipa || !ipb)
			goto done;
		if (create_flow(pol, proto, ipa, ipb))
			goto done;

		iaw_free(ipa);
		iaw_free(ipb);
		src->af = dst->af = AF_INET6;
		ipa = expand_keyword(src);
		ipb = expand_keyword(dst);
		if (!ipa || !ipb)
			goto done;
		if (create_flow(pol, proto, ipa, ipb))
			goto done;
	} else if (src->af == AF_UNSPEC) {
		src->af = dst->af;
		ipa = expand_keyword(src);
		if (!ipa)
			goto done;
		if (create_flow(pol, proto, ipa, dst))
			goto done;
	} else if (dst->af == AF_UNSPEC) {
		dst->af = src->af;
		ipa = expand_keyword(dst);
		if (!ipa)
			goto done;
		if (create_flow(pol, proto, src, ipa))
			goto done;
	} else if (create_flow(pol, proto, src, dst))
		goto done;
	ret = 0;
 done:
	src->af = srcaf;
	dst->af = dstaf;
	iaw_free(ipa);
	iaw_free(ipb);
	return (ret);
}

static struct ipsec_addr_wrap *
expand_keyword(struct ipsec_addr_wrap *ip)
{
	switch(ip->af) {
	case AF_INET:
		switch(ip->type) {
		case IPSEC_ADDR_ANY:
			return (host("0.0.0.0/0"));
		case IPSEC_ADDR_DYNAMIC:
			return (host("0.0.0.0"));
		}
		break;
	case AF_INET6:
		switch(ip->type) {
		case IPSEC_ADDR_ANY:
			return (host("::/0"));
		case IPSEC_ADDR_DYNAMIC:
			return (host("::"));
		}
	}
	return (NULL);
}

int
create_user(const char *user, const char *pass)
{
	struct iked_user	 usr;

	bzero(&usr, sizeof(usr));

	if (*user == '\0' || (strlcpy(usr.usr_name, user,
	    sizeof(usr.usr_name)) >= sizeof(usr.usr_name))) {
		yyerror("invalid user name");
		return (-1);
	}
	if (*pass == '\0' || (strlcpy(usr.usr_pass, pass,
	    sizeof(usr.usr_pass)) >= sizeof(usr.usr_pass))) {
		yyerror("invalid password");
		explicit_bzero(&usr, sizeof usr);	/* zap partial password */
		return (-1);
	}

	config_setuser(env, &usr, PROC_IKEV2);

	rules++;

	explicit_bzero(&usr, sizeof usr);
	return (0);
}

void
iaw_free(struct ipsec_addr_wrap *head)
{
	struct ipsec_addr_wrap *n, *cur;

	if (head == NULL)
		return;

	for (n = head; n != NULL; ) {
		cur = n;
		n = n->next;
		if (cur->srcnat != NULL) {
			free(cur->srcnat->name);
			free(cur->srcnat);
		}
		free(cur->name);
		free(cur);
	}
}
#line 2958 "parse.c"

#if YYDEBUG
#include <stdio.h>	/* needed for printf */
#endif

#include <stdlib.h>	/* needed for malloc, etc */
#include <string.h>	/* needed for memset */

/* allocate initial stack or double stack size, up to YYMAXDEPTH */
static int yygrowstack(YYSTACKDATA *data)
{
    int i;
    unsigned newsize;
    YYINT *newss;
    YYSTYPE *newvs;

    if ((newsize = data->stacksize) == 0)
        newsize = YYINITSTACKSIZE;
    else if (newsize >= YYMAXDEPTH)
        return YYENOMEM;
    else if ((newsize *= 2) > YYMAXDEPTH)
        newsize = YYMAXDEPTH;

    i = (int) (data->s_mark - data->s_base);
    newss = (YYINT *)realloc(data->s_base, newsize * sizeof(*newss));
    if (newss == NULL)
        return YYENOMEM;

    data->s_base = newss;
    data->s_mark = newss + i;

    newvs = (YYSTYPE *)realloc(data->l_base, newsize * sizeof(*newvs));
    if (newvs == NULL)
        return YYENOMEM;

    data->l_base = newvs;
    data->l_mark = newvs + i;

    data->stacksize = newsize;
    data->s_last = data->s_base + newsize - 1;
    return 0;
}

#if YYPURE || defined(YY_NO_LEAKS)
static void yyfreestack(YYSTACKDATA *data)
{
    free(data->s_base);
    free(data->l_base);
    memset(data, 0, sizeof(*data));
}
#else
#define yyfreestack(data) /* nothing */
#endif

#define YYABORT  goto yyabort
#define YYREJECT goto yyabort
#define YYACCEPT goto yyaccept
#define YYERROR  goto yyerrlab

int
YYPARSE_DECL()
{
    int yym, yyn, yystate;
#if YYDEBUG
    const char *yys;

    if ((yys = getenv("YYDEBUG")) != NULL)
    {
        yyn = *yys;
        if (yyn >= '0' && yyn <= '9')
            yydebug = yyn - '0';
    }
#endif

    /* yym is set below */
    /* yyn is set below */
    yynerrs = 0;
    yyerrflag = 0;
    yychar = YYEMPTY;
    yystate = 0;

#if YYPURE
    memset(&yystack, 0, sizeof(yystack));
#endif

    if (yystack.s_base == NULL && yygrowstack(&yystack) == YYENOMEM) goto yyoverflow;
    yystack.s_mark = yystack.s_base;
    yystack.l_mark = yystack.l_base;
    yystate = 0;
    *yystack.s_mark = 0;

yyloop:
    if ((yyn = yydefred[yystate]) != 0) goto yyreduce;
    if (yychar < 0)
    {
        yychar = YYLEX;
        if (yychar < 0) yychar = YYEOF;
#if YYDEBUG
        if (yydebug)
        {
            if ((yys = yyname[YYTRANSLATE(yychar)]) == NULL) yys = yyname[YYUNDFTOKEN];
            printf("%sdebug: state %d, reading %d (%s)\n",
                    YYPREFIX, yystate, yychar, yys);
        }
#endif
    }
    if (((yyn = yysindex[yystate]) != 0) && (yyn += yychar) >= 0 &&
            yyn <= YYTABLESIZE && yycheck[yyn] == (YYINT) yychar)
    {
#if YYDEBUG
        if (yydebug)
            printf("%sdebug: state %d, shifting to state %d\n",
                    YYPREFIX, yystate, yytable[yyn]);
#endif
        if (yystack.s_mark >= yystack.s_last && yygrowstack(&yystack) == YYENOMEM) goto yyoverflow;
        yystate = yytable[yyn];
        *++yystack.s_mark = yytable[yyn];
        *++yystack.l_mark = yylval;
        yychar = YYEMPTY;
        if (yyerrflag > 0)  --yyerrflag;
        goto yyloop;
    }
    if (((yyn = yyrindex[yystate]) != 0) && (yyn += yychar) >= 0 &&
            yyn <= YYTABLESIZE && yycheck[yyn] == (YYINT) yychar)
    {
        yyn = yytable[yyn];
        goto yyreduce;
    }
    if (yyerrflag != 0) goto yyinrecovery;

    YYERROR_CALL("syntax error");

    goto yyerrlab; /* redundant goto avoids 'unused label' warning */
yyerrlab:
    ++yynerrs;

yyinrecovery:
    if (yyerrflag < 3)
    {
        yyerrflag = 3;
        for (;;)
        {
            if (((yyn = yysindex[*yystack.s_mark]) != 0) && (yyn += YYERRCODE) >= 0 &&
                    yyn <= YYTABLESIZE && yycheck[yyn] == (YYINT) YYERRCODE)
            {
#if YYDEBUG
                if (yydebug)
                    printf("%sdebug: state %d, error recovery shifting\
 to state %d\n", YYPREFIX, *yystack.s_mark, yytable[yyn]);
#endif
                if (yystack.s_mark >= yystack.s_last && yygrowstack(&yystack) == YYENOMEM) goto yyoverflow;
                yystate = yytable[yyn];
                *++yystack.s_mark = yytable[yyn];
                *++yystack.l_mark = yylval;
                goto yyloop;
            }
            else
            {
#if YYDEBUG
                if (yydebug)
                    printf("%sdebug: error recovery discarding state %d\n",
                            YYPREFIX, *yystack.s_mark);
#endif
                if (yystack.s_mark <= yystack.s_base) goto yyabort;
                --yystack.s_mark;
                --yystack.l_mark;
            }
        }
    }
    else
    {
        if (yychar == YYEOF) goto yyabort;
#if YYDEBUG
        if (yydebug)
        {
            if ((yys = yyname[YYTRANSLATE(yychar)]) == NULL) yys = yyname[YYUNDFTOKEN];
            printf("%sdebug: state %d, error recovery discards token %d (%s)\n",
                    YYPREFIX, yystate, yychar, yys);
        }
#endif
        yychar = YYEMPTY;
        goto yyloop;
    }

yyreduce:
#if YYDEBUG
    if (yydebug)
        printf("%sdebug: state %d, reducing by rule %d (%s)\n",
                YYPREFIX, yystate, yyn, yyrule[yyn]);
#endif
    yym = yylen[yyn];
    if (yym > 0)
        yyval = yystack.l_mark[1-yym];
    else
        memset(&yyval, 0, sizeof yyval);

    switch (yyn)
    {
case 9:
#line 494 "parse.y"
	{ file->errors++; }
#line 3160 "parse.c"
break;
case 12:
#line 501 "parse.y"
	{
			struct file	*nfile;

			if ((nfile = pushfile(yystack.l_mark[0].v.string, 1)) == NULL) {
				yyerror("failed to include file %s", yystack.l_mark[0].v.string);
				free(yystack.l_mark[0].v.string);
				YYERROR;
			}
			free(yystack.l_mark[0].v.string);

			file = nfile;
			lungetc('\n');
		}
#line 3177 "parse.c"
break;
case 13:
#line 516 "parse.y"
	{ passive = 0; }
#line 3182 "parse.c"
break;
case 14:
#line 517 "parse.y"
	{ passive = 1; }
#line 3187 "parse.c"
break;
case 15:
#line 518 "parse.y"
	{ decouple = 0; }
#line 3192 "parse.c"
break;
case 16:
#line 519 "parse.y"
	{ decouple = 1; }
#line 3197 "parse.c"
break;
case 17:
#line 520 "parse.y"
	{ fragmentation = 1; }
#line 3202 "parse.c"
break;
case 18:
#line 521 "parse.y"
	{ fragmentation = 0; }
#line 3207 "parse.c"
break;
case 19:
#line 522 "parse.y"
	{ mobike = 1; }
#line 3212 "parse.c"
break;
case 20:
#line 523 "parse.y"
	{ mobike = 0; }
#line 3217 "parse.c"
break;
case 21:
#line 524 "parse.y"
	{ vendorid = 1; }
#line 3222 "parse.c"
break;
case 22:
#line 525 "parse.y"
	{ vendorid = 0; }
#line 3227 "parse.c"
break;
case 23:
#line 526 "parse.y"
	{ enforcesingleikesa = 1; }
#line 3232 "parse.c"
break;
case 24:
#line 527 "parse.y"
	{ enforcesingleikesa = 0; }
#line 3237 "parse.c"
break;
case 25:
#line 528 "parse.y"
	{ stickyaddress = 1; }
#line 3242 "parse.c"
break;
case 26:
#line 529 "parse.y"
	{ stickyaddress = 0; }
#line 3247 "parse.c"
break;
case 27:
#line 530 "parse.y"
	{
			ocsp_url = yystack.l_mark[0].v.string;
		}
#line 3254 "parse.c"
break;
case 28:
#line 533 "parse.y"
	{
			ocsp_url = yystack.l_mark[-2].v.string;
			ocsp_tolerate = yystack.l_mark[0].v.number;
		}
#line 3262 "parse.c"
break;
case 29:
#line 537 "parse.y"
	{
			ocsp_url = yystack.l_mark[-4].v.string;
			ocsp_tolerate = yystack.l_mark[-2].v.number;
			ocsp_maxage = yystack.l_mark[0].v.number;
		}
#line 3271 "parse.c"
break;
case 30:
#line 542 "parse.y"
	{
			cert_partial_chain = 1;
		}
#line 3278 "parse.c"
break;
case 31:
#line 545 "parse.y"
	{
			if (yystack.l_mark[0].v.number < 0) {
				yyerror("timeout outside range");
				YYERROR;
			}
			dpd_interval = yystack.l_mark[0].v.number;
		}
#line 3289 "parse.c"
break;
case 32:
#line 554 "parse.y"
	{
			if (create_user(yystack.l_mark[-1].v.string, yystack.l_mark[0].v.string) == -1)
				YYERROR;
			free(yystack.l_mark[-1].v.string);
			freezero(yystack.l_mark[0].v.string, strlen(yystack.l_mark[0].v.string));
		}
#line 3299 "parse.c"
break;
case 33:
#line 564 "parse.y"
	{
			if (create_ike(yystack.l_mark[-16].v.string, yystack.l_mark[-13].v.number, yystack.l_mark[-12].v.proto, yystack.l_mark[-11].v.number, yystack.l_mark[-10].v.hosts, &yystack.l_mark[-9].v.peers, yystack.l_mark[-8].v.mode, yystack.l_mark[-7].v.mode, yystack.l_mark[-14].v.satype,
			    yystack.l_mark[-15].v.ikemode, yystack.l_mark[-6].v.ids.srcid, yystack.l_mark[-6].v.ids.dstid, yystack.l_mark[-5].v.number, &yystack.l_mark[-4].v.lifetime, &yystack.l_mark[-3].v.ikeauth,
			    yystack.l_mark[0].v.filters, yystack.l_mark[-2].v.cfg, yystack.l_mark[-1].v.string) == -1) {
				yyerror("create_ike failed");
				YYERROR;
			}
		}
#line 3311 "parse.c"
break;
case 34:
#line 574 "parse.y"
	{ yyval.v.cfg = NULL; }
#line 3316 "parse.c"
break;
case 35:
#line 575 "parse.y"
	{ yyval.v.cfg = yystack.l_mark[0].v.cfg; }
#line 3321 "parse.c"
break;
case 36:
#line 578 "parse.y"
	{ yyval.v.cfg = yystack.l_mark[0].v.cfg; }
#line 3326 "parse.c"
break;
case 37:
#line 579 "parse.y"
	{
			if (yystack.l_mark[0].v.cfg == NULL)
				yyval.v.cfg = yystack.l_mark[-1].v.cfg;
			else if (yystack.l_mark[-1].v.cfg == NULL)
				yyval.v.cfg = yystack.l_mark[0].v.cfg;
			else {
				yystack.l_mark[-1].v.cfg->tail->next = yystack.l_mark[0].v.cfg;
				yystack.l_mark[-1].v.cfg->tail = yystack.l_mark[0].v.cfg->tail;
				yyval.v.cfg = yystack.l_mark[-1].v.cfg;
			}
		}
#line 3341 "parse.c"
break;
case 38:
#line 592 "parse.y"
	{
			const struct ipsec_xf	*xf;

			if ((xf = parse_xf(yystack.l_mark[-1].v.string, yystack.l_mark[0].v.host->af, cpxfs)) == NULL) {
				yyerror("not a valid ikecfg option");
				free(yystack.l_mark[-1].v.string);
				free(yystack.l_mark[0].v.host);
				YYERROR;
			}
			free(yystack.l_mark[-1].v.string);
			yyval.v.cfg = yystack.l_mark[0].v.host;
			yyval.v.cfg->type = xf->id;
			yyval.v.cfg->action = IKEV2_CP_REPLY;	/* XXX */
		}
#line 3359 "parse.c"
break;
case 39:
#line 606 "parse.y"
	{
			const struct ipsec_xf	*xf;

			if ((xf = parse_xf(yystack.l_mark[-1].v.string, yystack.l_mark[0].v.anyhost->af, cpxfs)) == NULL) {
				yyerror("not a valid ikecfg option");
				free(yystack.l_mark[-1].v.string);
				free(yystack.l_mark[0].v.anyhost);
				YYERROR;
			}
			free(yystack.l_mark[-1].v.string);
			yyval.v.cfg = yystack.l_mark[0].v.anyhost;
			yyval.v.cfg->type = xf->id;
			yyval.v.cfg->action = IKEV2_CP_REQUEST;	/* XXX */
		}
#line 3377 "parse.c"
break;
case 40:
#line 622 "parse.y"
	{ yyval.v.string = NULL; }
#line 3382 "parse.c"
break;
case 41:
#line 623 "parse.y"
	{
			yyval.v.string = yystack.l_mark[0].v.string;
		}
#line 3389 "parse.c"
break;
case 42:
#line 627 "parse.y"
	{ yyval.v.satype = IKEV2_SAPROTO_ESP; }
#line 3394 "parse.c"
break;
case 43:
#line 628 "parse.y"
	{ yyval.v.satype = IKEV2_SAPROTO_ESP; }
#line 3399 "parse.c"
break;
case 44:
#line 629 "parse.y"
	{ yyval.v.satype = IKEV2_SAPROTO_AH; }
#line 3404 "parse.c"
break;
case 45:
#line 632 "parse.y"
	{ yyval.v.number = AF_UNSPEC; }
#line 3409 "parse.c"
break;
case 46:
#line 633 "parse.y"
	{ yyval.v.number = AF_INET; }
#line 3414 "parse.c"
break;
case 47:
#line 634 "parse.y"
	{ yyval.v.number = AF_INET6; }
#line 3419 "parse.c"
break;
case 48:
#line 637 "parse.y"
	{ yyval.v.proto = NULL; }
#line 3424 "parse.c"
break;
case 49:
#line 638 "parse.y"
	{ yyval.v.proto = yystack.l_mark[0].v.proto; }
#line 3429 "parse.c"
break;
case 50:
#line 639 "parse.y"
	{ yyval.v.proto = yystack.l_mark[-1].v.proto; }
#line 3434 "parse.c"
break;
case 51:
#line 642 "parse.y"
	{ yyval.v.proto = yystack.l_mark[0].v.proto; }
#line 3439 "parse.c"
break;
case 52:
#line 643 "parse.y"
	{
			if (yystack.l_mark[0].v.proto == NULL)
				yyval.v.proto = yystack.l_mark[-2].v.proto;
			else if (yystack.l_mark[-2].v.proto == NULL)
				yyval.v.proto = yystack.l_mark[0].v.proto;
			else {
				yystack.l_mark[-2].v.proto->tail->next = yystack.l_mark[0].v.proto;
				yystack.l_mark[-2].v.proto->tail = yystack.l_mark[0].v.proto->tail;
				yyval.v.proto = yystack.l_mark[-2].v.proto;
			}
		}
#line 3454 "parse.c"
break;
case 53:
#line 656 "parse.y"
	{
			struct protoent *p;

			p = getprotobyname(yystack.l_mark[0].v.string);
			if (p == NULL) {
				yyerror("unknown protocol: %s", yystack.l_mark[0].v.string);
				YYERROR;
			}

			if ((yyval.v.proto = calloc(1, sizeof(*yyval.v.proto))) == NULL)
				err(1, "protoval: calloc");

			yyval.v.proto->type = p->p_proto;
			yyval.v.proto->tail = yyval.v.proto;
			free(yystack.l_mark[0].v.string);
		}
#line 3474 "parse.c"
break;
case 54:
#line 672 "parse.y"
	{
			if (yystack.l_mark[0].v.number > 255 || yystack.l_mark[0].v.number < 0) {
				yyerror("protocol outside range");
				YYERROR;
			}
			if ((yyval.v.proto = calloc(1, sizeof(*yyval.v.proto))) == NULL)
				err(1, "protoval: calloc");

			yyval.v.proto->type = yystack.l_mark[0].v.number;
			yyval.v.proto->tail = yyval.v.proto;
		}
#line 3489 "parse.c"
break;
case 55:
#line 685 "parse.y"
	{ yyval.v.number = -1; }
#line 3494 "parse.c"
break;
case 56:
#line 686 "parse.y"
	{
#ifdef SADB_X_EXT_RDOMAIN
			if (yystack.l_mark[0].v.number > 255 || yystack.l_mark[0].v.number < 0) {
				yyerror("rdomain outside range");
				YYERROR;
			}
			yyval.v.number = yystack.l_mark[0].v.number;
#else
			yyerror("'rdomain' is not supported on this platform");
			YYERROR;
#endif
		}
#line 3510 "parse.c"
break;
case 57:
#line 699 "parse.y"
	{ yyval.v.hosts = yystack.l_mark[0].v.hosts; }
#line 3515 "parse.c"
break;
case 58:
#line 700 "parse.y"
	{
			if (yystack.l_mark[0].v.hosts == NULL)
				yyval.v.hosts = yystack.l_mark[-2].v.hosts;
			else if (yystack.l_mark[-2].v.hosts == NULL)
				yyval.v.hosts = yystack.l_mark[0].v.hosts;
			else {
				yystack.l_mark[-2].v.hosts->src->tail->next = yystack.l_mark[0].v.hosts->src;
				yystack.l_mark[-2].v.hosts->src->tail = yystack.l_mark[0].v.hosts->src->tail;
				yystack.l_mark[-2].v.hosts->dst->tail->next = yystack.l_mark[0].v.hosts->dst;
				yystack.l_mark[-2].v.hosts->dst->tail = yystack.l_mark[0].v.hosts->dst->tail;
				yyval.v.hosts = yystack.l_mark[-2].v.hosts;
				free(yystack.l_mark[0].v.hosts);
			}
		}
#line 3533 "parse.c"
break;
case 59:
#line 716 "parse.y"
	{
			struct ipsec_addr_wrap *ipa;
			for (ipa = yystack.l_mark[-1].v.host; ipa; ipa = ipa->next) {
				if (ipa->srcnat) {
					yyerror("no flow NAT support for"
					    " destination network: %s",
					    ipa->name);
					YYERROR;
				}
			}

			if ((yyval.v.hosts = calloc(1, sizeof(*yyval.v.hosts))) == NULL)
				err(1, "hosts: calloc");

			yyval.v.hosts->src = yystack.l_mark[-4].v.host;
			yyval.v.hosts->src->port = yystack.l_mark[-3].v.port;
			yyval.v.hosts->dst = yystack.l_mark[-1].v.host;
			yyval.v.hosts->dst->port = yystack.l_mark[0].v.port;
		}
#line 3556 "parse.c"
break;
case 60:
#line 735 "parse.y"
	{
			struct ipsec_addr_wrap *ipa;
			for (ipa = yystack.l_mark[-4].v.host; ipa; ipa = ipa->next) {
				if (ipa->srcnat) {
					yyerror("no flow NAT support for"
					    " destination network: %s",
					    ipa->name);
					YYERROR;
				}
			}
			if ((yyval.v.hosts = calloc(1, sizeof(*yyval.v.hosts))) == NULL)
				err(1, "hosts: calloc");

			yyval.v.hosts->src = yystack.l_mark[-1].v.host;
			yyval.v.hosts->src->port = yystack.l_mark[0].v.port;
			yyval.v.hosts->dst = yystack.l_mark[-4].v.host;
			yyval.v.hosts->dst->port = yystack.l_mark[-3].v.port;
		}
#line 3578 "parse.c"
break;
case 61:
#line 755 "parse.y"
	{ yyval.v.port = 0; }
#line 3583 "parse.c"
break;
case 62:
#line 756 "parse.y"
	{ yyval.v.port = yystack.l_mark[0].v.number; }
#line 3588 "parse.c"
break;
case 63:
#line 759 "parse.y"
	{
			struct servent *s;

			if ((s = getservbyname(yystack.l_mark[0].v.string, "tcp")) != NULL ||
			    (s = getservbyname(yystack.l_mark[0].v.string, "udp")) != NULL) {
				yyval.v.number = s->s_port;
			} else {
				yyerror("unknown port: %s", yystack.l_mark[0].v.string);
				YYERROR;
			}
			free(yystack.l_mark[0].v.string);
		}
#line 3604 "parse.c"
break;
case 64:
#line 771 "parse.y"
	{
			if (yystack.l_mark[0].v.number > USHRT_MAX || yystack.l_mark[0].v.number < 0) {
				yyerror("port outside range");
				YYERROR;
			}
			yyval.v.number = htons(yystack.l_mark[0].v.number);
		}
#line 3615 "parse.c"
break;
case 65:
#line 780 "parse.y"
	{
			yyval.v.peers.dst = NULL;
			yyval.v.peers.src = NULL;
		}
#line 3623 "parse.c"
break;
case 66:
#line 784 "parse.y"
	{
			yyval.v.peers.dst = yystack.l_mark[-2].v.anyhost;
			yyval.v.peers.src = yystack.l_mark[0].v.anyhost;
		}
#line 3631 "parse.c"
break;
case 67:
#line 788 "parse.y"
	{
			yyval.v.peers.dst = yystack.l_mark[0].v.anyhost;
			yyval.v.peers.src = yystack.l_mark[-2].v.anyhost;
		}
#line 3639 "parse.c"
break;
case 68:
#line 792 "parse.y"
	{
			yyval.v.peers.dst = yystack.l_mark[0].v.anyhost;
			yyval.v.peers.src = NULL;
		}
#line 3647 "parse.c"
break;
case 69:
#line 796 "parse.y"
	{
			yyval.v.peers.dst = NULL;
			yyval.v.peers.src = yystack.l_mark[0].v.anyhost;
		}
#line 3655 "parse.c"
break;
case 70:
#line 802 "parse.y"
	{ yyval.v.anyhost = yystack.l_mark[0].v.host; }
#line 3660 "parse.c"
break;
case 71:
#line 803 "parse.y"
	{
			yyval.v.anyhost = host_any();
		}
#line 3667 "parse.c"
break;
case 72:
#line 807 "parse.y"
	{
			if ((yyval.v.host = host(yystack.l_mark[0].v.string)) == NULL) {
				free(yystack.l_mark[0].v.string);
				yyerror("could not parse host specification");
				YYERROR;
			}
			free(yystack.l_mark[0].v.string);
		}
#line 3679 "parse.c"
break;
case 73:
#line 815 "parse.y"
	{
			char	*buf;

			if (asprintf(&buf, "%s/%lld", yystack.l_mark[-2].v.string, (long long)yystack.l_mark[0].v.number) == -1)
				err(1, "host: asprintf");
			free(yystack.l_mark[-2].v.string);
			if ((yyval.v.host = host(buf)) == NULL)	{
				free(buf);
				yyerror("could not parse host specification");
				YYERROR;
			}
			free(buf);
		}
#line 3696 "parse.c"
break;
case 74:
#line 830 "parse.y"
	{ yyval.v.host = yystack.l_mark[0].v.host; }
#line 3701 "parse.c"
break;
case 75:
#line 831 "parse.y"
	{
			if ((yystack.l_mark[-3].v.host->af != AF_UNSPEC) && (yystack.l_mark[-1].v.host->af != AF_UNSPEC) &&
			    (yystack.l_mark[-1].v.host->af != yystack.l_mark[-3].v.host->af)) {
				yyerror("Flow NAT address family mismatch");
				YYERROR;
			}
			yyval.v.host = yystack.l_mark[-3].v.host;
			yyval.v.host->srcnat = yystack.l_mark[-1].v.host;
		}
#line 3714 "parse.c"
break;
case 76:
#line 840 "parse.y"
	{
			yyval.v.host = host_any();
		}
#line 3721 "parse.c"
break;
case 77:
#line 843 "parse.y"
	{
			yyval.v.host = host_dynamic();
		}
#line 3728 "parse.c"
break;
case 78:
#line 848 "parse.y"
	{
			yyval.v.ids.srcid = NULL;
			yyval.v.ids.dstid = NULL;
		}
#line 3736 "parse.c"
break;
case 79:
#line 852 "parse.y"
	{
			yyval.v.ids.srcid = yystack.l_mark[-2].v.id;
			yyval.v.ids.dstid = yystack.l_mark[0].v.id;
		}
#line 3744 "parse.c"
break;
case 80:
#line 856 "parse.y"
	{
			yyval.v.ids.srcid = yystack.l_mark[0].v.id;
			yyval.v.ids.dstid = NULL;
		}
#line 3752 "parse.c"
break;
case 81:
#line 860 "parse.y"
	{
			yyval.v.ids.srcid = NULL;
			yyval.v.ids.dstid = yystack.l_mark[0].v.id;
		}
#line 3760 "parse.c"
break;
case 82:
#line 866 "parse.y"
	{ yyval.v.id = yystack.l_mark[0].v.string; }
#line 3765 "parse.c"
break;
case 83:
#line 869 "parse.y"
	{
			if ((ipsec_transforms = calloc(1,
			    sizeof(struct ipsec_transforms))) == NULL)
				err(1, "transforms: calloc");
		}
#line 3774 "parse.c"
break;
case 84:
#line 874 "parse.y"
	{
			yyval.v.transforms = ipsec_transforms;
		}
#line 3781 "parse.c"
break;
case 85:
#line 877 "parse.y"
	{
			yyval.v.transforms = NULL;
		}
#line 3788 "parse.c"
break;
case 88:
#line 886 "parse.y"
	{
			const struct ipsec_xf **xfs = ipsec_transforms->authxf;
			size_t nxfs = ipsec_transforms->nauthxf;
			xfs = recallocarray(xfs, nxfs, nxfs + 1,
			    sizeof(struct ipsec_xf *));
			if (xfs == NULL)
				err(1, "transform: recallocarray");
			if ((xfs[nxfs] = parse_xf(yystack.l_mark[0].v.string, 0, authxfs)) == NULL) {
				yyerror("%s not a valid transform", yystack.l_mark[0].v.string);
				YYERROR;
			}
			free(yystack.l_mark[0].v.string);
			ipsec_transforms->authxf = xfs;
			ipsec_transforms->nauthxf++;
		}
#line 3807 "parse.c"
break;
case 89:
#line 901 "parse.y"
	{
			const struct ipsec_xf **xfs = ipsec_transforms->encxf;
			size_t nxfs = ipsec_transforms->nencxf;
			xfs = recallocarray(xfs, nxfs, nxfs + 1,
			    sizeof(struct ipsec_xf *));
			if (xfs == NULL)
				err(1, "transform: recallocarray");
			if ((xfs[nxfs] = parse_xf(yystack.l_mark[0].v.string, 0, encxfs)) == NULL) {
				yyerror("%s not a valid transform", yystack.l_mark[0].v.string);
				YYERROR;
			}
			free(yystack.l_mark[0].v.string);
			ipsec_transforms->encxf = xfs;
			ipsec_transforms->nencxf++;
		}
#line 3826 "parse.c"
break;
case 90:
#line 916 "parse.y"
	{
			const struct ipsec_xf **xfs = ipsec_transforms->prfxf;
			size_t nxfs = ipsec_transforms->nprfxf;
			xfs = recallocarray(xfs, nxfs, nxfs + 1,
			    sizeof(struct ipsec_xf *));
			if (xfs == NULL)
				err(1, "transform: recallocarray");
			if ((xfs[nxfs] = parse_xf(yystack.l_mark[0].v.string, 0, prfxfs)) == NULL) {
				yyerror("%s not a valid transform", yystack.l_mark[0].v.string);
				YYERROR;
			}
			free(yystack.l_mark[0].v.string);
			ipsec_transforms->prfxf = xfs;
			ipsec_transforms->nprfxf++;
		}
#line 3845 "parse.c"
break;
case 91:
#line 931 "parse.y"
	{
			const struct ipsec_xf **xfs = ipsec_transforms->groupxf;
			size_t nxfs = ipsec_transforms->ngroupxf;
			xfs = recallocarray(xfs, nxfs, nxfs + 1,
			    sizeof(struct ipsec_xf *));
			if (xfs == NULL)
				err(1, "transform: recallocarray");
			if ((xfs[nxfs] = parse_xf(yystack.l_mark[0].v.string, 0, groupxfs)) == NULL) {
				yyerror("%s not a valid transform", yystack.l_mark[0].v.string);
				YYERROR;
			}
			free(yystack.l_mark[0].v.string);
			ipsec_transforms->groupxf = xfs;
			ipsec_transforms->ngroupxf++;
		}
#line 3864 "parse.c"
break;
case 92:
#line 946 "parse.y"
	{
			const struct ipsec_xf **xfs = ipsec_transforms->esnxf;
			size_t nxfs = ipsec_transforms->nesnxf;
			xfs = recallocarray(xfs, nxfs, nxfs + 1,
			    sizeof(struct ipsec_xf *));
			if (xfs == NULL)
				err(1, "transform: recallocarray");
			if ((xfs[nxfs] = parse_xf(yystack.l_mark[0].v.string, 0, esnxfs)) == NULL) {
				yyerror("%s not a valid transform", yystack.l_mark[0].v.string);
				YYERROR;
			}
			ipsec_transforms->esnxf = xfs;
			ipsec_transforms->nesnxf++;
		}
#line 3882 "parse.c"
break;
case 93:
#line 962 "parse.y"
	{ yyval.v.string = "esn"; }
#line 3887 "parse.c"
break;
case 94:
#line 963 "parse.y"
	{ yyval.v.string = "noesn"; }
#line 3892 "parse.c"
break;
case 95:
#line 966 "parse.y"
	{
			if ((ipsec_mode = calloc(1,
			    sizeof(struct ipsec_mode))) == NULL)
				err(1, "ike_sas: calloc");
		}
#line 3901 "parse.c"
break;
case 96:
#line 971 "parse.y"
	{
			yyval.v.mode = ipsec_mode;
		}
#line 3908 "parse.c"
break;
case 97:
#line 974 "parse.y"
	{
			yyval.v.mode = NULL;
		}
#line 3915 "parse.c"
break;
case 100:
#line 983 "parse.y"
	{
			if ((ipsec_mode->xfs = recallocarray(ipsec_mode->xfs,
			    ipsec_mode->nxfs, ipsec_mode->nxfs + 1,
			    sizeof(struct ipsec_transforms *))) == NULL)
				err(1, "ike_sa: recallocarray");
			ipsec_mode->nxfs++;
			encxfs = ikeencxfs;
		}
#line 3927 "parse.c"
break;
case 101:
#line 990 "parse.y"
	{
			ipsec_mode->xfs[ipsec_mode->nxfs - 1] = yystack.l_mark[0].v.transforms;
		}
#line 3934 "parse.c"
break;
case 102:
#line 995 "parse.y"
	{
			if ((ipsec_mode = calloc(1,
			    sizeof(struct ipsec_mode))) == NULL)
				err(1, "child_sas: calloc");
		}
#line 3943 "parse.c"
break;
case 103:
#line 1000 "parse.y"
	{
			yyval.v.mode = ipsec_mode;
		}
#line 3950 "parse.c"
break;
case 104:
#line 1003 "parse.y"
	{
			yyval.v.mode = NULL;
		}
#line 3957 "parse.c"
break;
case 107:
#line 1012 "parse.y"
	{
			if ((ipsec_mode->xfs = recallocarray(ipsec_mode->xfs,
			    ipsec_mode->nxfs, ipsec_mode->nxfs + 1,
			    sizeof(struct ipsec_transforms *))) == NULL)
				err(1, "child_sa: recallocarray");
			ipsec_mode->nxfs++;
			encxfs = ipsecencxfs;
		}
#line 3969 "parse.c"
break;
case 108:
#line 1019 "parse.y"
	{
			ipsec_mode->xfs[ipsec_mode->nxfs - 1] = yystack.l_mark[0].v.transforms;
		}
#line 3976 "parse.c"
break;
case 109:
#line 1024 "parse.y"
	{
			yyval.v.ikemode = yystack.l_mark[-4].v.ikemode | yystack.l_mark[-3].v.ikemode | yystack.l_mark[-2].v.ikemode | yystack.l_mark[-1].v.ikemode | yystack.l_mark[0].v.ikemode;
		}
#line 3983 "parse.c"
break;
case 110:
#line 1029 "parse.y"
	{ yyval.v.ikemode = 0; }
#line 3988 "parse.c"
break;
case 111:
#line 1030 "parse.y"
	{ yyval.v.ikemode = IKED_POLICY_QUICK; }
#line 3993 "parse.c"
break;
case 112:
#line 1031 "parse.y"
	{ yyval.v.ikemode = IKED_POLICY_SKIP; }
#line 3998 "parse.c"
break;
case 113:
#line 1032 "parse.y"
	{ yyval.v.ikemode = IKED_POLICY_DEFAULT; }
#line 4003 "parse.c"
break;
case 114:
#line 1035 "parse.y"
	{ yyval.v.ikemode = IKED_POLICY_PASSIVE; }
#line 4008 "parse.c"
break;
case 115:
#line 1036 "parse.y"
	{ yyval.v.ikemode = IKED_POLICY_PASSIVE; }
#line 4013 "parse.c"
break;
case 116:
#line 1037 "parse.y"
	{ yyval.v.ikemode = IKED_POLICY_ACTIVE; }
#line 4018 "parse.c"
break;
case 117:
#line 1040 "parse.y"
	{ yyval.v.ikemode = 0; }
#line 4023 "parse.c"
break;
case 118:
#line 1041 "parse.y"
	{ yyval.v.ikemode = IKED_POLICY_IPCOMP; }
#line 4028 "parse.c"
break;
case 119:
#line 1044 "parse.y"
	{ yyval.v.ikemode = 0; }
#line 4033 "parse.c"
break;
case 120:
#line 1045 "parse.y"
	{ yyval.v.ikemode = 0; }
#line 4038 "parse.c"
break;
case 121:
#line 1046 "parse.y"
	{ yyval.v.ikemode = IKED_POLICY_TRANSPORT; }
#line 4043 "parse.c"
break;
case 122:
#line 1049 "parse.y"
	{ yyval.v.ikemode = 0; }
#line 4048 "parse.c"
break;
case 123:
#line 1050 "parse.y"
	{ yyval.v.ikemode = IKED_POLICY_NATT_FORCE; }
#line 4053 "parse.c"
break;
case 124:
#line 1053 "parse.y"
	{
			yyval.v.ikeauth.auth_method = IKEV2_AUTH_SIG_ANY;	/* default */
			yyval.v.ikeauth.auth_eap = 0;
			yyval.v.ikeauth.auth_length = 0;
		}
#line 4062 "parse.c"
break;
case 125:
#line 1058 "parse.y"
	{
			memcpy(&yyval.v.ikeauth, &yystack.l_mark[0].v.ikekey, sizeof(yyval.v.ikeauth));
			yyval.v.ikeauth.auth_method = IKEV2_AUTH_SHARED_KEY_MIC;
			yyval.v.ikeauth.auth_eap = 0;
			explicit_bzero(&yystack.l_mark[0].v.ikekey, sizeof(yystack.l_mark[0].v.ikekey));
		}
#line 4072 "parse.c"
break;
case 126:
#line 1064 "parse.y"
	{
			unsigned int i;

			for (i = 0; i < strlen(yystack.l_mark[0].v.string); i++)
				if (yystack.l_mark[0].v.string[i] == '-')
					yystack.l_mark[0].v.string[i] = '_';

			if (strcasecmp("mschap_v2", yystack.l_mark[0].v.string) != 0) {
				yyerror("unsupported EAP method: %s", yystack.l_mark[0].v.string);
				free(yystack.l_mark[0].v.string);
				YYERROR;
			}
			free(yystack.l_mark[0].v.string);

			yyval.v.ikeauth.auth_method = IKEV2_AUTH_SIG_ANY;
			yyval.v.ikeauth.auth_eap = EAP_TYPE_MSCHAP_V2;
			yyval.v.ikeauth.auth_length = 0;
		}
#line 4094 "parse.c"
break;
case 127:
#line 1082 "parse.y"
	{
			const struct ipsec_xf *xf;

			if ((xf = parse_xf(yystack.l_mark[0].v.string, 0, methodxfs)) == NULL ||
			    xf->id == IKEV2_AUTH_NONE) {
				yyerror("not a valid authentication mode");
				free(yystack.l_mark[0].v.string);
				YYERROR;
			}
			free(yystack.l_mark[0].v.string);

			yyval.v.ikeauth.auth_method = xf->id;
			yyval.v.ikeauth.auth_eap = 0;
			yyval.v.ikeauth.auth_length = 0;
		}
#line 4113 "parse.c"
break;
case 128:
#line 1099 "parse.y"
	{
			yyval.v.number = yystack.l_mark[0].v.number;
		}
#line 4120 "parse.c"
break;
case 129:
#line 1102 "parse.y"
	{
			uint64_t	 bytes = 0;
			char		 unit = 0;

			if (sscanf(yystack.l_mark[0].v.string, "%llu%c", (long long unsigned *)&bytes,
			    &unit) != 2) {
				yyerror("invalid byte specification: %s", yystack.l_mark[0].v.string);
				YYERROR;
			}
			free(yystack.l_mark[0].v.string);
			switch (toupper((unsigned char)unit)) {
			case 'K':
				bytes *= 1024;
				break;
			case 'M':
				bytes *= 1024 * 1024;
				break;
			case 'G':
				bytes *= 1024 * 1024 * 1024;
				break;
			default:
				yyerror("invalid byte unit");
				YYERROR;
			}
			yyval.v.number = bytes;
		}
#line 4150 "parse.c"
break;
case 130:
#line 1130 "parse.y"
	{
			yyval.v.number = yystack.l_mark[0].v.number;
		}
#line 4157 "parse.c"
break;
case 131:
#line 1133 "parse.y"
	{
			uint64_t	 seconds = 0;
			char		 unit = 0;

			if (sscanf(yystack.l_mark[0].v.string, "%llu%c", (long long unsigned *)&seconds,
			    &unit) != 2) {
				yyerror("invalid time specification: %s", yystack.l_mark[0].v.string);
				YYERROR;
			}
			free(yystack.l_mark[0].v.string);
			switch (tolower((unsigned char)unit)) {
			case 'm':
				seconds *= 60;
				break;
			case 'h':
				seconds *= 60 * 60;
				break;
			default:
				yyerror("invalid time unit");
				YYERROR;
			}
			yyval.v.number = seconds;
		}
#line 4184 "parse.c"
break;
case 132:
#line 1158 "parse.y"
	{
			yyval.v.lifetime = deflifetime;
		}
#line 4191 "parse.c"
break;
case 133:
#line 1161 "parse.y"
	{
			yyval.v.lifetime.lt_seconds = yystack.l_mark[0].v.number;
			yyval.v.lifetime.lt_bytes = deflifetime.lt_bytes;
		}
#line 4199 "parse.c"
break;
case 134:
#line 1165 "parse.y"
	{
			yyval.v.lifetime.lt_seconds = yystack.l_mark[-2].v.number;
			yyval.v.lifetime.lt_bytes = yystack.l_mark[0].v.number;
		}
#line 4207 "parse.c"
break;
case 135:
#line 1171 "parse.y"
	{
			yyval.v.number = 0;
		}
#line 4214 "parse.c"
break;
case 136:
#line 1174 "parse.y"
	{
			yyval.v.number = yystack.l_mark[0].v.number;
		}
#line 4221 "parse.c"
break;
case 137:
#line 1178 "parse.y"
	{
			uint8_t		*hex;

			bzero(&yyval.v.ikekey, sizeof(yyval.v.ikekey));

			hex = yystack.l_mark[0].v.string;
			if (strncmp(hex, "0x", 2) == 0) {
				hex += 2;
				if (parsekey(hex, strlen(hex), &yyval.v.ikekey) != 0) {
					free(yystack.l_mark[0].v.string);
					YYERROR;
				}
			} else {
				if (strlen(yystack.l_mark[0].v.string) > sizeof(yyval.v.ikekey.auth_data)) {
					yyerror("psk too long");
					free(yystack.l_mark[0].v.string);
					YYERROR;
				}
				strlcpy(yyval.v.ikekey.auth_data, yystack.l_mark[0].v.string,
				    sizeof(yyval.v.ikekey.auth_data));
				yyval.v.ikekey.auth_length = strlen(yystack.l_mark[0].v.string);
			}
			freezero(yystack.l_mark[0].v.string, strlen(yystack.l_mark[0].v.string));
		}
#line 4249 "parse.c"
break;
case 138:
#line 1202 "parse.y"
	{
			if (parsekeyfile(yystack.l_mark[0].v.string, &yyval.v.ikekey) != 0) {
				free(yystack.l_mark[0].v.string);
				YYERROR;
			}
			free(yystack.l_mark[0].v.string);
		}
#line 4260 "parse.c"
break;
case 139:
#line 1211 "parse.y"
	{
			if ((ipsec_filters = calloc(1,
			    sizeof(struct ipsec_filters))) == NULL)
				err(1, "filters: calloc");
		}
#line 4269 "parse.c"
break;
case 140:
#line 1216 "parse.y"
	{
			yyval.v.filters = ipsec_filters;
		}
#line 4276 "parse.c"
break;
case 141:
#line 1219 "parse.y"
	{
			yyval.v.filters = NULL;
		}
#line 4283 "parse.c"
break;
case 144:
#line 1229 "parse.y"
	{
			ipsec_filters->tag = yystack.l_mark[0].v.string;
		}
#line 4290 "parse.c"
break;
case 145:
#line 1233 "parse.y"
	{
			const char	*errstr = NULL;
			size_t		 len;

			len = strcspn(yystack.l_mark[0].v.string, "0123456789");
			if (strlen("enc") != len ||
			    strncmp("enc", yystack.l_mark[0].v.string, len) != 0) {
				yyerror("invalid tap interface name: %s", yystack.l_mark[0].v.string);
				free(yystack.l_mark[0].v.string);
				YYERROR;
			}
			ipsec_filters->tap =
			    strtonum(yystack.l_mark[0].v.string + len, 0, UINT_MAX, &errstr);
			free(yystack.l_mark[0].v.string);
			if (errstr != NULL) {
				yyerror("invalid tap interface unit: %s",
				    errstr);
				YYERROR;
			}
		}
#line 4314 "parse.c"
break;
case 146:
#line 1255 "parse.y"
	{
			yyval.v.string = NULL;
		}
#line 4321 "parse.c"
break;
case 147:
#line 1258 "parse.y"
	{
			yyval.v.string = yystack.l_mark[0].v.string;
		}
#line 4328 "parse.c"
break;
case 148:
#line 1263 "parse.y"
	{
			if (asprintf(&yyval.v.string, "%s %s", yystack.l_mark[-1].v.string, yystack.l_mark[0].v.string) == -1)
				err(1, "string: asprintf");
			free(yystack.l_mark[-1].v.string);
			free(yystack.l_mark[0].v.string);
		}
#line 4338 "parse.c"
break;
case 150:
#line 1273 "parse.y"
	{
			char *s = yystack.l_mark[-2].v.string;
			log_debug("%s = \"%s\"\n", yystack.l_mark[-2].v.string, yystack.l_mark[0].v.string);
			while (*s++) {
				if (isspace((unsigned char)*s)) {
					yyerror("macro name cannot contain "
					    "whitespace");
					free(yystack.l_mark[-2].v.string);
					free(yystack.l_mark[0].v.string);
					YYERROR;
				}
			}
			if (symset(yystack.l_mark[-2].v.string, yystack.l_mark[0].v.string, 0) == -1)
				err(1, "cannot store variable");
			free(yystack.l_mark[-2].v.string);
			free(yystack.l_mark[0].v.string);
		}
#line 4359 "parse.c"
break;
case 160:
#line 1311 "parse.y"
	{
			int	 c;

			while ((c = lgetc(0)) != '\n' && c != EOF)
				; /* nothing */
			if (c == '\n')
				lungetc(c);
		}
#line 4371 "parse.c"
break;
#line 4373 "parse.c"
    }
    yystack.s_mark -= yym;
    yystate = *yystack.s_mark;
    yystack.l_mark -= yym;
    yym = yylhs[yyn];
    if (yystate == 0 && yym == 0)
    {
#if YYDEBUG
        if (yydebug)
            printf("%sdebug: after reduction, shifting from state 0 to\
 state %d\n", YYPREFIX, YYFINAL);
#endif
        yystate = YYFINAL;
        *++yystack.s_mark = YYFINAL;
        *++yystack.l_mark = yyval;
        if (yychar < 0)
        {
            yychar = YYLEX;
            if (yychar < 0) yychar = YYEOF;
#if YYDEBUG
            if (yydebug)
            {
                if ((yys = yyname[YYTRANSLATE(yychar)]) == NULL) yys = yyname[YYUNDFTOKEN];
                printf("%sdebug: state %d, reading %d (%s)\n",
                        YYPREFIX, YYFINAL, yychar, yys);
            }
#endif
        }
        if (yychar == YYEOF) goto yyaccept;
        goto yyloop;
    }
    if (((yyn = yygindex[yym]) != 0) && (yyn += yystate) >= 0 &&
            yyn <= YYTABLESIZE && yycheck[yyn] == (YYINT) yystate)
        yystate = yytable[yyn];
    else
        yystate = yydgoto[yym];
#if YYDEBUG
    if (yydebug)
        printf("%sdebug: after reduction, shifting from state %d \
to state %d\n", YYPREFIX, *yystack.s_mark, yystate);
#endif
    if (yystack.s_mark >= yystack.s_last && yygrowstack(&yystack) == YYENOMEM) goto yyoverflow;
    *++yystack.s_mark = (YYINT) yystate;
    *++yystack.l_mark = yyval;
    goto yyloop;

yyoverflow:
    YYERROR_CALL("yacc stack overflow");

yyabort:
    yyfreestack(&yystack);
    return (1);

yyaccept:
    yyfreestack(&yystack);
    return (0);
}
