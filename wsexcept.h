#pragma once

#include <fmt/format.h>
#include <string>

#ifndef _WIN32
#include <gssapi/gssapi.h>
#endif

class formatted_error : public std::exception {
public:
	template<typename T, typename... Args>
	formatted_error(const T& s, Args&&... args) {
		msg = fmt::format(s, std::forward<Args>(args)...);
	}

	const char* what() const noexcept {
		return msg.c_str();
	}

private:
	std::string msg;
};

#ifndef _WIN32
enum class krb5_minor {
	KRB5KDC_ERR_NONE = -1765328384L,
	KRB5KDC_ERR_NAME_EXP = -1765328383L,
	KRB5KDC_ERR_SERVICE_EXP = -1765328382L,
	KRB5KDC_ERR_BAD_PVNO = -1765328381L,
	KRB5KDC_ERR_C_OLD_MAST_KVNO = -1765328380L,
	KRB5KDC_ERR_S_OLD_MAST_KVNO = -1765328379L,
	KRB5KDC_ERR_C_PRINCIPAL_UNKNOWN = -1765328378L,
	KRB5KDC_ERR_S_PRINCIPAL_UNKNOWN = -1765328377L,
	KRB5KDC_ERR_PRINCIPAL_NOT_UNIQUE = -1765328376L,
	KRB5KDC_ERR_NULL_KEY = -1765328375L,
	KRB5KDC_ERR_CANNOT_POSTDATE = -1765328374L,
	KRB5KDC_ERR_NEVER_VALID = -1765328373L,
	KRB5KDC_ERR_POLICY = -1765328372L,
	KRB5KDC_ERR_BADOPTION = -1765328371L,
	KRB5KDC_ERR_ETYPE_NOSUPP = -1765328370L,
	KRB5KDC_ERR_SUMTYPE_NOSUPP = -1765328369L,
	KRB5KDC_ERR_PADATA_TYPE_NOSUPP = -1765328368L,
	KRB5KDC_ERR_TRTYPE_NOSUPP = -1765328367L,
	KRB5KDC_ERR_CLIENT_REVOKED = -1765328366L,
	KRB5KDC_ERR_SERVICE_REVOKED = -1765328365L,
	KRB5KDC_ERR_TGT_REVOKED = -1765328364L,
	KRB5KDC_ERR_CLIENT_NOTYET = -1765328363L,
	KRB5KDC_ERR_SERVICE_NOTYET = -1765328362L,
	KRB5KDC_ERR_KEY_EXP = -1765328361L,
	KRB5KDC_ERR_PREAUTH_FAILED = -1765328360L,
	KRB5KDC_ERR_PREAUTH_REQUIRED = -1765328359L,
	KRB5KDC_ERR_SERVER_NOMATCH = -1765328358L,
	KRB5KDC_ERR_MUST_USE_USER2USER = -1765328357L,
	KRB5KDC_ERR_PATH_NOT_ACCEPTED = -1765328356L,
	KRB5KDC_ERR_SVC_UNAVAILABLE = -1765328355L,
	KRB5PLACEHOLD_30 = -1765328354L,
	KRB5KRB_AP_ERR_BAD_INTEGRITY = -1765328353L,
	KRB5KRB_AP_ERR_TKT_EXPIRED = -1765328352L,
	KRB5KRB_AP_ERR_TKT_NYV = -1765328351L,
	KRB5KRB_AP_ERR_REPEAT = -1765328350L,
	KRB5KRB_AP_ERR_NOT_US = -1765328349L,
	KRB5KRB_AP_ERR_BADMATCH = -1765328348L,
	KRB5KRB_AP_ERR_SKEW = -1765328347L,
	KRB5KRB_AP_ERR_BADADDR = -1765328346L,
	KRB5KRB_AP_ERR_BADVERSION = -1765328345L,
	KRB5KRB_AP_ERR_MSG_TYPE = -1765328344L,
	KRB5KRB_AP_ERR_MODIFIED = -1765328343L,
	KRB5KRB_AP_ERR_BADORDER = -1765328342L,
	KRB5KRB_AP_ERR_ILL_CR_TKT = -1765328341L,
	KRB5KRB_AP_ERR_BADKEYVER = -1765328340L,
	KRB5KRB_AP_ERR_NOKEY = -1765328339L,
	KRB5KRB_AP_ERR_MUT_FAIL = -1765328338L,
	KRB5KRB_AP_ERR_BADDIRECTION = -1765328337L,
	KRB5KRB_AP_ERR_METHOD = -1765328336L,
	KRB5KRB_AP_ERR_BADSEQ = -1765328335L,
	KRB5KRB_AP_ERR_INAPP_CKSUM = -1765328334L,
	KRB5KRB_AP_PATH_NOT_ACCEPTED = -1765328333L,
	KRB5KRB_ERR_RESPONSE_TOO_BIG = -1765328332L,
	KRB5PLACEHOLD_53 = -1765328331L,
	KRB5PLACEHOLD_54 = -1765328330L,
	KRB5PLACEHOLD_55 = -1765328329L,
	KRB5PLACEHOLD_56 = -1765328328L,
	KRB5PLACEHOLD_57 = -1765328327L,
	KRB5PLACEHOLD_58 = -1765328326L,
	KRB5PLACEHOLD_59 = -1765328325L,
	KRB5KRB_ERR_GENERIC = -1765328324L,
	KRB5KRB_ERR_FIELD_TOOLONG = -1765328323L,
	KRB5KDC_ERR_CLIENT_NOT_TRUSTED = -1765328322L,
	KRB5KDC_ERR_KDC_NOT_TRUSTED = -1765328321L,
	KRB5KDC_ERR_INVALID_SIG = -1765328320L,
	KRB5KDC_ERR_DH_KEY_PARAMETERS_NOT_ACCEPTED = -1765328319L,
	KRB5KDC_ERR_CERTIFICATE_MISMATCH = -1765328318L,
	KRB5KRB_AP_ERR_NO_TGT = -1765328317L,
	KRB5KDC_ERR_WRONG_REALM = -1765328316L,
	KRB5KRB_AP_ERR_USER_TO_USER_REQUIRED = -1765328315L,
	KRB5KDC_ERR_CANT_VERIFY_CERTIFICATE = -1765328314L,
	KRB5KDC_ERR_INVALID_CERTIFICATE = -1765328313L,
	KRB5KDC_ERR_REVOKED_CERTIFICATE = -1765328312L,
	KRB5KDC_ERR_REVOCATION_STATUS_UNKNOWN = -1765328311L,
	KRB5KDC_ERR_REVOCATION_STATUS_UNAVAILABLE = -1765328310L,
	KRB5KDC_ERR_CLIENT_NAME_MISMATCH = -1765328309L,
	KRB5KDC_ERR_KDC_NAME_MISMATCH = -1765328308L,
	KRB5KDC_ERR_INCONSISTENT_KEY_PURPOSE = -1765328307L,
	KRB5KDC_ERR_DIGEST_IN_CERT_NOT_ACCEPTED = -1765328306L,
	KRB5KDC_ERR_PA_CHECKSUM_MUST_BE_INCLUDED = -1765328305L,
	KRB5KDC_ERR_DIGEST_IN_SIGNED_DATA_NOT_ACCEPTED = -1765328304L,
	KRB5KDC_ERR_PUBLIC_KEY_ENCRYPTION_NOT_SUPPORTED = -1765328303L,
	KRB5PLACEHOLD_82 = -1765328302L,
	KRB5PLACEHOLD_83 = -1765328301L,
	KRB5PLACEHOLD_84 = -1765328300L,
	KRB5KRB_AP_ERR_IAKERB_KDC_NOT_FOUND = -1765328299L,
	KRB5KRB_AP_ERR_IAKERB_KDC_NO_RESPONSE = -1765328298L,
	KRB5PLACEHOLD_87 = -1765328297L,
	KRB5PLACEHOLD_88 = -1765328296L,
	KRB5PLACEHOLD_89 = -1765328295L,
	KRB5KDC_ERR_PREAUTH_EXPIRED = -1765328294L,
	KRB5KDC_ERR_MORE_PREAUTH_DATA_REQUIRED = -1765328293L,
	KRB5PLACEHOLD_92 = -1765328292L,
	KRB5KDC_ERR_UNKNOWN_CRITICAL_FAST_OPTION = -1765328291L,
	KRB5PLACEHOLD_94 = -1765328290L,
	KRB5PLACEHOLD_95 = -1765328289L,
	KRB5PLACEHOLD_96 = -1765328288L,
	KRB5PLACEHOLD_97 = -1765328287L,
	KRB5PLACEHOLD_98 = -1765328286L,
	KRB5PLACEHOLD_99 = -1765328285L,
	KRB5KDC_ERR_NO_ACCEPTABLE_KDF = -1765328284L,
	KRB5PLACEHOLD_101 = -1765328283L,
	KRB5PLACEHOLD_102 = -1765328282L,
	KRB5PLACEHOLD_103 = -1765328281L,
	KRB5PLACEHOLD_104 = -1765328280L,
	KRB5PLACEHOLD_105 = -1765328279L,
	KRB5PLACEHOLD_106 = -1765328278L,
	KRB5PLACEHOLD_107 = -1765328277L,
	KRB5PLACEHOLD_108 = -1765328276L,
	KRB5PLACEHOLD_109 = -1765328275L,
	KRB5PLACEHOLD_110 = -1765328274L,
	KRB5PLACEHOLD_111 = -1765328273L,
	KRB5PLACEHOLD_112 = -1765328272L,
	KRB5PLACEHOLD_113 = -1765328271L,
	KRB5PLACEHOLD_114 = -1765328270L,
	KRB5PLACEHOLD_115 = -1765328269L,
	KRB5PLACEHOLD_116 = -1765328268L,
	KRB5PLACEHOLD_117 = -1765328267L,
	KRB5PLACEHOLD_118 = -1765328266L,
	KRB5PLACEHOLD_119 = -1765328265L,
	KRB5PLACEHOLD_120 = -1765328264L,
	KRB5PLACEHOLD_121 = -1765328263L,
	KRB5PLACEHOLD_122 = -1765328262L,
	KRB5PLACEHOLD_123 = -1765328261L,
	KRB5PLACEHOLD_124 = -1765328260L,
	KRB5PLACEHOLD_125 = -1765328259L,
	KRB5PLACEHOLD_126 = -1765328258L,
	KRB5PLACEHOLD_127 = -1765328257L,
	KRB5_ERR_RCSID = -1765328256L,
	KRB5_LIBOS_BADLOCKFLAG = -1765328255L,
	KRB5_LIBOS_CANTREADPWD = -1765328254L,
	KRB5_LIBOS_BADPWDMATCH = -1765328253L,
	KRB5_LIBOS_PWDINTR = -1765328252L,
	KRB5_PARSE_ILLCHAR = -1765328251L,
	KRB5_PARSE_MALFORMED = -1765328250L,
	KRB5_CONFIG_CANTOPEN = -1765328249L,
	KRB5_CONFIG_BADFORMAT = -1765328248L,
	KRB5_CONFIG_NOTENUFSPACE = -1765328247L,
	KRB5_BADMSGTYPE = -1765328246L,
	KRB5_CC_BADNAME = -1765328245L,
	KRB5_CC_UNKNOWN_TYPE = -1765328244L,
	KRB5_CC_NOTFOUND = -1765328243L,
	KRB5_CC_END = -1765328242L,
	KRB5_NO_TKT_SUPPLIED = -1765328241L,
	KRB5KRB_AP_WRONG_PRINC = -1765328240L,
	KRB5KRB_AP_ERR_TKT_INVALID = -1765328239L,
	KRB5_PRINC_NOMATCH = -1765328238L,
	KRB5_KDCREP_MODIFIED = -1765328237L,
	KRB5_KDCREP_SKEW = -1765328236L,
	KRB5_IN_TKT_REALM_MISMATCH = -1765328235L,
	KRB5_PROG_ETYPE_NOSUPP = -1765328234L,
	KRB5_PROG_KEYTYPE_NOSUPP = -1765328233L,
	KRB5_WRONG_ETYPE = -1765328232L,
	KRB5_PROG_SUMTYPE_NOSUPP = -1765328231L,
	KRB5_REALM_UNKNOWN = -1765328230L,
	KRB5_SERVICE_UNKNOWN = -1765328229L,
	KRB5_KDC_UNREACH = -1765328228L,
	KRB5_NO_LOCALNAME = -1765328227L,
	KRB5_MUTUAL_FAILED = -1765328226L,
	KRB5_RC_TYPE_EXISTS = -1765328225L,
	KRB5_RC_MALLOC = -1765328224L,
	KRB5_RC_TYPE_NOTFOUND = -1765328223L,
	KRB5_RC_UNKNOWN = -1765328222L,
	KRB5_RC_REPLAY = -1765328221L,
	KRB5_RC_IO = -1765328220L,
	KRB5_RC_NOIO = -1765328219L,
	KRB5_RC_PARSE = -1765328218L,
	KRB5_RC_IO_EOF = -1765328217L,
	KRB5_RC_IO_MALLOC = -1765328216L,
	KRB5_RC_IO_PERM = -1765328215L,
	KRB5_RC_IO_IO = -1765328214L,
	KRB5_RC_IO_UNKNOWN = -1765328213L,
	KRB5_RC_IO_SPACE = -1765328212L,
	KRB5_TRANS_CANTOPEN = -1765328211L,
	KRB5_TRANS_BADFORMAT = -1765328210L,
	KRB5_LNAME_CANTOPEN = -1765328209L,
	KRB5_LNAME_NOTRANS = -1765328208L,
	KRB5_LNAME_BADFORMAT = -1765328207L,
	KRB5_CRYPTO_INTERNAL = -1765328206L,
	KRB5_KT_BADNAME = -1765328205L,
	KRB5_KT_UNKNOWN_TYPE = -1765328204L,
	KRB5_KT_NOTFOUND = -1765328203L,
	KRB5_KT_END = -1765328202L,
	KRB5_KT_NOWRITE = -1765328201L,
	KRB5_KT_IOERR = -1765328200L,
	KRB5_NO_TKT_IN_RLM = -1765328199L,
	KRB5DES_BAD_KEYPAR = -1765328198L,
	KRB5DES_WEAK_KEY = -1765328197L,
	KRB5_BAD_ENCTYPE = -1765328196L,
	KRB5_BAD_KEYSIZE = -1765328195L,
	KRB5_BAD_MSIZE = -1765328194L,
	KRB5_CC_TYPE_EXISTS = -1765328193L,
	KRB5_KT_TYPE_EXISTS = -1765328192L,
	KRB5_CC_IO = -1765328191L,
	KRB5_FCC_PERM = -1765328190L,
	KRB5_FCC_NOFILE = -1765328189L,
	KRB5_FCC_INTERNAL = -1765328188L,
	KRB5_CC_WRITE = -1765328187L,
	KRB5_CC_NOMEM = -1765328186L,
	KRB5_CC_FORMAT = -1765328185L,
	KRB5_CC_NOT_KTYPE = -1765328184L,
	KRB5_INVALID_FLAGS = -1765328183L,
	KRB5_NO_2ND_TKT = -1765328182L,
	KRB5_NOCREDS_SUPPLIED = -1765328181L,
	KRB5_SENDAUTH_BADAUTHVERS = -1765328180L,
	KRB5_SENDAUTH_BADAPPLVERS = -1765328179L,
	KRB5_SENDAUTH_BADRESPONSE = -1765328178L,
	KRB5_SENDAUTH_REJECTED = -1765328177L,
	KRB5_PREAUTH_BAD_TYPE = -1765328176L,
	KRB5_PREAUTH_NO_KEY = -1765328175L,
	KRB5_PREAUTH_FAILED = -1765328174L,
	KRB5_RCACHE_BADVNO = -1765328173L,
	KRB5_CCACHE_BADVNO = -1765328172L,
	KRB5_KEYTAB_BADVNO = -1765328171L,
	KRB5_PROG_ATYPE_NOSUPP = -1765328170L,
	KRB5_RC_REQUIRED = -1765328169L,
	KRB5_ERR_BAD_HOSTNAME = -1765328168L,
	KRB5_ERR_HOST_REALM_UNKNOWN = -1765328167L,
	KRB5_SNAME_UNSUPP_NAMETYPE = -1765328166L,
	KRB5KRB_AP_ERR_V4_REPLY = -1765328165L,
	KRB5_REALM_CANT_RESOLVE = -1765328164L,
	KRB5_TKT_NOT_FORWARDABLE = -1765328163L,
	KRB5_FWD_BAD_PRINCIPAL = -1765328162L,
	KRB5_GET_IN_TKT_LOOP = -1765328161L,
	KRB5_CONFIG_NODEFREALM = -1765328160L,
	KRB5_SAM_UNSUPPORTED = -1765328159L,
	KRB5_SAM_INVALID_ETYPE = -1765328158L,
	KRB5_SAM_NO_CHECKSUM = -1765328157L,
	KRB5_SAM_BAD_CHECKSUM = -1765328156L,
	KRB5_KT_NAME_TOOLONG = -1765328155L,
	KRB5_KT_KVNONOTFOUND = -1765328154L,
	KRB5_APPL_EXPIRED = -1765328153L,
	KRB5_LIB_EXPIRED = -1765328152L,
	KRB5_CHPW_PWDNULL = -1765328151L,
	KRB5_CHPW_FAIL = -1765328150L,
	KRB5_KT_FORMAT = -1765328149L,
	KRB5_NOPERM_ETYPE = -1765328148L,
	KRB5_CONFIG_ETYPE_NOSUPP = -1765328147L,
	KRB5_OBSOLETE_FN = -1765328146L,
	KRB5_EAI_FAIL = -1765328145L,
	KRB5_EAI_NODATA = -1765328144L,
	KRB5_EAI_NONAME = -1765328143L,
	KRB5_EAI_SERVICE = -1765328142L,
	KRB5_ERR_NUMERIC_REALM = -1765328141L,
	KRB5_ERR_BAD_S2K_PARAMS = -1765328140L,
	KRB5_ERR_NO_SERVICE = -1765328139L,
	KRB5_CC_READONLY = -1765328138L,
	KRB5_CC_NOSUPP = -1765328137L,
	KRB5_DELTAT_BADFORMAT = -1765328136L,
	KRB5_PLUGIN_NO_HANDLE = -1765328135L,
	KRB5_PLUGIN_OP_NOTSUPP = -1765328134L,
	KRB5_ERR_INVALID_UTF8 = -1765328133L,
	KRB5_ERR_FAST_REQUIRED = -1765328132L,
	KRB5_LOCAL_ADDR_REQUIRED = -1765328131L,
	KRB5_REMOTE_ADDR_REQUIRED = -1765328130L,
	KRB5_TRACE_NOSUPP = -1765328129L
};

template<>
struct fmt::formatter<enum krb5_minor> {
	constexpr auto parse(format_parse_context& ctx) {
		auto it = ctx.begin();

		if (it != ctx.end() && *it != '}')
			throw format_error("invalid format");

		return it;
	}

	template<typename format_context>
	auto format(enum krb5_minor t, format_context& ctx) {
		switch (t) {
			case krb5_minor::KRB5KDC_ERR_NONE:
				return format_to(ctx.out(), "KRB5KDC_ERR_NONE");

			case krb5_minor::KRB5KDC_ERR_NAME_EXP:
				return format_to(ctx.out(), "KRB5KDC_ERR_NAME_EXP");

			case krb5_minor::KRB5KDC_ERR_SERVICE_EXP:
				return format_to(ctx.out(), "KRB5KDC_ERR_SERVICE_EXP");

			case krb5_minor::KRB5KDC_ERR_BAD_PVNO:
				return format_to(ctx.out(), "KRB5KDC_ERR_BAD_PVNO");

			case krb5_minor::KRB5KDC_ERR_C_OLD_MAST_KVNO:
				return format_to(ctx.out(), "KRB5KDC_ERR_C_OLD_MAST_KVNO");

			case krb5_minor::KRB5KDC_ERR_S_OLD_MAST_KVNO:
				return format_to(ctx.out(), "KRB5KDC_ERR_S_OLD_MAST_KVNO");

			case krb5_minor::KRB5KDC_ERR_C_PRINCIPAL_UNKNOWN:
				return format_to(ctx.out(), "KRB5KDC_ERR_C_PRINCIPAL_UNKNOWN");

			case krb5_minor::KRB5KDC_ERR_S_PRINCIPAL_UNKNOWN:
				return format_to(ctx.out(), "KRB5KDC_ERR_S_PRINCIPAL_UNKNOWN");

			case krb5_minor::KRB5KDC_ERR_PRINCIPAL_NOT_UNIQUE:
				return format_to(ctx.out(), "KRB5KDC_ERR_PRINCIPAL_NOT_UNIQUE");

			case krb5_minor::KRB5KDC_ERR_NULL_KEY:
				return format_to(ctx.out(), "KRB5KDC_ERR_NULL_KEY");

			case krb5_minor::KRB5KDC_ERR_CANNOT_POSTDATE:
				return format_to(ctx.out(), "KRB5KDC_ERR_CANNOT_POSTDATE");

			case krb5_minor::KRB5KDC_ERR_NEVER_VALID:
				return format_to(ctx.out(), "KRB5KDC_ERR_NEVER_VALID");

			case krb5_minor::KRB5KDC_ERR_POLICY:
				return format_to(ctx.out(), "KRB5KDC_ERR_POLICY");

			case krb5_minor::KRB5KDC_ERR_BADOPTION:
				return format_to(ctx.out(), "KRB5KDC_ERR_BADOPTION");

			case krb5_minor::KRB5KDC_ERR_ETYPE_NOSUPP:
				return format_to(ctx.out(), "KRB5KDC_ERR_ETYPE_NOSUPP");

			case krb5_minor::KRB5KDC_ERR_SUMTYPE_NOSUPP:
				return format_to(ctx.out(), "KRB5KDC_ERR_SUMTYPE_NOSUPP");

			case krb5_minor::KRB5KDC_ERR_PADATA_TYPE_NOSUPP:
				return format_to(ctx.out(), "KRB5KDC_ERR_PADATA_TYPE_NOSUPP");

			case krb5_minor::KRB5KDC_ERR_TRTYPE_NOSUPP:
				return format_to(ctx.out(), "KRB5KDC_ERR_TRTYPE_NOSUPP");

			case krb5_minor::KRB5KDC_ERR_CLIENT_REVOKED:
				return format_to(ctx.out(), "KRB5KDC_ERR_CLIENT_REVOKED");

			case krb5_minor::KRB5KDC_ERR_SERVICE_REVOKED:
				return format_to(ctx.out(), "KRB5KDC_ERR_SERVICE_REVOKED");

			case krb5_minor::KRB5KDC_ERR_TGT_REVOKED:
				return format_to(ctx.out(), "KRB5KDC_ERR_TGT_REVOKED");

			case krb5_minor::KRB5KDC_ERR_CLIENT_NOTYET:
				return format_to(ctx.out(), "KRB5KDC_ERR_CLIENT_NOTYET");

			case krb5_minor::KRB5KDC_ERR_SERVICE_NOTYET:
				return format_to(ctx.out(), "KRB5KDC_ERR_SERVICE_NOTYET");

			case krb5_minor::KRB5KDC_ERR_KEY_EXP:
				return format_to(ctx.out(), "KRB5KDC_ERR_KEY_EXP");

			case krb5_minor::KRB5KDC_ERR_PREAUTH_FAILED:
				return format_to(ctx.out(), "KRB5KDC_ERR_PREAUTH_FAILED");

			case krb5_minor::KRB5KDC_ERR_PREAUTH_REQUIRED:
				return format_to(ctx.out(), "KRB5KDC_ERR_PREAUTH_REQUIRED");

			case krb5_minor::KRB5KDC_ERR_SERVER_NOMATCH:
				return format_to(ctx.out(), "KRB5KDC_ERR_SERVER_NOMATCH");

			case krb5_minor::KRB5KDC_ERR_MUST_USE_USER2USER:
				return format_to(ctx.out(), "KRB5KDC_ERR_MUST_USE_USER2USER");

			case krb5_minor::KRB5KDC_ERR_PATH_NOT_ACCEPTED:
				return format_to(ctx.out(), "KRB5KDC_ERR_PATH_NOT_ACCEPTED");

			case krb5_minor::KRB5KDC_ERR_SVC_UNAVAILABLE:
				return format_to(ctx.out(), "KRB5KDC_ERR_SVC_UNAVAILABLE");

			case krb5_minor::KRB5PLACEHOLD_30:
				return format_to(ctx.out(), "KRB5PLACEHOLD_30");

			case krb5_minor::KRB5KRB_AP_ERR_BAD_INTEGRITY:
				return format_to(ctx.out(), "KRB5KRB_AP_ERR_BAD_INTEGRITY");

			case krb5_minor::KRB5KRB_AP_ERR_TKT_EXPIRED:
				return format_to(ctx.out(), "KRB5KRB_AP_ERR_TKT_EXPIRED");

			case krb5_minor::KRB5KRB_AP_ERR_TKT_NYV:
				return format_to(ctx.out(), "KRB5KRB_AP_ERR_TKT_NYV");

			case krb5_minor::KRB5KRB_AP_ERR_REPEAT:
				return format_to(ctx.out(), "KRB5KRB_AP_ERR_REPEAT");

			case krb5_minor::KRB5KRB_AP_ERR_NOT_US:
				return format_to(ctx.out(), "KRB5KRB_AP_ERR_NOT_US");

			case krb5_minor::KRB5KRB_AP_ERR_BADMATCH:
				return format_to(ctx.out(), "KRB5KRB_AP_ERR_BADMATCH");

			case krb5_minor::KRB5KRB_AP_ERR_SKEW:
				return format_to(ctx.out(), "KRB5KRB_AP_ERR_SKEW");

			case krb5_minor::KRB5KRB_AP_ERR_BADADDR:
				return format_to(ctx.out(), "KRB5KRB_AP_ERR_BADADDR");

			case krb5_minor::KRB5KRB_AP_ERR_BADVERSION:
				return format_to(ctx.out(), "KRB5KRB_AP_ERR_BADVERSION");

			case krb5_minor::KRB5KRB_AP_ERR_MSG_TYPE:
				return format_to(ctx.out(), "KRB5KRB_AP_ERR_MSG_TYPE");

			case krb5_minor::KRB5KRB_AP_ERR_MODIFIED:
				return format_to(ctx.out(), "KRB5KRB_AP_ERR_MODIFIED");

			case krb5_minor::KRB5KRB_AP_ERR_BADORDER:
				return format_to(ctx.out(), "KRB5KRB_AP_ERR_BADORDER");

			case krb5_minor::KRB5KRB_AP_ERR_ILL_CR_TKT:
				return format_to(ctx.out(), "KRB5KRB_AP_ERR_ILL_CR_TKT");

			case krb5_minor::KRB5KRB_AP_ERR_BADKEYVER:
				return format_to(ctx.out(), "KRB5KRB_AP_ERR_BADKEYVER");

			case krb5_minor::KRB5KRB_AP_ERR_NOKEY:
				return format_to(ctx.out(), "KRB5KRB_AP_ERR_NOKEY");

			case krb5_minor::KRB5KRB_AP_ERR_MUT_FAIL:
				return format_to(ctx.out(), "KRB5KRB_AP_ERR_MUT_FAIL");

			case krb5_minor::KRB5KRB_AP_ERR_BADDIRECTION:
				return format_to(ctx.out(), "KRB5KRB_AP_ERR_BADDIRECTION");

			case krb5_minor::KRB5KRB_AP_ERR_METHOD:
				return format_to(ctx.out(), "KRB5KRB_AP_ERR_METHOD");

			case krb5_minor::KRB5KRB_AP_ERR_BADSEQ:
				return format_to(ctx.out(), "KRB5KRB_AP_ERR_BADSEQ");

			case krb5_minor::KRB5KRB_AP_ERR_INAPP_CKSUM:
				return format_to(ctx.out(), "KRB5KRB_AP_ERR_INAPP_CKSUM");

			case krb5_minor::KRB5KRB_AP_PATH_NOT_ACCEPTED:
				return format_to(ctx.out(), "KRB5KRB_AP_PATH_NOT_ACCEPTED");

			case krb5_minor::KRB5KRB_ERR_RESPONSE_TOO_BIG:
				return format_to(ctx.out(), "KRB5KRB_ERR_RESPONSE_TOO_BIG");

			case krb5_minor::KRB5PLACEHOLD_53:
				return format_to(ctx.out(), "KRB5PLACEHOLD_53");

			case krb5_minor::KRB5PLACEHOLD_54:
				return format_to(ctx.out(), "KRB5PLACEHOLD_54");

			case krb5_minor::KRB5PLACEHOLD_55:
				return format_to(ctx.out(), "KRB5PLACEHOLD_55");

			case krb5_minor::KRB5PLACEHOLD_56:
				return format_to(ctx.out(), "KRB5PLACEHOLD_56");

			case krb5_minor::KRB5PLACEHOLD_57:
				return format_to(ctx.out(), "KRB5PLACEHOLD_57");

			case krb5_minor::KRB5PLACEHOLD_58:
				return format_to(ctx.out(), "KRB5PLACEHOLD_58");

			case krb5_minor::KRB5PLACEHOLD_59:
				return format_to(ctx.out(), "KRB5PLACEHOLD_59");

			case krb5_minor::KRB5KRB_ERR_GENERIC:
				return format_to(ctx.out(), "KRB5KRB_ERR_GENERIC");

			case krb5_minor::KRB5KRB_ERR_FIELD_TOOLONG:
				return format_to(ctx.out(), "KRB5KRB_ERR_FIELD_TOOLONG");

			case krb5_minor::KRB5KDC_ERR_CLIENT_NOT_TRUSTED:
				return format_to(ctx.out(), "KRB5KDC_ERR_CLIENT_NOT_TRUSTED");

			case krb5_minor::KRB5KDC_ERR_KDC_NOT_TRUSTED:
				return format_to(ctx.out(), "KRB5KDC_ERR_KDC_NOT_TRUSTED");

			case krb5_minor::KRB5KDC_ERR_INVALID_SIG:
				return format_to(ctx.out(), "KRB5KDC_ERR_INVALID_SIG");

			case krb5_minor::KRB5KDC_ERR_DH_KEY_PARAMETERS_NOT_ACCEPTED:
				return format_to(ctx.out(), "KRB5KDC_ERR_DH_KEY_PARAMETERS_NOT_ACCEPTED");

			case krb5_minor::KRB5KDC_ERR_CERTIFICATE_MISMATCH:
				return format_to(ctx.out(), "KRB5KDC_ERR_CERTIFICATE_MISMATCH");

			case krb5_minor::KRB5KRB_AP_ERR_NO_TGT:
				return format_to(ctx.out(), "KRB5KRB_AP_ERR_NO_TGT");

			case krb5_minor::KRB5KDC_ERR_WRONG_REALM:
				return format_to(ctx.out(), "KRB5KDC_ERR_WRONG_REALM");

			case krb5_minor::KRB5KRB_AP_ERR_USER_TO_USER_REQUIRED:
				return format_to(ctx.out(), "KRB5KRB_AP_ERR_USER_TO_USER_REQUIRED");

			case krb5_minor::KRB5KDC_ERR_CANT_VERIFY_CERTIFICATE:
				return format_to(ctx.out(), "KRB5KDC_ERR_CANT_VERIFY_CERTIFICATE");

			case krb5_minor::KRB5KDC_ERR_INVALID_CERTIFICATE:
				return format_to(ctx.out(), "KRB5KDC_ERR_INVALID_CERTIFICATE");

			case krb5_minor::KRB5KDC_ERR_REVOKED_CERTIFICATE:
				return format_to(ctx.out(), "KRB5KDC_ERR_REVOKED_CERTIFICATE");

			case krb5_minor::KRB5KDC_ERR_REVOCATION_STATUS_UNKNOWN:
				return format_to(ctx.out(), "KRB5KDC_ERR_REVOCATION_STATUS_UNKNOWN");

			case krb5_minor::KRB5KDC_ERR_REVOCATION_STATUS_UNAVAILABLE:
				return format_to(ctx.out(), "KRB5KDC_ERR_REVOCATION_STATUS_UNAVAILABLE");

			case krb5_minor::KRB5KDC_ERR_CLIENT_NAME_MISMATCH:
				return format_to(ctx.out(), "KRB5KDC_ERR_CLIENT_NAME_MISMATCH");

			case krb5_minor::KRB5KDC_ERR_KDC_NAME_MISMATCH:
				return format_to(ctx.out(), "KRB5KDC_ERR_KDC_NAME_MISMATCH");

			case krb5_minor::KRB5KDC_ERR_INCONSISTENT_KEY_PURPOSE:
				return format_to(ctx.out(), "KRB5KDC_ERR_INCONSISTENT_KEY_PURPOSE");

			case krb5_minor::KRB5KDC_ERR_DIGEST_IN_CERT_NOT_ACCEPTED:
				return format_to(ctx.out(), "KRB5KDC_ERR_DIGEST_IN_CERT_NOT_ACCEPTED");

			case krb5_minor::KRB5KDC_ERR_PA_CHECKSUM_MUST_BE_INCLUDED:
				return format_to(ctx.out(), "KRB5KDC_ERR_PA_CHECKSUM_MUST_BE_INCLUDED");

			case krb5_minor::KRB5KDC_ERR_DIGEST_IN_SIGNED_DATA_NOT_ACCEPTED:
				return format_to(ctx.out(), "KRB5KDC_ERR_DIGEST_IN_SIGNED_DATA_NOT_ACCEPTED");

			case krb5_minor::KRB5KDC_ERR_PUBLIC_KEY_ENCRYPTION_NOT_SUPPORTED:
				return format_to(ctx.out(), "KRB5KDC_ERR_PUBLIC_KEY_ENCRYPTION_NOT_SUPPORTED");

			case krb5_minor::KRB5PLACEHOLD_82:
				return format_to(ctx.out(), "KRB5PLACEHOLD_82");

			case krb5_minor::KRB5PLACEHOLD_83:
				return format_to(ctx.out(), "KRB5PLACEHOLD_83");

			case krb5_minor::KRB5PLACEHOLD_84:
				return format_to(ctx.out(), "KRB5PLACEHOLD_84");

			case krb5_minor::KRB5KRB_AP_ERR_IAKERB_KDC_NOT_FOUND:
				return format_to(ctx.out(), "KRB5KRB_AP_ERR_IAKERB_KDC_NOT_FOUND");

			case krb5_minor::KRB5KRB_AP_ERR_IAKERB_KDC_NO_RESPONSE:
				return format_to(ctx.out(), "KRB5KRB_AP_ERR_IAKERB_KDC_NO_RESPONSE");

			case krb5_minor::KRB5PLACEHOLD_87:
				return format_to(ctx.out(), "KRB5PLACEHOLD_87");

			case krb5_minor::KRB5PLACEHOLD_88:
				return format_to(ctx.out(), "KRB5PLACEHOLD_88");

			case krb5_minor::KRB5PLACEHOLD_89:
				return format_to(ctx.out(), "KRB5PLACEHOLD_89");

			case krb5_minor::KRB5KDC_ERR_PREAUTH_EXPIRED:
				return format_to(ctx.out(), "KRB5KDC_ERR_PREAUTH_EXPIRED");

			case krb5_minor::KRB5KDC_ERR_MORE_PREAUTH_DATA_REQUIRED:
				return format_to(ctx.out(), "KRB5KDC_ERR_MORE_PREAUTH_DATA_REQUIRED");

			case krb5_minor::KRB5PLACEHOLD_92:
				return format_to(ctx.out(), "KRB5PLACEHOLD_92");

			case krb5_minor::KRB5KDC_ERR_UNKNOWN_CRITICAL_FAST_OPTION:
				return format_to(ctx.out(), "KRB5KDC_ERR_UNKNOWN_CRITICAL_FAST_OPTION");

			case krb5_minor::KRB5PLACEHOLD_94:
				return format_to(ctx.out(), "KRB5PLACEHOLD_94");

			case krb5_minor::KRB5PLACEHOLD_95:
				return format_to(ctx.out(), "KRB5PLACEHOLD_95");

			case krb5_minor::KRB5PLACEHOLD_96:
				return format_to(ctx.out(), "KRB5PLACEHOLD_96");

			case krb5_minor::KRB5PLACEHOLD_97:
				return format_to(ctx.out(), "KRB5PLACEHOLD_97");

			case krb5_minor::KRB5PLACEHOLD_98:
				return format_to(ctx.out(), "KRB5PLACEHOLD_98");

			case krb5_minor::KRB5PLACEHOLD_99:
				return format_to(ctx.out(), "KRB5PLACEHOLD_99");

			case krb5_minor::KRB5KDC_ERR_NO_ACCEPTABLE_KDF:
				return format_to(ctx.out(), "KRB5KDC_ERR_NO_ACCEPTABLE_KDF");

			case krb5_minor::KRB5PLACEHOLD_101:
				return format_to(ctx.out(), "KRB5PLACEHOLD_101");

			case krb5_minor::KRB5PLACEHOLD_102:
				return format_to(ctx.out(), "KRB5PLACEHOLD_102");

			case krb5_minor::KRB5PLACEHOLD_103:
				return format_to(ctx.out(), "KRB5PLACEHOLD_103");

			case krb5_minor::KRB5PLACEHOLD_104:
				return format_to(ctx.out(), "KRB5PLACEHOLD_104");

			case krb5_minor::KRB5PLACEHOLD_105:
				return format_to(ctx.out(), "KRB5PLACEHOLD_105");

			case krb5_minor::KRB5PLACEHOLD_106:
				return format_to(ctx.out(), "KRB5PLACEHOLD_106");

			case krb5_minor::KRB5PLACEHOLD_107:
				return format_to(ctx.out(), "KRB5PLACEHOLD_107");

			case krb5_minor::KRB5PLACEHOLD_108:
				return format_to(ctx.out(), "KRB5PLACEHOLD_108");

			case krb5_minor::KRB5PLACEHOLD_109:
				return format_to(ctx.out(), "KRB5PLACEHOLD_109");

			case krb5_minor::KRB5PLACEHOLD_110:
				return format_to(ctx.out(), "KRB5PLACEHOLD_110");

			case krb5_minor::KRB5PLACEHOLD_111:
				return format_to(ctx.out(), "KRB5PLACEHOLD_111");

			case krb5_minor::KRB5PLACEHOLD_112:
				return format_to(ctx.out(), "KRB5PLACEHOLD_112");

			case krb5_minor::KRB5PLACEHOLD_113:
				return format_to(ctx.out(), "KRB5PLACEHOLD_113");

			case krb5_minor::KRB5PLACEHOLD_114:
				return format_to(ctx.out(), "KRB5PLACEHOLD_114");

			case krb5_minor::KRB5PLACEHOLD_115:
				return format_to(ctx.out(), "KRB5PLACEHOLD_115");

			case krb5_minor::KRB5PLACEHOLD_116:
				return format_to(ctx.out(), "KRB5PLACEHOLD_116");

			case krb5_minor::KRB5PLACEHOLD_117:
				return format_to(ctx.out(), "KRB5PLACEHOLD_117");

			case krb5_minor::KRB5PLACEHOLD_118:
				return format_to(ctx.out(), "KRB5PLACEHOLD_118");

			case krb5_minor::KRB5PLACEHOLD_119:
				return format_to(ctx.out(), "KRB5PLACEHOLD_119");

			case krb5_minor::KRB5PLACEHOLD_120:
				return format_to(ctx.out(), "KRB5PLACEHOLD_120");

			case krb5_minor::KRB5PLACEHOLD_121:
				return format_to(ctx.out(), "KRB5PLACEHOLD_121");

			case krb5_minor::KRB5PLACEHOLD_122:
				return format_to(ctx.out(), "KRB5PLACEHOLD_122");

			case krb5_minor::KRB5PLACEHOLD_123:
				return format_to(ctx.out(), "KRB5PLACEHOLD_123");

			case krb5_minor::KRB5PLACEHOLD_124:
				return format_to(ctx.out(), "KRB5PLACEHOLD_124");

			case krb5_minor::KRB5PLACEHOLD_125:
				return format_to(ctx.out(), "KRB5PLACEHOLD_125");

			case krb5_minor::KRB5PLACEHOLD_126:
				return format_to(ctx.out(), "KRB5PLACEHOLD_126");

			case krb5_minor::KRB5PLACEHOLD_127:
				return format_to(ctx.out(), "KRB5PLACEHOLD_127");

			case krb5_minor::KRB5_ERR_RCSID:
				return format_to(ctx.out(), "KRB5_ERR_RCSID");

			case krb5_minor::KRB5_LIBOS_BADLOCKFLAG:
				return format_to(ctx.out(), "KRB5_LIBOS_BADLOCKFLAG");

			case krb5_minor::KRB5_LIBOS_CANTREADPWD:
				return format_to(ctx.out(), "KRB5_LIBOS_CANTREADPWD");

			case krb5_minor::KRB5_LIBOS_BADPWDMATCH:
				return format_to(ctx.out(), "KRB5_LIBOS_BADPWDMATCH");

			case krb5_minor::KRB5_LIBOS_PWDINTR:
				return format_to(ctx.out(), "KRB5_LIBOS_PWDINTR");

			case krb5_minor::KRB5_PARSE_ILLCHAR:
				return format_to(ctx.out(), "KRB5_PARSE_ILLCHAR");

			case krb5_minor::KRB5_PARSE_MALFORMED:
				return format_to(ctx.out(), "KRB5_PARSE_MALFORMED");

			case krb5_minor::KRB5_CONFIG_CANTOPEN:
				return format_to(ctx.out(), "KRB5_CONFIG_CANTOPEN");

			case krb5_minor::KRB5_CONFIG_BADFORMAT:
				return format_to(ctx.out(), "KRB5_CONFIG_BADFORMAT");

			case krb5_minor::KRB5_CONFIG_NOTENUFSPACE:
				return format_to(ctx.out(), "KRB5_CONFIG_NOTENUFSPACE");

			case krb5_minor::KRB5_BADMSGTYPE:
				return format_to(ctx.out(), "KRB5_BADMSGTYPE");

			case krb5_minor::KRB5_CC_BADNAME:
				return format_to(ctx.out(), "KRB5_CC_BADNAME");

			case krb5_minor::KRB5_CC_UNKNOWN_TYPE:
				return format_to(ctx.out(), "KRB5_CC_UNKNOWN_TYPE");

			case krb5_minor::KRB5_CC_NOTFOUND:
				return format_to(ctx.out(), "KRB5_CC_NOTFOUND");

			case krb5_minor::KRB5_CC_END:
				return format_to(ctx.out(), "KRB5_CC_END");

			case krb5_minor::KRB5_NO_TKT_SUPPLIED:
				return format_to(ctx.out(), "KRB5_NO_TKT_SUPPLIED");

			case krb5_minor::KRB5KRB_AP_WRONG_PRINC:
				return format_to(ctx.out(), "KRB5KRB_AP_WRONG_PRINC");

			case krb5_minor::KRB5KRB_AP_ERR_TKT_INVALID:
				return format_to(ctx.out(), "KRB5KRB_AP_ERR_TKT_INVALID");

			case krb5_minor::KRB5_PRINC_NOMATCH:
				return format_to(ctx.out(), "KRB5_PRINC_NOMATCH");

			case krb5_minor::KRB5_KDCREP_MODIFIED:
				return format_to(ctx.out(), "KRB5_KDCREP_MODIFIED");

			case krb5_minor::KRB5_KDCREP_SKEW:
				return format_to(ctx.out(), "KRB5_KDCREP_SKEW");

			case krb5_minor::KRB5_IN_TKT_REALM_MISMATCH:
				return format_to(ctx.out(), "KRB5_IN_TKT_REALM_MISMATCH");

			case krb5_minor::KRB5_PROG_ETYPE_NOSUPP:
				return format_to(ctx.out(), "KRB5_PROG_ETYPE_NOSUPP");

			case krb5_minor::KRB5_PROG_KEYTYPE_NOSUPP:
				return format_to(ctx.out(), "KRB5_PROG_KEYTYPE_NOSUPP");

			case krb5_minor::KRB5_WRONG_ETYPE:
				return format_to(ctx.out(), "KRB5_WRONG_ETYPE");

			case krb5_minor::KRB5_PROG_SUMTYPE_NOSUPP:
				return format_to(ctx.out(), "KRB5_PROG_SUMTYPE_NOSUPP");

			case krb5_minor::KRB5_REALM_UNKNOWN:
				return format_to(ctx.out(), "KRB5_REALM_UNKNOWN");

			case krb5_minor::KRB5_SERVICE_UNKNOWN:
				return format_to(ctx.out(), "KRB5_SERVICE_UNKNOWN");

			case krb5_minor::KRB5_KDC_UNREACH:
				return format_to(ctx.out(), "KRB5_KDC_UNREACH");

			case krb5_minor::KRB5_NO_LOCALNAME:
				return format_to(ctx.out(), "KRB5_NO_LOCALNAME");

			case krb5_minor::KRB5_MUTUAL_FAILED:
				return format_to(ctx.out(), "KRB5_MUTUAL_FAILED");

			case krb5_minor::KRB5_RC_TYPE_EXISTS:
				return format_to(ctx.out(), "KRB5_RC_TYPE_EXISTS");

			case krb5_minor::KRB5_RC_MALLOC:
				return format_to(ctx.out(), "KRB5_RC_MALLOC");

			case krb5_minor::KRB5_RC_TYPE_NOTFOUND:
				return format_to(ctx.out(), "KRB5_RC_TYPE_NOTFOUND");

			case krb5_minor::KRB5_RC_UNKNOWN:
				return format_to(ctx.out(), "KRB5_RC_UNKNOWN");

			case krb5_minor::KRB5_RC_REPLAY:
				return format_to(ctx.out(), "KRB5_RC_REPLAY");

			case krb5_minor::KRB5_RC_IO:
				return format_to(ctx.out(), "KRB5_RC_IO");

			case krb5_minor::KRB5_RC_NOIO:
				return format_to(ctx.out(), "KRB5_RC_NOIO");

			case krb5_minor::KRB5_RC_PARSE:
				return format_to(ctx.out(), "KRB5_RC_PARSE");

			case krb5_minor::KRB5_RC_IO_EOF:
				return format_to(ctx.out(), "KRB5_RC_IO_EOF");

			case krb5_minor::KRB5_RC_IO_MALLOC:
				return format_to(ctx.out(), "KRB5_RC_IO_MALLOC");

			case krb5_minor::KRB5_RC_IO_PERM:
				return format_to(ctx.out(), "KRB5_RC_IO_PERM");

			case krb5_minor::KRB5_RC_IO_IO:
				return format_to(ctx.out(), "KRB5_RC_IO_IO");

			case krb5_minor::KRB5_RC_IO_UNKNOWN:
				return format_to(ctx.out(), "KRB5_RC_IO_UNKNOWN");

			case krb5_minor::KRB5_RC_IO_SPACE:
				return format_to(ctx.out(), "KRB5_RC_IO_SPACE");

			case krb5_minor::KRB5_TRANS_CANTOPEN:
				return format_to(ctx.out(), "KRB5_TRANS_CANTOPEN");

			case krb5_minor::KRB5_TRANS_BADFORMAT:
				return format_to(ctx.out(), "KRB5_TRANS_BADFORMAT");

			case krb5_minor::KRB5_LNAME_CANTOPEN:
				return format_to(ctx.out(), "KRB5_LNAME_CANTOPEN");

			case krb5_minor::KRB5_LNAME_NOTRANS:
				return format_to(ctx.out(), "KRB5_LNAME_NOTRANS");

			case krb5_minor::KRB5_LNAME_BADFORMAT:
				return format_to(ctx.out(), "KRB5_LNAME_BADFORMAT");

			case krb5_minor::KRB5_CRYPTO_INTERNAL:
				return format_to(ctx.out(), "KRB5_CRYPTO_INTERNAL");

			case krb5_minor::KRB5_KT_BADNAME:
				return format_to(ctx.out(), "KRB5_KT_BADNAME");

			case krb5_minor::KRB5_KT_UNKNOWN_TYPE:
				return format_to(ctx.out(), "KRB5_KT_UNKNOWN_TYPE");

			case krb5_minor::KRB5_KT_NOTFOUND:
				return format_to(ctx.out(), "KRB5_KT_NOTFOUND");

			case krb5_minor::KRB5_KT_END:
				return format_to(ctx.out(), "KRB5_KT_END");

			case krb5_minor::KRB5_KT_NOWRITE:
				return format_to(ctx.out(), "KRB5_KT_NOWRITE");

			case krb5_minor::KRB5_KT_IOERR:
				return format_to(ctx.out(), "KRB5_KT_IOERR");

			case krb5_minor::KRB5_NO_TKT_IN_RLM:
				return format_to(ctx.out(), "KRB5_NO_TKT_IN_RLM");

			case krb5_minor::KRB5DES_BAD_KEYPAR:
				return format_to(ctx.out(), "KRB5DES_BAD_KEYPAR");

			case krb5_minor::KRB5DES_WEAK_KEY:
				return format_to(ctx.out(), "KRB5DES_WEAK_KEY");

			case krb5_minor::KRB5_BAD_ENCTYPE:
				return format_to(ctx.out(), "KRB5_BAD_ENCTYPE");

			case krb5_minor::KRB5_BAD_KEYSIZE:
				return format_to(ctx.out(), "KRB5_BAD_KEYSIZE");

			case krb5_minor::KRB5_BAD_MSIZE:
				return format_to(ctx.out(), "KRB5_BAD_MSIZE");

			case krb5_minor::KRB5_CC_TYPE_EXISTS:
				return format_to(ctx.out(), "KRB5_CC_TYPE_EXISTS");

			case krb5_minor::KRB5_KT_TYPE_EXISTS:
				return format_to(ctx.out(), "KRB5_KT_TYPE_EXISTS");

			case krb5_minor::KRB5_CC_IO:
				return format_to(ctx.out(), "KRB5_CC_IO");

			case krb5_minor::KRB5_FCC_PERM:
				return format_to(ctx.out(), "KRB5_FCC_PERM");

			case krb5_minor::KRB5_FCC_NOFILE:
				return format_to(ctx.out(), "KRB5_FCC_NOFILE");

			case krb5_minor::KRB5_FCC_INTERNAL:
				return format_to(ctx.out(), "KRB5_FCC_INTERNAL");

			case krb5_minor::KRB5_CC_WRITE:
				return format_to(ctx.out(), "KRB5_CC_WRITE");

			case krb5_minor::KRB5_CC_NOMEM:
				return format_to(ctx.out(), "KRB5_CC_NOMEM");

			case krb5_minor::KRB5_CC_FORMAT:
				return format_to(ctx.out(), "KRB5_CC_FORMAT");

			case krb5_minor::KRB5_CC_NOT_KTYPE:
				return format_to(ctx.out(), "KRB5_CC_NOT_KTYPE");

			case krb5_minor::KRB5_INVALID_FLAGS:
				return format_to(ctx.out(), "KRB5_INVALID_FLAGS");

			case krb5_minor::KRB5_NO_2ND_TKT:
				return format_to(ctx.out(), "KRB5_NO_2ND_TKT");

			case krb5_minor::KRB5_NOCREDS_SUPPLIED:
				return format_to(ctx.out(), "KRB5_NOCREDS_SUPPLIED");

			case krb5_minor::KRB5_SENDAUTH_BADAUTHVERS:
				return format_to(ctx.out(), "KRB5_SENDAUTH_BADAUTHVERS");

			case krb5_minor::KRB5_SENDAUTH_BADAPPLVERS:
				return format_to(ctx.out(), "KRB5_SENDAUTH_BADAPPLVERS");

			case krb5_minor::KRB5_SENDAUTH_BADRESPONSE:
				return format_to(ctx.out(), "KRB5_SENDAUTH_BADRESPONSE");

			case krb5_minor::KRB5_SENDAUTH_REJECTED:
				return format_to(ctx.out(), "KRB5_SENDAUTH_REJECTED");

			case krb5_minor::KRB5_PREAUTH_BAD_TYPE:
				return format_to(ctx.out(), "KRB5_PREAUTH_BAD_TYPE");

			case krb5_minor::KRB5_PREAUTH_NO_KEY:
				return format_to(ctx.out(), "KRB5_PREAUTH_NO_KEY");

			case krb5_minor::KRB5_PREAUTH_FAILED:
				return format_to(ctx.out(), "KRB5_PREAUTH_FAILED");

			case krb5_minor::KRB5_RCACHE_BADVNO:
				return format_to(ctx.out(), "KRB5_RCACHE_BADVNO");

			case krb5_minor::KRB5_CCACHE_BADVNO:
				return format_to(ctx.out(), "KRB5_CCACHE_BADVNO");

			case krb5_minor::KRB5_KEYTAB_BADVNO:
				return format_to(ctx.out(), "KRB5_KEYTAB_BADVNO");

			case krb5_minor::KRB5_PROG_ATYPE_NOSUPP:
				return format_to(ctx.out(), "KRB5_PROG_ATYPE_NOSUPP");

			case krb5_minor::KRB5_RC_REQUIRED:
				return format_to(ctx.out(), "KRB5_RC_REQUIRED");

			case krb5_minor::KRB5_ERR_BAD_HOSTNAME:
				return format_to(ctx.out(), "KRB5_ERR_BAD_HOSTNAME");

			case krb5_minor::KRB5_ERR_HOST_REALM_UNKNOWN:
				return format_to(ctx.out(), "KRB5_ERR_HOST_REALM_UNKNOWN");

			case krb5_minor::KRB5_SNAME_UNSUPP_NAMETYPE:
				return format_to(ctx.out(), "KRB5_SNAME_UNSUPP_NAMETYPE");

			case krb5_minor::KRB5KRB_AP_ERR_V4_REPLY:
				return format_to(ctx.out(), "KRB5KRB_AP_ERR_V4_REPLY");

			case krb5_minor::KRB5_REALM_CANT_RESOLVE:
				return format_to(ctx.out(), "KRB5_REALM_CANT_RESOLVE");

			case krb5_minor::KRB5_TKT_NOT_FORWARDABLE:
				return format_to(ctx.out(), "KRB5_TKT_NOT_FORWARDABLE");

			case krb5_minor::KRB5_FWD_BAD_PRINCIPAL:
				return format_to(ctx.out(), "KRB5_FWD_BAD_PRINCIPAL");

			case krb5_minor::KRB5_GET_IN_TKT_LOOP:
				return format_to(ctx.out(), "KRB5_GET_IN_TKT_LOOP");

			case krb5_minor::KRB5_CONFIG_NODEFREALM:
				return format_to(ctx.out(), "KRB5_CONFIG_NODEFREALM");

			case krb5_minor::KRB5_SAM_UNSUPPORTED:
				return format_to(ctx.out(), "KRB5_SAM_UNSUPPORTED");

			case krb5_minor::KRB5_SAM_INVALID_ETYPE:
				return format_to(ctx.out(), "KRB5_SAM_INVALID_ETYPE");

			case krb5_minor::KRB5_SAM_NO_CHECKSUM:
				return format_to(ctx.out(), "KRB5_SAM_NO_CHECKSUM");

			case krb5_minor::KRB5_SAM_BAD_CHECKSUM:
				return format_to(ctx.out(), "KRB5_SAM_BAD_CHECKSUM");

			case krb5_minor::KRB5_KT_NAME_TOOLONG:
				return format_to(ctx.out(), "KRB5_KT_NAME_TOOLONG");

			case krb5_minor::KRB5_KT_KVNONOTFOUND:
				return format_to(ctx.out(), "KRB5_KT_KVNONOTFOUND");

			case krb5_minor::KRB5_APPL_EXPIRED:
				return format_to(ctx.out(), "KRB5_APPL_EXPIRED");

			case krb5_minor::KRB5_LIB_EXPIRED:
				return format_to(ctx.out(), "KRB5_LIB_EXPIRED");

			case krb5_minor::KRB5_CHPW_PWDNULL:
				return format_to(ctx.out(), "KRB5_CHPW_PWDNULL");

			case krb5_minor::KRB5_CHPW_FAIL:
				return format_to(ctx.out(), "KRB5_CHPW_FAIL");

			case krb5_minor::KRB5_KT_FORMAT:
				return format_to(ctx.out(), "KRB5_KT_FORMAT");

			case krb5_minor::KRB5_NOPERM_ETYPE:
				return format_to(ctx.out(), "KRB5_NOPERM_ETYPE");

			case krb5_minor::KRB5_CONFIG_ETYPE_NOSUPP:
				return format_to(ctx.out(), "KRB5_CONFIG_ETYPE_NOSUPP");

			case krb5_minor::KRB5_OBSOLETE_FN:
				return format_to(ctx.out(), "KRB5_OBSOLETE_FN");

			case krb5_minor::KRB5_EAI_FAIL:
				return format_to(ctx.out(), "KRB5_EAI_FAIL");

			case krb5_minor::KRB5_EAI_NODATA:
				return format_to(ctx.out(), "KRB5_EAI_NODATA");

			case krb5_minor::KRB5_EAI_NONAME:
				return format_to(ctx.out(), "KRB5_EAI_NONAME");

			case krb5_minor::KRB5_EAI_SERVICE:
				return format_to(ctx.out(), "KRB5_EAI_SERVICE");

			case krb5_minor::KRB5_ERR_NUMERIC_REALM:
				return format_to(ctx.out(), "KRB5_ERR_NUMERIC_REALM");

			case krb5_minor::KRB5_ERR_BAD_S2K_PARAMS:
				return format_to(ctx.out(), "KRB5_ERR_BAD_S2K_PARAMS");

			case krb5_minor::KRB5_ERR_NO_SERVICE:
				return format_to(ctx.out(), "KRB5_ERR_NO_SERVICE");

			case krb5_minor::KRB5_CC_READONLY:
				return format_to(ctx.out(), "KRB5_CC_READONLY");

			case krb5_minor::KRB5_CC_NOSUPP:
				return format_to(ctx.out(), "KRB5_CC_NOSUPP");

			case krb5_minor::KRB5_DELTAT_BADFORMAT:
				return format_to(ctx.out(), "KRB5_DELTAT_BADFORMAT");

			case krb5_minor::KRB5_PLUGIN_NO_HANDLE:
				return format_to(ctx.out(), "KRB5_PLUGIN_NO_HANDLE");

			case krb5_minor::KRB5_PLUGIN_OP_NOTSUPP:
				return format_to(ctx.out(), "KRB5_PLUGIN_OP_NOTSUPP");

			case krb5_minor::KRB5_ERR_INVALID_UTF8:
				return format_to(ctx.out(), "KRB5_ERR_INVALID_UTF8");

			case krb5_minor::KRB5_ERR_FAST_REQUIRED:
				return format_to(ctx.out(), "KRB5_ERR_FAST_REQUIRED");

			case krb5_minor::KRB5_LOCAL_ADDR_REQUIRED:
				return format_to(ctx.out(), "KRB5_LOCAL_ADDR_REQUIRED");

			case krb5_minor::KRB5_REMOTE_ADDR_REQUIRED:
				return format_to(ctx.out(), "KRB5_REMOTE_ADDR_REQUIRED");

			case krb5_minor::KRB5_TRACE_NOSUPP:
				return format_to(ctx.out(), "KRB5_TRACE_NOSUPP");

			default:
				return format_to(ctx.out(), "{}", (int32_t)t);
		}
	}
};

class gss_error : public std::exception {
public:
	gss_error(const std::string_view& func, OM_uint32 major, OM_uint32 minor) {
		OM_uint32 message_context = 0;
		OM_uint32 min_status;
		gss_buffer_desc status_string;
		bool first = true;

		msg = fmt::format(FMT_STRING("{} failed (minor {}): "), func, (enum krb5_minor)minor);

		do {
			gss_display_status(&min_status, major, GSS_C_GSS_CODE, GSS_C_NO_OID,
							&message_context, &status_string);

			if (!first)
				msg += "; ";

			msg += std::string((char*)status_string.value, status_string.length);

			gss_release_buffer(&min_status, &status_string);
			first = false;
		} while (message_context != 0);
	}

	const char* what() const noexcept {
		return msg.c_str();
	}

private:
	std::string msg;
};
#endif
