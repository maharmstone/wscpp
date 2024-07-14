#pragma once

#ifdef __cpp_lib_format
#include <format>
namespace fmtns = std;
#else
#include <fmt/format.h>
namespace fmtns = fmt;
#endif

#include <string>

#ifndef _WIN32
#include <gssapi/gssapi.h>
#endif

class formatted_error : public std::exception {
public:
	template<typename... Args>
	formatted_error(fmtns::format_string<Args...> s, Args&&... args) : msg(fmtns::format(s, std::forward<Args>(args)...)) {
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
struct fmtns::formatter<enum krb5_minor> {
	constexpr auto parse(format_parse_context& ctx) {
		auto it = ctx.begin();

		if (it != ctx.end() && *it != '}')
			throw format_error("invalid format");

		return it;
	}

	template<typename format_context>
	auto format(enum krb5_minor t, format_context& ctx) const {
		switch (t) {
			case krb5_minor::KRB5KDC_ERR_NONE:
				return fmtns::format_to(ctx.out(), "KRB5KDC_ERR_NONE");

			case krb5_minor::KRB5KDC_ERR_NAME_EXP:
				return fmtns::format_to(ctx.out(), "KRB5KDC_ERR_NAME_EXP");

			case krb5_minor::KRB5KDC_ERR_SERVICE_EXP:
				return fmtns::format_to(ctx.out(), "KRB5KDC_ERR_SERVICE_EXP");

			case krb5_minor::KRB5KDC_ERR_BAD_PVNO:
				return fmtns::format_to(ctx.out(), "KRB5KDC_ERR_BAD_PVNO");

			case krb5_minor::KRB5KDC_ERR_C_OLD_MAST_KVNO:
				return fmtns::format_to(ctx.out(), "KRB5KDC_ERR_C_OLD_MAST_KVNO");

			case krb5_minor::KRB5KDC_ERR_S_OLD_MAST_KVNO:
				return fmtns::format_to(ctx.out(), "KRB5KDC_ERR_S_OLD_MAST_KVNO");

			case krb5_minor::KRB5KDC_ERR_C_PRINCIPAL_UNKNOWN:
				return fmtns::format_to(ctx.out(), "KRB5KDC_ERR_C_PRINCIPAL_UNKNOWN");

			case krb5_minor::KRB5KDC_ERR_S_PRINCIPAL_UNKNOWN:
				return fmtns::format_to(ctx.out(), "KRB5KDC_ERR_S_PRINCIPAL_UNKNOWN");

			case krb5_minor::KRB5KDC_ERR_PRINCIPAL_NOT_UNIQUE:
				return fmtns::format_to(ctx.out(), "KRB5KDC_ERR_PRINCIPAL_NOT_UNIQUE");

			case krb5_minor::KRB5KDC_ERR_NULL_KEY:
				return fmtns::format_to(ctx.out(), "KRB5KDC_ERR_NULL_KEY");

			case krb5_minor::KRB5KDC_ERR_CANNOT_POSTDATE:
				return fmtns::format_to(ctx.out(), "KRB5KDC_ERR_CANNOT_POSTDATE");

			case krb5_minor::KRB5KDC_ERR_NEVER_VALID:
				return fmtns::format_to(ctx.out(), "KRB5KDC_ERR_NEVER_VALID");

			case krb5_minor::KRB5KDC_ERR_POLICY:
				return fmtns::format_to(ctx.out(), "KRB5KDC_ERR_POLICY");

			case krb5_minor::KRB5KDC_ERR_BADOPTION:
				return fmtns::format_to(ctx.out(), "KRB5KDC_ERR_BADOPTION");

			case krb5_minor::KRB5KDC_ERR_ETYPE_NOSUPP:
				return fmtns::format_to(ctx.out(), "KRB5KDC_ERR_ETYPE_NOSUPP");

			case krb5_minor::KRB5KDC_ERR_SUMTYPE_NOSUPP:
				return fmtns::format_to(ctx.out(), "KRB5KDC_ERR_SUMTYPE_NOSUPP");

			case krb5_minor::KRB5KDC_ERR_PADATA_TYPE_NOSUPP:
				return fmtns::format_to(ctx.out(), "KRB5KDC_ERR_PADATA_TYPE_NOSUPP");

			case krb5_minor::KRB5KDC_ERR_TRTYPE_NOSUPP:
				return fmtns::format_to(ctx.out(), "KRB5KDC_ERR_TRTYPE_NOSUPP");

			case krb5_minor::KRB5KDC_ERR_CLIENT_REVOKED:
				return fmtns::format_to(ctx.out(), "KRB5KDC_ERR_CLIENT_REVOKED");

			case krb5_minor::KRB5KDC_ERR_SERVICE_REVOKED:
				return fmtns::format_to(ctx.out(), "KRB5KDC_ERR_SERVICE_REVOKED");

			case krb5_minor::KRB5KDC_ERR_TGT_REVOKED:
				return fmtns::format_to(ctx.out(), "KRB5KDC_ERR_TGT_REVOKED");

			case krb5_minor::KRB5KDC_ERR_CLIENT_NOTYET:
				return fmtns::format_to(ctx.out(), "KRB5KDC_ERR_CLIENT_NOTYET");

			case krb5_minor::KRB5KDC_ERR_SERVICE_NOTYET:
				return fmtns::format_to(ctx.out(), "KRB5KDC_ERR_SERVICE_NOTYET");

			case krb5_minor::KRB5KDC_ERR_KEY_EXP:
				return fmtns::format_to(ctx.out(), "KRB5KDC_ERR_KEY_EXP");

			case krb5_minor::KRB5KDC_ERR_PREAUTH_FAILED:
				return fmtns::format_to(ctx.out(), "KRB5KDC_ERR_PREAUTH_FAILED");

			case krb5_minor::KRB5KDC_ERR_PREAUTH_REQUIRED:
				return fmtns::format_to(ctx.out(), "KRB5KDC_ERR_PREAUTH_REQUIRED");

			case krb5_minor::KRB5KDC_ERR_SERVER_NOMATCH:
				return fmtns::format_to(ctx.out(), "KRB5KDC_ERR_SERVER_NOMATCH");

			case krb5_minor::KRB5KDC_ERR_MUST_USE_USER2USER:
				return fmtns::format_to(ctx.out(), "KRB5KDC_ERR_MUST_USE_USER2USER");

			case krb5_minor::KRB5KDC_ERR_PATH_NOT_ACCEPTED:
				return fmtns::format_to(ctx.out(), "KRB5KDC_ERR_PATH_NOT_ACCEPTED");

			case krb5_minor::KRB5KDC_ERR_SVC_UNAVAILABLE:
				return fmtns::format_to(ctx.out(), "KRB5KDC_ERR_SVC_UNAVAILABLE");

			case krb5_minor::KRB5PLACEHOLD_30:
				return fmtns::format_to(ctx.out(), "KRB5PLACEHOLD_30");

			case krb5_minor::KRB5KRB_AP_ERR_BAD_INTEGRITY:
				return fmtns::format_to(ctx.out(), "KRB5KRB_AP_ERR_BAD_INTEGRITY");

			case krb5_minor::KRB5KRB_AP_ERR_TKT_EXPIRED:
				return fmtns::format_to(ctx.out(), "KRB5KRB_AP_ERR_TKT_EXPIRED");

			case krb5_minor::KRB5KRB_AP_ERR_TKT_NYV:
				return fmtns::format_to(ctx.out(), "KRB5KRB_AP_ERR_TKT_NYV");

			case krb5_minor::KRB5KRB_AP_ERR_REPEAT:
				return fmtns::format_to(ctx.out(), "KRB5KRB_AP_ERR_REPEAT");

			case krb5_minor::KRB5KRB_AP_ERR_NOT_US:
				return fmtns::format_to(ctx.out(), "KRB5KRB_AP_ERR_NOT_US");

			case krb5_minor::KRB5KRB_AP_ERR_BADMATCH:
				return fmtns::format_to(ctx.out(), "KRB5KRB_AP_ERR_BADMATCH");

			case krb5_minor::KRB5KRB_AP_ERR_SKEW:
				return fmtns::format_to(ctx.out(), "KRB5KRB_AP_ERR_SKEW");

			case krb5_minor::KRB5KRB_AP_ERR_BADADDR:
				return fmtns::format_to(ctx.out(), "KRB5KRB_AP_ERR_BADADDR");

			case krb5_minor::KRB5KRB_AP_ERR_BADVERSION:
				return fmtns::format_to(ctx.out(), "KRB5KRB_AP_ERR_BADVERSION");

			case krb5_minor::KRB5KRB_AP_ERR_MSG_TYPE:
				return fmtns::format_to(ctx.out(), "KRB5KRB_AP_ERR_MSG_TYPE");

			case krb5_minor::KRB5KRB_AP_ERR_MODIFIED:
				return fmtns::format_to(ctx.out(), "KRB5KRB_AP_ERR_MODIFIED");

			case krb5_minor::KRB5KRB_AP_ERR_BADORDER:
				return fmtns::format_to(ctx.out(), "KRB5KRB_AP_ERR_BADORDER");

			case krb5_minor::KRB5KRB_AP_ERR_ILL_CR_TKT:
				return fmtns::format_to(ctx.out(), "KRB5KRB_AP_ERR_ILL_CR_TKT");

			case krb5_minor::KRB5KRB_AP_ERR_BADKEYVER:
				return fmtns::format_to(ctx.out(), "KRB5KRB_AP_ERR_BADKEYVER");

			case krb5_minor::KRB5KRB_AP_ERR_NOKEY:
				return fmtns::format_to(ctx.out(), "KRB5KRB_AP_ERR_NOKEY");

			case krb5_minor::KRB5KRB_AP_ERR_MUT_FAIL:
				return fmtns::format_to(ctx.out(), "KRB5KRB_AP_ERR_MUT_FAIL");

			case krb5_minor::KRB5KRB_AP_ERR_BADDIRECTION:
				return fmtns::format_to(ctx.out(), "KRB5KRB_AP_ERR_BADDIRECTION");

			case krb5_minor::KRB5KRB_AP_ERR_METHOD:
				return fmtns::format_to(ctx.out(), "KRB5KRB_AP_ERR_METHOD");

			case krb5_minor::KRB5KRB_AP_ERR_BADSEQ:
				return fmtns::format_to(ctx.out(), "KRB5KRB_AP_ERR_BADSEQ");

			case krb5_minor::KRB5KRB_AP_ERR_INAPP_CKSUM:
				return fmtns::format_to(ctx.out(), "KRB5KRB_AP_ERR_INAPP_CKSUM");

			case krb5_minor::KRB5KRB_AP_PATH_NOT_ACCEPTED:
				return fmtns::format_to(ctx.out(), "KRB5KRB_AP_PATH_NOT_ACCEPTED");

			case krb5_minor::KRB5KRB_ERR_RESPONSE_TOO_BIG:
				return fmtns::format_to(ctx.out(), "KRB5KRB_ERR_RESPONSE_TOO_BIG");

			case krb5_minor::KRB5PLACEHOLD_53:
				return fmtns::format_to(ctx.out(), "KRB5PLACEHOLD_53");

			case krb5_minor::KRB5PLACEHOLD_54:
				return fmtns::format_to(ctx.out(), "KRB5PLACEHOLD_54");

			case krb5_minor::KRB5PLACEHOLD_55:
				return fmtns::format_to(ctx.out(), "KRB5PLACEHOLD_55");

			case krb5_minor::KRB5PLACEHOLD_56:
				return fmtns::format_to(ctx.out(), "KRB5PLACEHOLD_56");

			case krb5_minor::KRB5PLACEHOLD_57:
				return fmtns::format_to(ctx.out(), "KRB5PLACEHOLD_57");

			case krb5_minor::KRB5PLACEHOLD_58:
				return fmtns::format_to(ctx.out(), "KRB5PLACEHOLD_58");

			case krb5_minor::KRB5PLACEHOLD_59:
				return fmtns::format_to(ctx.out(), "KRB5PLACEHOLD_59");

			case krb5_minor::KRB5KRB_ERR_GENERIC:
				return fmtns::format_to(ctx.out(), "KRB5KRB_ERR_GENERIC");

			case krb5_minor::KRB5KRB_ERR_FIELD_TOOLONG:
				return fmtns::format_to(ctx.out(), "KRB5KRB_ERR_FIELD_TOOLONG");

			case krb5_minor::KRB5KDC_ERR_CLIENT_NOT_TRUSTED:
				return fmtns::format_to(ctx.out(), "KRB5KDC_ERR_CLIENT_NOT_TRUSTED");

			case krb5_minor::KRB5KDC_ERR_KDC_NOT_TRUSTED:
				return fmtns::format_to(ctx.out(), "KRB5KDC_ERR_KDC_NOT_TRUSTED");

			case krb5_minor::KRB5KDC_ERR_INVALID_SIG:
				return fmtns::format_to(ctx.out(), "KRB5KDC_ERR_INVALID_SIG");

			case krb5_minor::KRB5KDC_ERR_DH_KEY_PARAMETERS_NOT_ACCEPTED:
				return fmtns::format_to(ctx.out(), "KRB5KDC_ERR_DH_KEY_PARAMETERS_NOT_ACCEPTED");

			case krb5_minor::KRB5KDC_ERR_CERTIFICATE_MISMATCH:
				return fmtns::format_to(ctx.out(), "KRB5KDC_ERR_CERTIFICATE_MISMATCH");

			case krb5_minor::KRB5KRB_AP_ERR_NO_TGT:
				return fmtns::format_to(ctx.out(), "KRB5KRB_AP_ERR_NO_TGT");

			case krb5_minor::KRB5KDC_ERR_WRONG_REALM:
				return fmtns::format_to(ctx.out(), "KRB5KDC_ERR_WRONG_REALM");

			case krb5_minor::KRB5KRB_AP_ERR_USER_TO_USER_REQUIRED:
				return fmtns::format_to(ctx.out(), "KRB5KRB_AP_ERR_USER_TO_USER_REQUIRED");

			case krb5_minor::KRB5KDC_ERR_CANT_VERIFY_CERTIFICATE:
				return fmtns::format_to(ctx.out(), "KRB5KDC_ERR_CANT_VERIFY_CERTIFICATE");

			case krb5_minor::KRB5KDC_ERR_INVALID_CERTIFICATE:
				return fmtns::format_to(ctx.out(), "KRB5KDC_ERR_INVALID_CERTIFICATE");

			case krb5_minor::KRB5KDC_ERR_REVOKED_CERTIFICATE:
				return fmtns::format_to(ctx.out(), "KRB5KDC_ERR_REVOKED_CERTIFICATE");

			case krb5_minor::KRB5KDC_ERR_REVOCATION_STATUS_UNKNOWN:
				return fmtns::format_to(ctx.out(), "KRB5KDC_ERR_REVOCATION_STATUS_UNKNOWN");

			case krb5_minor::KRB5KDC_ERR_REVOCATION_STATUS_UNAVAILABLE:
				return fmtns::format_to(ctx.out(), "KRB5KDC_ERR_REVOCATION_STATUS_UNAVAILABLE");

			case krb5_minor::KRB5KDC_ERR_CLIENT_NAME_MISMATCH:
				return fmtns::format_to(ctx.out(), "KRB5KDC_ERR_CLIENT_NAME_MISMATCH");

			case krb5_minor::KRB5KDC_ERR_KDC_NAME_MISMATCH:
				return fmtns::format_to(ctx.out(), "KRB5KDC_ERR_KDC_NAME_MISMATCH");

			case krb5_minor::KRB5KDC_ERR_INCONSISTENT_KEY_PURPOSE:
				return fmtns::format_to(ctx.out(), "KRB5KDC_ERR_INCONSISTENT_KEY_PURPOSE");

			case krb5_minor::KRB5KDC_ERR_DIGEST_IN_CERT_NOT_ACCEPTED:
				return fmtns::format_to(ctx.out(), "KRB5KDC_ERR_DIGEST_IN_CERT_NOT_ACCEPTED");

			case krb5_minor::KRB5KDC_ERR_PA_CHECKSUM_MUST_BE_INCLUDED:
				return fmtns::format_to(ctx.out(), "KRB5KDC_ERR_PA_CHECKSUM_MUST_BE_INCLUDED");

			case krb5_minor::KRB5KDC_ERR_DIGEST_IN_SIGNED_DATA_NOT_ACCEPTED:
				return fmtns::format_to(ctx.out(), "KRB5KDC_ERR_DIGEST_IN_SIGNED_DATA_NOT_ACCEPTED");

			case krb5_minor::KRB5KDC_ERR_PUBLIC_KEY_ENCRYPTION_NOT_SUPPORTED:
				return fmtns::format_to(ctx.out(), "KRB5KDC_ERR_PUBLIC_KEY_ENCRYPTION_NOT_SUPPORTED");

			case krb5_minor::KRB5PLACEHOLD_82:
				return fmtns::format_to(ctx.out(), "KRB5PLACEHOLD_82");

			case krb5_minor::KRB5PLACEHOLD_83:
				return fmtns::format_to(ctx.out(), "KRB5PLACEHOLD_83");

			case krb5_minor::KRB5PLACEHOLD_84:
				return fmtns::format_to(ctx.out(), "KRB5PLACEHOLD_84");

			case krb5_minor::KRB5KRB_AP_ERR_IAKERB_KDC_NOT_FOUND:
				return fmtns::format_to(ctx.out(), "KRB5KRB_AP_ERR_IAKERB_KDC_NOT_FOUND");

			case krb5_minor::KRB5KRB_AP_ERR_IAKERB_KDC_NO_RESPONSE:
				return fmtns::format_to(ctx.out(), "KRB5KRB_AP_ERR_IAKERB_KDC_NO_RESPONSE");

			case krb5_minor::KRB5PLACEHOLD_87:
				return fmtns::format_to(ctx.out(), "KRB5PLACEHOLD_87");

			case krb5_minor::KRB5PLACEHOLD_88:
				return fmtns::format_to(ctx.out(), "KRB5PLACEHOLD_88");

			case krb5_minor::KRB5PLACEHOLD_89:
				return fmtns::format_to(ctx.out(), "KRB5PLACEHOLD_89");

			case krb5_minor::KRB5KDC_ERR_PREAUTH_EXPIRED:
				return fmtns::format_to(ctx.out(), "KRB5KDC_ERR_PREAUTH_EXPIRED");

			case krb5_minor::KRB5KDC_ERR_MORE_PREAUTH_DATA_REQUIRED:
				return fmtns::format_to(ctx.out(), "KRB5KDC_ERR_MORE_PREAUTH_DATA_REQUIRED");

			case krb5_minor::KRB5PLACEHOLD_92:
				return fmtns::format_to(ctx.out(), "KRB5PLACEHOLD_92");

			case krb5_minor::KRB5KDC_ERR_UNKNOWN_CRITICAL_FAST_OPTION:
				return fmtns::format_to(ctx.out(), "KRB5KDC_ERR_UNKNOWN_CRITICAL_FAST_OPTION");

			case krb5_minor::KRB5PLACEHOLD_94:
				return fmtns::format_to(ctx.out(), "KRB5PLACEHOLD_94");

			case krb5_minor::KRB5PLACEHOLD_95:
				return fmtns::format_to(ctx.out(), "KRB5PLACEHOLD_95");

			case krb5_minor::KRB5PLACEHOLD_96:
				return fmtns::format_to(ctx.out(), "KRB5PLACEHOLD_96");

			case krb5_minor::KRB5PLACEHOLD_97:
				return fmtns::format_to(ctx.out(), "KRB5PLACEHOLD_97");

			case krb5_minor::KRB5PLACEHOLD_98:
				return fmtns::format_to(ctx.out(), "KRB5PLACEHOLD_98");

			case krb5_minor::KRB5PLACEHOLD_99:
				return fmtns::format_to(ctx.out(), "KRB5PLACEHOLD_99");

			case krb5_minor::KRB5KDC_ERR_NO_ACCEPTABLE_KDF:
				return fmtns::format_to(ctx.out(), "KRB5KDC_ERR_NO_ACCEPTABLE_KDF");

			case krb5_minor::KRB5PLACEHOLD_101:
				return fmtns::format_to(ctx.out(), "KRB5PLACEHOLD_101");

			case krb5_minor::KRB5PLACEHOLD_102:
				return fmtns::format_to(ctx.out(), "KRB5PLACEHOLD_102");

			case krb5_minor::KRB5PLACEHOLD_103:
				return fmtns::format_to(ctx.out(), "KRB5PLACEHOLD_103");

			case krb5_minor::KRB5PLACEHOLD_104:
				return fmtns::format_to(ctx.out(), "KRB5PLACEHOLD_104");

			case krb5_minor::KRB5PLACEHOLD_105:
				return fmtns::format_to(ctx.out(), "KRB5PLACEHOLD_105");

			case krb5_minor::KRB5PLACEHOLD_106:
				return fmtns::format_to(ctx.out(), "KRB5PLACEHOLD_106");

			case krb5_minor::KRB5PLACEHOLD_107:
				return fmtns::format_to(ctx.out(), "KRB5PLACEHOLD_107");

			case krb5_minor::KRB5PLACEHOLD_108:
				return fmtns::format_to(ctx.out(), "KRB5PLACEHOLD_108");

			case krb5_minor::KRB5PLACEHOLD_109:
				return fmtns::format_to(ctx.out(), "KRB5PLACEHOLD_109");

			case krb5_minor::KRB5PLACEHOLD_110:
				return fmtns::format_to(ctx.out(), "KRB5PLACEHOLD_110");

			case krb5_minor::KRB5PLACEHOLD_111:
				return fmtns::format_to(ctx.out(), "KRB5PLACEHOLD_111");

			case krb5_minor::KRB5PLACEHOLD_112:
				return fmtns::format_to(ctx.out(), "KRB5PLACEHOLD_112");

			case krb5_minor::KRB5PLACEHOLD_113:
				return fmtns::format_to(ctx.out(), "KRB5PLACEHOLD_113");

			case krb5_minor::KRB5PLACEHOLD_114:
				return fmtns::format_to(ctx.out(), "KRB5PLACEHOLD_114");

			case krb5_minor::KRB5PLACEHOLD_115:
				return fmtns::format_to(ctx.out(), "KRB5PLACEHOLD_115");

			case krb5_minor::KRB5PLACEHOLD_116:
				return fmtns::format_to(ctx.out(), "KRB5PLACEHOLD_116");

			case krb5_minor::KRB5PLACEHOLD_117:
				return fmtns::format_to(ctx.out(), "KRB5PLACEHOLD_117");

			case krb5_minor::KRB5PLACEHOLD_118:
				return fmtns::format_to(ctx.out(), "KRB5PLACEHOLD_118");

			case krb5_minor::KRB5PLACEHOLD_119:
				return fmtns::format_to(ctx.out(), "KRB5PLACEHOLD_119");

			case krb5_minor::KRB5PLACEHOLD_120:
				return fmtns::format_to(ctx.out(), "KRB5PLACEHOLD_120");

			case krb5_minor::KRB5PLACEHOLD_121:
				return fmtns::format_to(ctx.out(), "KRB5PLACEHOLD_121");

			case krb5_minor::KRB5PLACEHOLD_122:
				return fmtns::format_to(ctx.out(), "KRB5PLACEHOLD_122");

			case krb5_minor::KRB5PLACEHOLD_123:
				return fmtns::format_to(ctx.out(), "KRB5PLACEHOLD_123");

			case krb5_minor::KRB5PLACEHOLD_124:
				return fmtns::format_to(ctx.out(), "KRB5PLACEHOLD_124");

			case krb5_minor::KRB5PLACEHOLD_125:
				return fmtns::format_to(ctx.out(), "KRB5PLACEHOLD_125");

			case krb5_minor::KRB5PLACEHOLD_126:
				return fmtns::format_to(ctx.out(), "KRB5PLACEHOLD_126");

			case krb5_minor::KRB5PLACEHOLD_127:
				return fmtns::format_to(ctx.out(), "KRB5PLACEHOLD_127");

			case krb5_minor::KRB5_ERR_RCSID:
				return fmtns::format_to(ctx.out(), "KRB5_ERR_RCSID");

			case krb5_minor::KRB5_LIBOS_BADLOCKFLAG:
				return fmtns::format_to(ctx.out(), "KRB5_LIBOS_BADLOCKFLAG");

			case krb5_minor::KRB5_LIBOS_CANTREADPWD:
				return fmtns::format_to(ctx.out(), "KRB5_LIBOS_CANTREADPWD");

			case krb5_minor::KRB5_LIBOS_BADPWDMATCH:
				return fmtns::format_to(ctx.out(), "KRB5_LIBOS_BADPWDMATCH");

			case krb5_minor::KRB5_LIBOS_PWDINTR:
				return fmtns::format_to(ctx.out(), "KRB5_LIBOS_PWDINTR");

			case krb5_minor::KRB5_PARSE_ILLCHAR:
				return fmtns::format_to(ctx.out(), "KRB5_PARSE_ILLCHAR");

			case krb5_minor::KRB5_PARSE_MALFORMED:
				return fmtns::format_to(ctx.out(), "KRB5_PARSE_MALFORMED");

			case krb5_minor::KRB5_CONFIG_CANTOPEN:
				return fmtns::format_to(ctx.out(), "KRB5_CONFIG_CANTOPEN");

			case krb5_minor::KRB5_CONFIG_BADFORMAT:
				return fmtns::format_to(ctx.out(), "KRB5_CONFIG_BADFORMAT");

			case krb5_minor::KRB5_CONFIG_NOTENUFSPACE:
				return fmtns::format_to(ctx.out(), "KRB5_CONFIG_NOTENUFSPACE");

			case krb5_minor::KRB5_BADMSGTYPE:
				return fmtns::format_to(ctx.out(), "KRB5_BADMSGTYPE");

			case krb5_minor::KRB5_CC_BADNAME:
				return fmtns::format_to(ctx.out(), "KRB5_CC_BADNAME");

			case krb5_minor::KRB5_CC_UNKNOWN_TYPE:
				return fmtns::format_to(ctx.out(), "KRB5_CC_UNKNOWN_TYPE");

			case krb5_minor::KRB5_CC_NOTFOUND:
				return fmtns::format_to(ctx.out(), "KRB5_CC_NOTFOUND");

			case krb5_minor::KRB5_CC_END:
				return fmtns::format_to(ctx.out(), "KRB5_CC_END");

			case krb5_minor::KRB5_NO_TKT_SUPPLIED:
				return fmtns::format_to(ctx.out(), "KRB5_NO_TKT_SUPPLIED");

			case krb5_minor::KRB5KRB_AP_WRONG_PRINC:
				return fmtns::format_to(ctx.out(), "KRB5KRB_AP_WRONG_PRINC");

			case krb5_minor::KRB5KRB_AP_ERR_TKT_INVALID:
				return fmtns::format_to(ctx.out(), "KRB5KRB_AP_ERR_TKT_INVALID");

			case krb5_minor::KRB5_PRINC_NOMATCH:
				return fmtns::format_to(ctx.out(), "KRB5_PRINC_NOMATCH");

			case krb5_minor::KRB5_KDCREP_MODIFIED:
				return fmtns::format_to(ctx.out(), "KRB5_KDCREP_MODIFIED");

			case krb5_minor::KRB5_KDCREP_SKEW:
				return fmtns::format_to(ctx.out(), "KRB5_KDCREP_SKEW");

			case krb5_minor::KRB5_IN_TKT_REALM_MISMATCH:
				return fmtns::format_to(ctx.out(), "KRB5_IN_TKT_REALM_MISMATCH");

			case krb5_minor::KRB5_PROG_ETYPE_NOSUPP:
				return fmtns::format_to(ctx.out(), "KRB5_PROG_ETYPE_NOSUPP");

			case krb5_minor::KRB5_PROG_KEYTYPE_NOSUPP:
				return fmtns::format_to(ctx.out(), "KRB5_PROG_KEYTYPE_NOSUPP");

			case krb5_minor::KRB5_WRONG_ETYPE:
				return fmtns::format_to(ctx.out(), "KRB5_WRONG_ETYPE");

			case krb5_minor::KRB5_PROG_SUMTYPE_NOSUPP:
				return fmtns::format_to(ctx.out(), "KRB5_PROG_SUMTYPE_NOSUPP");

			case krb5_minor::KRB5_REALM_UNKNOWN:
				return fmtns::format_to(ctx.out(), "KRB5_REALM_UNKNOWN");

			case krb5_minor::KRB5_SERVICE_UNKNOWN:
				return fmtns::format_to(ctx.out(), "KRB5_SERVICE_UNKNOWN");

			case krb5_minor::KRB5_KDC_UNREACH:
				return fmtns::format_to(ctx.out(), "KRB5_KDC_UNREACH");

			case krb5_minor::KRB5_NO_LOCALNAME:
				return fmtns::format_to(ctx.out(), "KRB5_NO_LOCALNAME");

			case krb5_minor::KRB5_MUTUAL_FAILED:
				return fmtns::format_to(ctx.out(), "KRB5_MUTUAL_FAILED");

			case krb5_minor::KRB5_RC_TYPE_EXISTS:
				return fmtns::format_to(ctx.out(), "KRB5_RC_TYPE_EXISTS");

			case krb5_minor::KRB5_RC_MALLOC:
				return fmtns::format_to(ctx.out(), "KRB5_RC_MALLOC");

			case krb5_minor::KRB5_RC_TYPE_NOTFOUND:
				return fmtns::format_to(ctx.out(), "KRB5_RC_TYPE_NOTFOUND");

			case krb5_minor::KRB5_RC_UNKNOWN:
				return fmtns::format_to(ctx.out(), "KRB5_RC_UNKNOWN");

			case krb5_minor::KRB5_RC_REPLAY:
				return fmtns::format_to(ctx.out(), "KRB5_RC_REPLAY");

			case krb5_minor::KRB5_RC_IO:
				return fmtns::format_to(ctx.out(), "KRB5_RC_IO");

			case krb5_minor::KRB5_RC_NOIO:
				return fmtns::format_to(ctx.out(), "KRB5_RC_NOIO");

			case krb5_minor::KRB5_RC_PARSE:
				return fmtns::format_to(ctx.out(), "KRB5_RC_PARSE");

			case krb5_minor::KRB5_RC_IO_EOF:
				return fmtns::format_to(ctx.out(), "KRB5_RC_IO_EOF");

			case krb5_minor::KRB5_RC_IO_MALLOC:
				return fmtns::format_to(ctx.out(), "KRB5_RC_IO_MALLOC");

			case krb5_minor::KRB5_RC_IO_PERM:
				return fmtns::format_to(ctx.out(), "KRB5_RC_IO_PERM");

			case krb5_minor::KRB5_RC_IO_IO:
				return fmtns::format_to(ctx.out(), "KRB5_RC_IO_IO");

			case krb5_minor::KRB5_RC_IO_UNKNOWN:
				return fmtns::format_to(ctx.out(), "KRB5_RC_IO_UNKNOWN");

			case krb5_minor::KRB5_RC_IO_SPACE:
				return fmtns::format_to(ctx.out(), "KRB5_RC_IO_SPACE");

			case krb5_minor::KRB5_TRANS_CANTOPEN:
				return fmtns::format_to(ctx.out(), "KRB5_TRANS_CANTOPEN");

			case krb5_minor::KRB5_TRANS_BADFORMAT:
				return fmtns::format_to(ctx.out(), "KRB5_TRANS_BADFORMAT");

			case krb5_minor::KRB5_LNAME_CANTOPEN:
				return fmtns::format_to(ctx.out(), "KRB5_LNAME_CANTOPEN");

			case krb5_minor::KRB5_LNAME_NOTRANS:
				return fmtns::format_to(ctx.out(), "KRB5_LNAME_NOTRANS");

			case krb5_minor::KRB5_LNAME_BADFORMAT:
				return fmtns::format_to(ctx.out(), "KRB5_LNAME_BADFORMAT");

			case krb5_minor::KRB5_CRYPTO_INTERNAL:
				return fmtns::format_to(ctx.out(), "KRB5_CRYPTO_INTERNAL");

			case krb5_minor::KRB5_KT_BADNAME:
				return fmtns::format_to(ctx.out(), "KRB5_KT_BADNAME");

			case krb5_minor::KRB5_KT_UNKNOWN_TYPE:
				return fmtns::format_to(ctx.out(), "KRB5_KT_UNKNOWN_TYPE");

			case krb5_minor::KRB5_KT_NOTFOUND:
				return fmtns::format_to(ctx.out(), "KRB5_KT_NOTFOUND");

			case krb5_minor::KRB5_KT_END:
				return fmtns::format_to(ctx.out(), "KRB5_KT_END");

			case krb5_minor::KRB5_KT_NOWRITE:
				return fmtns::format_to(ctx.out(), "KRB5_KT_NOWRITE");

			case krb5_minor::KRB5_KT_IOERR:
				return fmtns::format_to(ctx.out(), "KRB5_KT_IOERR");

			case krb5_minor::KRB5_NO_TKT_IN_RLM:
				return fmtns::format_to(ctx.out(), "KRB5_NO_TKT_IN_RLM");

			case krb5_minor::KRB5DES_BAD_KEYPAR:
				return fmtns::format_to(ctx.out(), "KRB5DES_BAD_KEYPAR");

			case krb5_minor::KRB5DES_WEAK_KEY:
				return fmtns::format_to(ctx.out(), "KRB5DES_WEAK_KEY");

			case krb5_minor::KRB5_BAD_ENCTYPE:
				return fmtns::format_to(ctx.out(), "KRB5_BAD_ENCTYPE");

			case krb5_minor::KRB5_BAD_KEYSIZE:
				return fmtns::format_to(ctx.out(), "KRB5_BAD_KEYSIZE");

			case krb5_minor::KRB5_BAD_MSIZE:
				return fmtns::format_to(ctx.out(), "KRB5_BAD_MSIZE");

			case krb5_minor::KRB5_CC_TYPE_EXISTS:
				return fmtns::format_to(ctx.out(), "KRB5_CC_TYPE_EXISTS");

			case krb5_minor::KRB5_KT_TYPE_EXISTS:
				return fmtns::format_to(ctx.out(), "KRB5_KT_TYPE_EXISTS");

			case krb5_minor::KRB5_CC_IO:
				return fmtns::format_to(ctx.out(), "KRB5_CC_IO");

			case krb5_minor::KRB5_FCC_PERM:
				return fmtns::format_to(ctx.out(), "KRB5_FCC_PERM");

			case krb5_minor::KRB5_FCC_NOFILE:
				return fmtns::format_to(ctx.out(), "KRB5_FCC_NOFILE");

			case krb5_minor::KRB5_FCC_INTERNAL:
				return fmtns::format_to(ctx.out(), "KRB5_FCC_INTERNAL");

			case krb5_minor::KRB5_CC_WRITE:
				return fmtns::format_to(ctx.out(), "KRB5_CC_WRITE");

			case krb5_minor::KRB5_CC_NOMEM:
				return fmtns::format_to(ctx.out(), "KRB5_CC_NOMEM");

			case krb5_minor::KRB5_CC_FORMAT:
				return fmtns::format_to(ctx.out(), "KRB5_CC_FORMAT");

			case krb5_minor::KRB5_CC_NOT_KTYPE:
				return fmtns::format_to(ctx.out(), "KRB5_CC_NOT_KTYPE");

			case krb5_minor::KRB5_INVALID_FLAGS:
				return fmtns::format_to(ctx.out(), "KRB5_INVALID_FLAGS");

			case krb5_minor::KRB5_NO_2ND_TKT:
				return fmtns::format_to(ctx.out(), "KRB5_NO_2ND_TKT");

			case krb5_minor::KRB5_NOCREDS_SUPPLIED:
				return fmtns::format_to(ctx.out(), "KRB5_NOCREDS_SUPPLIED");

			case krb5_minor::KRB5_SENDAUTH_BADAUTHVERS:
				return fmtns::format_to(ctx.out(), "KRB5_SENDAUTH_BADAUTHVERS");

			case krb5_minor::KRB5_SENDAUTH_BADAPPLVERS:
				return fmtns::format_to(ctx.out(), "KRB5_SENDAUTH_BADAPPLVERS");

			case krb5_minor::KRB5_SENDAUTH_BADRESPONSE:
				return fmtns::format_to(ctx.out(), "KRB5_SENDAUTH_BADRESPONSE");

			case krb5_minor::KRB5_SENDAUTH_REJECTED:
				return fmtns::format_to(ctx.out(), "KRB5_SENDAUTH_REJECTED");

			case krb5_minor::KRB5_PREAUTH_BAD_TYPE:
				return fmtns::format_to(ctx.out(), "KRB5_PREAUTH_BAD_TYPE");

			case krb5_minor::KRB5_PREAUTH_NO_KEY:
				return fmtns::format_to(ctx.out(), "KRB5_PREAUTH_NO_KEY");

			case krb5_minor::KRB5_PREAUTH_FAILED:
				return fmtns::format_to(ctx.out(), "KRB5_PREAUTH_FAILED");

			case krb5_minor::KRB5_RCACHE_BADVNO:
				return fmtns::format_to(ctx.out(), "KRB5_RCACHE_BADVNO");

			case krb5_minor::KRB5_CCACHE_BADVNO:
				return fmtns::format_to(ctx.out(), "KRB5_CCACHE_BADVNO");

			case krb5_minor::KRB5_KEYTAB_BADVNO:
				return fmtns::format_to(ctx.out(), "KRB5_KEYTAB_BADVNO");

			case krb5_minor::KRB5_PROG_ATYPE_NOSUPP:
				return fmtns::format_to(ctx.out(), "KRB5_PROG_ATYPE_NOSUPP");

			case krb5_minor::KRB5_RC_REQUIRED:
				return fmtns::format_to(ctx.out(), "KRB5_RC_REQUIRED");

			case krb5_minor::KRB5_ERR_BAD_HOSTNAME:
				return fmtns::format_to(ctx.out(), "KRB5_ERR_BAD_HOSTNAME");

			case krb5_minor::KRB5_ERR_HOST_REALM_UNKNOWN:
				return fmtns::format_to(ctx.out(), "KRB5_ERR_HOST_REALM_UNKNOWN");

			case krb5_minor::KRB5_SNAME_UNSUPP_NAMETYPE:
				return fmtns::format_to(ctx.out(), "KRB5_SNAME_UNSUPP_NAMETYPE");

			case krb5_minor::KRB5KRB_AP_ERR_V4_REPLY:
				return fmtns::format_to(ctx.out(), "KRB5KRB_AP_ERR_V4_REPLY");

			case krb5_minor::KRB5_REALM_CANT_RESOLVE:
				return fmtns::format_to(ctx.out(), "KRB5_REALM_CANT_RESOLVE");

			case krb5_minor::KRB5_TKT_NOT_FORWARDABLE:
				return fmtns::format_to(ctx.out(), "KRB5_TKT_NOT_FORWARDABLE");

			case krb5_minor::KRB5_FWD_BAD_PRINCIPAL:
				return fmtns::format_to(ctx.out(), "KRB5_FWD_BAD_PRINCIPAL");

			case krb5_minor::KRB5_GET_IN_TKT_LOOP:
				return fmtns::format_to(ctx.out(), "KRB5_GET_IN_TKT_LOOP");

			case krb5_minor::KRB5_CONFIG_NODEFREALM:
				return fmtns::format_to(ctx.out(), "KRB5_CONFIG_NODEFREALM");

			case krb5_minor::KRB5_SAM_UNSUPPORTED:
				return fmtns::format_to(ctx.out(), "KRB5_SAM_UNSUPPORTED");

			case krb5_minor::KRB5_SAM_INVALID_ETYPE:
				return fmtns::format_to(ctx.out(), "KRB5_SAM_INVALID_ETYPE");

			case krb5_minor::KRB5_SAM_NO_CHECKSUM:
				return fmtns::format_to(ctx.out(), "KRB5_SAM_NO_CHECKSUM");

			case krb5_minor::KRB5_SAM_BAD_CHECKSUM:
				return fmtns::format_to(ctx.out(), "KRB5_SAM_BAD_CHECKSUM");

			case krb5_minor::KRB5_KT_NAME_TOOLONG:
				return fmtns::format_to(ctx.out(), "KRB5_KT_NAME_TOOLONG");

			case krb5_minor::KRB5_KT_KVNONOTFOUND:
				return fmtns::format_to(ctx.out(), "KRB5_KT_KVNONOTFOUND");

			case krb5_minor::KRB5_APPL_EXPIRED:
				return fmtns::format_to(ctx.out(), "KRB5_APPL_EXPIRED");

			case krb5_minor::KRB5_LIB_EXPIRED:
				return fmtns::format_to(ctx.out(), "KRB5_LIB_EXPIRED");

			case krb5_minor::KRB5_CHPW_PWDNULL:
				return fmtns::format_to(ctx.out(), "KRB5_CHPW_PWDNULL");

			case krb5_minor::KRB5_CHPW_FAIL:
				return fmtns::format_to(ctx.out(), "KRB5_CHPW_FAIL");

			case krb5_minor::KRB5_KT_FORMAT:
				return fmtns::format_to(ctx.out(), "KRB5_KT_FORMAT");

			case krb5_minor::KRB5_NOPERM_ETYPE:
				return fmtns::format_to(ctx.out(), "KRB5_NOPERM_ETYPE");

			case krb5_minor::KRB5_CONFIG_ETYPE_NOSUPP:
				return fmtns::format_to(ctx.out(), "KRB5_CONFIG_ETYPE_NOSUPP");

			case krb5_minor::KRB5_OBSOLETE_FN:
				return fmtns::format_to(ctx.out(), "KRB5_OBSOLETE_FN");

			case krb5_minor::KRB5_EAI_FAIL:
				return fmtns::format_to(ctx.out(), "KRB5_EAI_FAIL");

			case krb5_minor::KRB5_EAI_NODATA:
				return fmtns::format_to(ctx.out(), "KRB5_EAI_NODATA");

			case krb5_minor::KRB5_EAI_NONAME:
				return fmtns::format_to(ctx.out(), "KRB5_EAI_NONAME");

			case krb5_minor::KRB5_EAI_SERVICE:
				return fmtns::format_to(ctx.out(), "KRB5_EAI_SERVICE");

			case krb5_minor::KRB5_ERR_NUMERIC_REALM:
				return fmtns::format_to(ctx.out(), "KRB5_ERR_NUMERIC_REALM");

			case krb5_minor::KRB5_ERR_BAD_S2K_PARAMS:
				return fmtns::format_to(ctx.out(), "KRB5_ERR_BAD_S2K_PARAMS");

			case krb5_minor::KRB5_ERR_NO_SERVICE:
				return fmtns::format_to(ctx.out(), "KRB5_ERR_NO_SERVICE");

			case krb5_minor::KRB5_CC_READONLY:
				return fmtns::format_to(ctx.out(), "KRB5_CC_READONLY");

			case krb5_minor::KRB5_CC_NOSUPP:
				return fmtns::format_to(ctx.out(), "KRB5_CC_NOSUPP");

			case krb5_minor::KRB5_DELTAT_BADFORMAT:
				return fmtns::format_to(ctx.out(), "KRB5_DELTAT_BADFORMAT");

			case krb5_minor::KRB5_PLUGIN_NO_HANDLE:
				return fmtns::format_to(ctx.out(), "KRB5_PLUGIN_NO_HANDLE");

			case krb5_minor::KRB5_PLUGIN_OP_NOTSUPP:
				return fmtns::format_to(ctx.out(), "KRB5_PLUGIN_OP_NOTSUPP");

			case krb5_minor::KRB5_ERR_INVALID_UTF8:
				return fmtns::format_to(ctx.out(), "KRB5_ERR_INVALID_UTF8");

			case krb5_minor::KRB5_ERR_FAST_REQUIRED:
				return fmtns::format_to(ctx.out(), "KRB5_ERR_FAST_REQUIRED");

			case krb5_minor::KRB5_LOCAL_ADDR_REQUIRED:
				return fmtns::format_to(ctx.out(), "KRB5_LOCAL_ADDR_REQUIRED");

			case krb5_minor::KRB5_REMOTE_ADDR_REQUIRED:
				return fmtns::format_to(ctx.out(), "KRB5_REMOTE_ADDR_REQUIRED");

			case krb5_minor::KRB5_TRACE_NOSUPP:
				return fmtns::format_to(ctx.out(), "KRB5_TRACE_NOSUPP");

			default:
				return fmtns::format_to(ctx.out(), "{}", (int32_t)t);
		}
	}
};

class gss_error : public std::exception {
public:
	gss_error(std::string_view func, OM_uint32 major, OM_uint32 minor) {
		OM_uint32 message_context = 0;
		OM_uint32 min_status;
		gss_buffer_desc status_string;
		bool first = true;

		msg = fmtns::format("{} failed (minor {}): ", func, (enum krb5_minor)minor);

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
#else
enum class sec_error : uint32_t {
	_SEC_E_OK = 0,
	_SEC_E_INSUFFICIENT_MEMORY = 0x80090300,
	_SEC_E_INVALID_HANDLE = 0x80090301,
	_SEC_E_UNSUPPORTED_FUNCTION = 0x80090302,
	_SEC_E_TARGET_UNKNOWN = 0x80090303,
	_SEC_E_INTERNAL_ERROR = 0x80090304,
	_SEC_E_SECPKG_NOT_FOUND = 0x80090305,
	_SEC_E_NOT_OWNER = 0x80090306,
	_SEC_E_CANNOT_INSTALL = 0x80090307,
	_SEC_E_INVALID_TOKEN = 0x80090308,
	_SEC_E_CANNOT_PACK = 0x80090309,
	_SEC_E_QOP_NOT_SUPPORTED = 0x8009030A,
	_SEC_E_NO_IMPERSONATION = 0x8009030B,
	_SEC_E_LOGON_DENIED = 0x8009030C,
	_SEC_E_UNKNOWN_CREDENTIALS = 0x8009030D,
	_SEC_E_NO_CREDENTIALS = 0x8009030E,
	_SEC_E_MESSAGE_ALTERED = 0x8009030F,
	_SEC_E_OUT_OF_SEQUENCE = 0x80090310,
	_SEC_E_NO_AUTHENTICATING_AUTHORITY = 0x80090311,
	_SEC_I_CONTINUE_NEEDED = 0x00090312,
	_SEC_I_COMPLETE_NEEDED = 0x00090313,
	_SEC_I_COMPLETE_AND_CONTINUE = 0x00090314,
	_SEC_I_LOCAL_LOGON = 0x00090315,
	_SEC_I_GENERIC_EXTENSION_RECEIVED = 0x00090316,
	_SEC_E_BAD_PKGID = 0x80090316,
	_SEC_E_CONTEXT_EXPIRED = 0x80090317,
	_SEC_I_CONTEXT_EXPIRED = 0x00090317,
	_SEC_E_INCOMPLETE_MESSAGE = 0x80090318,
	_SEC_E_INCOMPLETE_CREDENTIALS = 0x80090320,
	_SEC_E_BUFFER_TOO_SMALL = 0x80090321,
	_SEC_I_INCOMPLETE_CREDENTIALS = 0x00090320,
	_SEC_I_RENEGOTIATE = 0x00090321,
	_SEC_E_WRONG_PRINCIPAL = 0x80090322,
	_SEC_I_NO_LSA_CONTEXT = 0x00090323,
	_SEC_E_TIME_SKEW = 0x80090324,
	_SEC_E_UNTRUSTED_ROOT = 0x80090325,
	_SEC_E_ILLEGAL_MESSAGE = 0x80090326,
	_SEC_E_CERT_UNKNOWN = 0x80090327,
	_SEC_E_CERT_EXPIRED = 0x80090328,
	_SEC_E_ENCRYPT_FAILURE = 0x80090329,
	_SEC_E_DECRYPT_FAILURE = 0x80090330,
	_SEC_E_ALGORITHM_MISMATCH = 0x80090331,
	_SEC_E_SECURITY_QOS_FAILED = 0x80090332,
	_SEC_E_UNFINISHED_CONTEXT_DELETED = 0x80090333,
	_SEC_E_NO_TGT_REPLY = 0x80090334,
	_SEC_E_NO_IP_ADDRESSES = 0x80090335,
	_SEC_E_WRONG_CREDENTIAL_HANDLE = 0x80090336,
	_SEC_E_CRYPTO_SYSTEM_INVALID = 0x80090337,
	_SEC_E_MAX_REFERRALS_EXCEEDED = 0x80090338,
	_SEC_E_MUST_BE_KDC = 0x80090339,
	_SEC_E_STRONG_CRYPTO_NOT_SUPPORTED = 0x8009033A,
	_SEC_E_TOO_MANY_PRINCIPALS = 0x8009033B,
	_SEC_E_NO_PA_DATA = 0x8009033C,
	_SEC_E_PKINIT_NAME_MISMATCH = 0x8009033D,
	_SEC_E_SMARTCARD_LOGON_REQUIRED = 0x8009033E,
	_SEC_E_SHUTDOWN_IN_PROGRESS = 0x8009033F,
	_SEC_E_KDC_INVALID_REQUEST = 0x80090340,
	_SEC_E_KDC_UNABLE_TO_REFER = 0x80090341,
	_SEC_E_KDC_UNKNOWN_ETYPE = 0x80090342,
	_SEC_E_UNSUPPORTED_PREAUTH = 0x80090343,
	_SEC_E_DELEGATION_REQUIRED = 0x80090345,
	_SEC_E_BAD_BINDINGS = 0x80090346,
	_SEC_E_MULTIPLE_ACCOUNTS = 0x80090347,
	_SEC_E_NO_KERB_KEY = 0x80090348,
	_SEC_E_CERT_WRONG_USAGE = 0x80090349,
	_SEC_E_DOWNGRADE_DETECTED = 0x80090350,
	_SEC_E_SMARTCARD_CERT_REVOKED = 0x80090351,
	_SEC_E_ISSUING_CA_UNTRUSTED = 0x80090352,
	_SEC_E_REVOCATION_OFFLINE_C = 0x80090353,
	_SEC_E_PKINIT_CLIENT_FAILURE = 0x80090354,
	_SEC_E_SMARTCARD_CERT_EXPIRED = 0x80090355,
	_SEC_E_NO_S4U_PROT_SUPPORT = 0x80090356,
	_SEC_E_CROSSREALM_DELEGATION_FAILURE = 0x80090357,
	_SEC_E_REVOCATION_OFFLINE_KDC = 0x80090358,
	_SEC_E_ISSUING_CA_UNTRUSTED_KDC = 0x80090359,
	_SEC_E_KDC_CERT_EXPIRED = 0x8009035A,
	_SEC_E_KDC_CERT_REVOKED = 0x8009035B,
	_SEC_I_SIGNATURE_NEEDED = 0x0009035C,
	_SEC_E_INVALID_PARAMETER = 0x8009035D,
	_SEC_E_DELEGATION_POLICY = 0x8009035E,
	_SEC_E_POLICY_NLTM_ONLY = 0x8009035F,
	_SEC_I_NO_RENEGOTIATION = 0x00090360,
	_SEC_E_NO_CONTEXT = 0x80090361,
	_SEC_E_PKU2U_CERT_FAILURE = 0x80090362,
	_SEC_E_MUTUAL_AUTH_FAILED = 0x80090363,
	_SEC_I_MESSAGE_FRAGMENT = 0x00090364,
	_SEC_E_ONLY_HTTPS_ALLOWED = 0x80090365,
	_SEC_I_CONTINUE_NEEDED_MESSAGE_OK = 0x00090366,
	_SEC_E_APPLICATION_PROTOCOL_MISMATCH = 0x80090367,
	_SEC_I_ASYNC_CALL_PENDING = 0x00090368,
	_SEC_E_INVALID_UPN_NAME = 0x80090369,
	_SEC_E_EXT_BUFFER_TOO_SMALL = 0x8009036A,
	_SEC_E_INSUFFICIENT_BUFFERS = 0x8009036B
};

template<>
struct fmtns::formatter<enum sec_error> {
	constexpr auto parse(format_parse_context& ctx) {
		auto it = ctx.begin();

		if (it != ctx.end() && *it != '}')
			throw format_error("invalid format");

		return it;
	}

	template<typename format_context>
	auto format(enum sec_error t, format_context& ctx) const {
		switch (t) {
			case sec_error::_SEC_E_OK:
				return fmtns::format_to(ctx.out(), "SEC_E_OK");

			case sec_error::_SEC_E_INSUFFICIENT_MEMORY:
				return fmtns::format_to(ctx.out(), "SEC_E_INSUFFICIENT_MEMORY");

			case sec_error::_SEC_E_INVALID_HANDLE:
				return fmtns::format_to(ctx.out(), "SEC_E_INVALID_HANDLE");

			case sec_error::_SEC_E_UNSUPPORTED_FUNCTION:
				return fmtns::format_to(ctx.out(), "SEC_E_UNSUPPORTED_FUNCTION");

			case sec_error::_SEC_E_TARGET_UNKNOWN:
				return fmtns::format_to(ctx.out(), "SEC_E_TARGET_UNKNOWN");

			case sec_error::_SEC_E_INTERNAL_ERROR:
				return fmtns::format_to(ctx.out(), "SEC_E_INTERNAL_ERROR");

			case sec_error::_SEC_E_SECPKG_NOT_FOUND:
				return fmtns::format_to(ctx.out(), "SEC_E_SECPKG_NOT_FOUND");

			case sec_error::_SEC_E_NOT_OWNER:
				return fmtns::format_to(ctx.out(), "SEC_E_NOT_OWNER");

			case sec_error::_SEC_E_CANNOT_INSTALL:
				return fmtns::format_to(ctx.out(), "SEC_E_CANNOT_INSTALL");

			case sec_error::_SEC_E_INVALID_TOKEN:
				return fmtns::format_to(ctx.out(), "SEC_E_INVALID_TOKEN");

			case sec_error::_SEC_E_CANNOT_PACK:
				return fmtns::format_to(ctx.out(), "SEC_E_CANNOT_PACK");

			case sec_error::_SEC_E_QOP_NOT_SUPPORTED:
				return fmtns::format_to(ctx.out(), "SEC_E_QOP_NOT_SUPPORTED");

			case sec_error::_SEC_E_NO_IMPERSONATION:
				return fmtns::format_to(ctx.out(), "SEC_E_NO_IMPERSONATION");

			case sec_error::_SEC_E_LOGON_DENIED:
				return fmtns::format_to(ctx.out(), "SEC_E_LOGON_DENIED");

			case sec_error::_SEC_E_UNKNOWN_CREDENTIALS:
				return fmtns::format_to(ctx.out(), "SEC_E_UNKNOWN_CREDENTIALS");

			case sec_error::_SEC_E_NO_CREDENTIALS:
				return fmtns::format_to(ctx.out(), "SEC_E_NO_CREDENTIALS");

			case sec_error::_SEC_E_MESSAGE_ALTERED:
				return fmtns::format_to(ctx.out(), "SEC_E_MESSAGE_ALTERED");

			case sec_error::_SEC_E_OUT_OF_SEQUENCE:
				return fmtns::format_to(ctx.out(), "SEC_E_OUT_OF_SEQUENCE");

			case sec_error::_SEC_E_NO_AUTHENTICATING_AUTHORITY:
				return fmtns::format_to(ctx.out(), "SEC_E_NO_AUTHENTICATING_AUTHORITY");

			case sec_error::_SEC_I_CONTINUE_NEEDED:
				return fmtns::format_to(ctx.out(), "SEC_I_CONTINUE_NEEDED");

			case sec_error::_SEC_I_COMPLETE_NEEDED:
				return fmtns::format_to(ctx.out(), "SEC_I_COMPLETE_NEEDED");

			case sec_error::_SEC_I_COMPLETE_AND_CONTINUE:
				return fmtns::format_to(ctx.out(), "SEC_I_COMPLETE_AND_CONTINUE");

			case sec_error::_SEC_I_LOCAL_LOGON:
				return fmtns::format_to(ctx.out(), "SEC_I_LOCAL_LOGON");

			case sec_error::_SEC_I_GENERIC_EXTENSION_RECEIVED:
				return fmtns::format_to(ctx.out(), "SEC_I_GENERIC_EXTENSION_RECEIVED");

			case sec_error::_SEC_E_BAD_PKGID:
				return fmtns::format_to(ctx.out(), "SEC_E_BAD_PKGID");

			case sec_error::_SEC_E_CONTEXT_EXPIRED:
				return fmtns::format_to(ctx.out(), "SEC_E_CONTEXT_EXPIRED");

			case sec_error::_SEC_I_CONTEXT_EXPIRED:
				return fmtns::format_to(ctx.out(), "SEC_I_CONTEXT_EXPIRED");

			case sec_error::_SEC_E_INCOMPLETE_MESSAGE:
				return fmtns::format_to(ctx.out(), "SEC_E_INCOMPLETE_MESSAGE");

			case sec_error::_SEC_E_INCOMPLETE_CREDENTIALS:
				return fmtns::format_to(ctx.out(), "SEC_E_INCOMPLETE_CREDENTIALS");

			case sec_error::_SEC_E_BUFFER_TOO_SMALL:
				return fmtns::format_to(ctx.out(), "SEC_E_BUFFER_TOO_SMALL");

			case sec_error::_SEC_I_INCOMPLETE_CREDENTIALS:
				return fmtns::format_to(ctx.out(), "SEC_I_INCOMPLETE_CREDENTIALS");

			case sec_error::_SEC_I_RENEGOTIATE:
				return fmtns::format_to(ctx.out(), "SEC_I_RENEGOTIATE");

			case sec_error::_SEC_E_WRONG_PRINCIPAL:
				return fmtns::format_to(ctx.out(), "SEC_E_WRONG_PRINCIPAL");

			case sec_error::_SEC_I_NO_LSA_CONTEXT:
				return fmtns::format_to(ctx.out(), "SEC_I_NO_LSA_CONTEXT");

			case sec_error::_SEC_E_TIME_SKEW:
				return fmtns::format_to(ctx.out(), "SEC_E_TIME_SKEW");

			case sec_error::_SEC_E_UNTRUSTED_ROOT:
				return fmtns::format_to(ctx.out(), "SEC_E_UNTRUSTED_ROOT");

			case sec_error::_SEC_E_ILLEGAL_MESSAGE:
				return fmtns::format_to(ctx.out(), "SEC_E_ILLEGAL_MESSAGE");

			case sec_error::_SEC_E_CERT_UNKNOWN:
				return fmtns::format_to(ctx.out(), "SEC_E_CERT_UNKNOWN");

			case sec_error::_SEC_E_CERT_EXPIRED:
				return fmtns::format_to(ctx.out(), "SEC_E_CERT_EXPIRED");

			case sec_error::_SEC_E_ENCRYPT_FAILURE:
				return fmtns::format_to(ctx.out(), "SEC_E_ENCRYPT_FAILURE");

			case sec_error::_SEC_E_DECRYPT_FAILURE:
				return fmtns::format_to(ctx.out(), "SEC_E_DECRYPT_FAILURE");

			case sec_error::_SEC_E_ALGORITHM_MISMATCH:
				return fmtns::format_to(ctx.out(), "SEC_E_ALGORITHM_MISMATCH");

			case sec_error::_SEC_E_SECURITY_QOS_FAILED:
				return fmtns::format_to(ctx.out(), "SEC_E_SECURITY_QOS_FAILED");

			case sec_error::_SEC_E_UNFINISHED_CONTEXT_DELETED:
				return fmtns::format_to(ctx.out(), "SEC_E_UNFINISHED_CONTEXT_DELETED");

			case sec_error::_SEC_E_NO_TGT_REPLY:
				return fmtns::format_to(ctx.out(), "SEC_E_NO_TGT_REPLY");

			case sec_error::_SEC_E_NO_IP_ADDRESSES:
				return fmtns::format_to(ctx.out(), "SEC_E_NO_IP_ADDRESSES");

			case sec_error::_SEC_E_WRONG_CREDENTIAL_HANDLE:
				return fmtns::format_to(ctx.out(), "SEC_E_WRONG_CREDENTIAL_HANDLE");

			case sec_error::_SEC_E_CRYPTO_SYSTEM_INVALID:
				return fmtns::format_to(ctx.out(), "SEC_E_CRYPTO_SYSTEM_INVALID");

			case sec_error::_SEC_E_MAX_REFERRALS_EXCEEDED:
				return fmtns::format_to(ctx.out(), "SEC_E_MAX_REFERRALS_EXCEEDED");

			case sec_error::_SEC_E_MUST_BE_KDC:
				return fmtns::format_to(ctx.out(), "SEC_E_MUST_BE_KDC");

			case sec_error::_SEC_E_STRONG_CRYPTO_NOT_SUPPORTED:
				return fmtns::format_to(ctx.out(), "SEC_E_STRONG_CRYPTO_NOT_SUPPORTED");

			case sec_error::_SEC_E_TOO_MANY_PRINCIPALS:
				return fmtns::format_to(ctx.out(), "SEC_E_TOO_MANY_PRINCIPALS");

			case sec_error::_SEC_E_NO_PA_DATA:
				return fmtns::format_to(ctx.out(), "SEC_E_NO_PA_DATA");

			case sec_error::_SEC_E_PKINIT_NAME_MISMATCH:
				return fmtns::format_to(ctx.out(), "SEC_E_PKINIT_NAME_MISMATCH");

			case sec_error::_SEC_E_SMARTCARD_LOGON_REQUIRED:
				return fmtns::format_to(ctx.out(), "SEC_E_SMARTCARD_LOGON_REQUIRED");

			case sec_error::_SEC_E_SHUTDOWN_IN_PROGRESS:
				return fmtns::format_to(ctx.out(), "SEC_E_SHUTDOWN_IN_PROGRESS");

			case sec_error::_SEC_E_KDC_INVALID_REQUEST:
				return fmtns::format_to(ctx.out(), "SEC_E_KDC_INVALID_REQUEST");

			case sec_error::_SEC_E_KDC_UNABLE_TO_REFER:
				return fmtns::format_to(ctx.out(), "SEC_E_KDC_UNABLE_TO_REFER");

			case sec_error::_SEC_E_KDC_UNKNOWN_ETYPE:
				return fmtns::format_to(ctx.out(), "SEC_E_KDC_UNKNOWN_ETYPE");

			case sec_error::_SEC_E_UNSUPPORTED_PREAUTH:
				return fmtns::format_to(ctx.out(), "SEC_E_UNSUPPORTED_PREAUTH");

			case sec_error::_SEC_E_DELEGATION_REQUIRED:
				return fmtns::format_to(ctx.out(), "SEC_E_DELEGATION_REQUIRED");

			case sec_error::_SEC_E_BAD_BINDINGS:
				return fmtns::format_to(ctx.out(), "SEC_E_BAD_BINDINGS");

			case sec_error::_SEC_E_MULTIPLE_ACCOUNTS:
				return fmtns::format_to(ctx.out(), "SEC_E_MULTIPLE_ACCOUNTS");

			case sec_error::_SEC_E_NO_KERB_KEY:
				return fmtns::format_to(ctx.out(), "SEC_E_NO_KERB_KEY");

			case sec_error::_SEC_E_CERT_WRONG_USAGE:
				return fmtns::format_to(ctx.out(), "SEC_E_CERT_WRONG_USAGE");

			case sec_error::_SEC_E_DOWNGRADE_DETECTED:
				return fmtns::format_to(ctx.out(), "SEC_E_DOWNGRADE_DETECTED");

			case sec_error::_SEC_E_SMARTCARD_CERT_REVOKED:
				return fmtns::format_to(ctx.out(), "SEC_E_SMARTCARD_CERT_REVOKED");

			case sec_error::_SEC_E_ISSUING_CA_UNTRUSTED:
				return fmtns::format_to(ctx.out(), "SEC_E_ISSUING_CA_UNTRUSTED");

			case sec_error::_SEC_E_REVOCATION_OFFLINE_C:
				return fmtns::format_to(ctx.out(), "SEC_E_REVOCATION_OFFLINE_C");

			case sec_error::_SEC_E_PKINIT_CLIENT_FAILURE:
				return fmtns::format_to(ctx.out(), "SEC_E_PKINIT_CLIENT_FAILURE");

			case sec_error::_SEC_E_SMARTCARD_CERT_EXPIRED:
				return fmtns::format_to(ctx.out(), "SEC_E_SMARTCARD_CERT_EXPIRED");

			case sec_error::_SEC_E_NO_S4U_PROT_SUPPORT:
				return fmtns::format_to(ctx.out(), "SEC_E_NO_S4U_PROT_SUPPORT");

			case sec_error::_SEC_E_CROSSREALM_DELEGATION_FAILURE:
				return fmtns::format_to(ctx.out(), "SEC_E_CROSSREALM_DELEGATION_FAILURE");

			case sec_error::_SEC_E_REVOCATION_OFFLINE_KDC:
				return fmtns::format_to(ctx.out(), "SEC_E_REVOCATION_OFFLINE_KDC");

			case sec_error::_SEC_E_ISSUING_CA_UNTRUSTED_KDC:
				return fmtns::format_to(ctx.out(), "SEC_E_ISSUING_CA_UNTRUSTED_KDC");

			case sec_error::_SEC_E_KDC_CERT_EXPIRED:
				return fmtns::format_to(ctx.out(), "SEC_E_KDC_CERT_EXPIRED");

			case sec_error::_SEC_E_KDC_CERT_REVOKED:
				return fmtns::format_to(ctx.out(), "SEC_E_KDC_CERT_REVOKED");

			case sec_error::_SEC_I_SIGNATURE_NEEDED:
				return fmtns::format_to(ctx.out(), "SEC_I_SIGNATURE_NEEDED");

			case sec_error::_SEC_E_INVALID_PARAMETER:
				return fmtns::format_to(ctx.out(), "SEC_E_INVALID_PARAMETER");

			case sec_error::_SEC_E_DELEGATION_POLICY:
				return fmtns::format_to(ctx.out(), "SEC_E_DELEGATION_POLICY");

			case sec_error::_SEC_E_POLICY_NLTM_ONLY:
				return fmtns::format_to(ctx.out(), "SEC_E_POLICY_NLTM_ONLY");

			case sec_error::_SEC_I_NO_RENEGOTIATION:
				return fmtns::format_to(ctx.out(), "SEC_I_NO_RENEGOTIATION");

			case sec_error::_SEC_E_NO_CONTEXT:
				return fmtns::format_to(ctx.out(), "SEC_E_NO_CONTEXT");

			case sec_error::_SEC_E_PKU2U_CERT_FAILURE:
				return fmtns::format_to(ctx.out(), "SEC_E_PKU2U_CERT_FAILURE");

			case sec_error::_SEC_E_MUTUAL_AUTH_FAILED:
				return fmtns::format_to(ctx.out(), "SEC_E_MUTUAL_AUTH_FAILED");

			case sec_error::_SEC_I_MESSAGE_FRAGMENT:
				return fmtns::format_to(ctx.out(), "SEC_I_MESSAGE_FRAGMENT");

			case sec_error::_SEC_E_ONLY_HTTPS_ALLOWED:
				return fmtns::format_to(ctx.out(), "SEC_E_ONLY_HTTPS_ALLOWED");

			case sec_error::_SEC_I_CONTINUE_NEEDED_MESSAGE_OK:
				return fmtns::format_to(ctx.out(), "SEC_I_CONTINUE_NEEDED_MESSAGE_OK");

			case sec_error::_SEC_E_APPLICATION_PROTOCOL_MISMATCH:
				return fmtns::format_to(ctx.out(), "SEC_E_APPLICATION_PROTOCOL_MISMATCH");

			case sec_error::_SEC_I_ASYNC_CALL_PENDING:
				return fmtns::format_to(ctx.out(), "SEC_I_ASYNC_CALL_PENDING");

			case sec_error::_SEC_E_INVALID_UPN_NAME:
				return fmtns::format_to(ctx.out(), "SEC_E_INVALID_UPN_NAME");

			case sec_error::_SEC_E_EXT_BUFFER_TOO_SMALL:
				return fmtns::format_to(ctx.out(), "SEC_E_EXT_BUFFER_TOO_SMALL");

			case sec_error::_SEC_E_INSUFFICIENT_BUFFERS:
				return fmtns::format_to(ctx.out(), "SEC_E_INSUFFICIENT_BUFFERS");

			default:
				return fmtns::format_to(ctx.out(), "{:08x}", (uint32_t)t);
		}
	}
};
#endif

#ifdef _WIN32
std::string wsa_error_to_string(int err);
#else
std::string errno_to_string(int err);
#endif

class sockets_error : public std::exception {
public:
#ifdef _WIN32
	sockets_error(const char* func) : err(WSAGetLastError()), msg(std::string(func) + " failed (error " + wsa_error_to_string(err) + ")") { }
#else
	sockets_error(const char* func) : err(errno), msg(std::string(func) + " failed (error " + errno_to_string(err) + ")") { }
#endif

	virtual const char* what() const noexcept {
		return msg.c_str();
	}

private:
	int err;
	std::string msg;
};
