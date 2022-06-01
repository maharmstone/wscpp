#include "wsclient-impl.h"
#include "wsexcept.h"
#include <string.h>
#include <sys/types.h>
#ifndef _WIN32
#include <sys/socket.h>
#endif
#if !defined(WITH_OPENSSL) && defined(_WIN32)
#include <schannel.h>
#endif

using namespace std;

#ifdef WITH_OPENSSL
class ssl_error : public exception {
public:
	ssl_error(const char* func, unsigned long err) {
		auto str = ERR_reason_error_string(err);

		if (str)
			msg = str;
		else
			msg = func + " failed: "s + to_string(err);
	}

	const char* what() const noexcept {
		return msg.c_str();
	}

private:
	string msg;
};

static int ssl_bio_read(BIO* bio, char* data, int len) noexcept {
	auto& c = *(ws::client_ssl*)BIO_get_data(bio);

	try {
		return c.ssl_read_cb(span((uint8_t*)data, len));
	} catch (...) {
		c.exception = current_exception();
		return -1;
	}
}

static int ssl_bio_write(BIO* bio, const char* data, int len) noexcept {
	auto& c = *(ws::client_ssl*)BIO_get_data(bio);

	try {
		return c.ssl_write_cb(span((uint8_t*)data, (size_t)len));
	} catch (...) {
		c.exception = current_exception();
		return -1;
	}
}

static long ssl_bio_ctrl(BIO* bio, int cmd, long num, void* ptr) noexcept {
	auto& c = *(ws::client_ssl*)BIO_get_data(bio);

	try {
		return c.ssl_ctrl_cb(cmd, num, ptr);
	} catch (...) {
		c.exception = current_exception();
		return -1;
	}
}

static string x509_err_to_string(int err) {
	switch (err) {
		case X509_V_OK:
			return "X509_V_OK";
		case X509_V_ERR_UNSPECIFIED:
			return "X509_V_ERR_UNSPECIFIED";
		case X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT:
			return "X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT";
		case X509_V_ERR_UNABLE_TO_GET_CRL:
			return "X509_V_ERR_UNABLE_TO_GET_CRL";
		case X509_V_ERR_UNABLE_TO_DECRYPT_CERT_SIGNATURE:
			return "X509_V_ERR_UNABLE_TO_DECRYPT_CERT_SIGNATURE";
		case X509_V_ERR_UNABLE_TO_DECRYPT_CRL_SIGNATURE:
			return "X509_V_ERR_UNABLE_TO_DECRYPT_CRL_SIGNATURE";
		case X509_V_ERR_UNABLE_TO_DECODE_ISSUER_PUBLIC_KEY:
			return "X509_V_ERR_UNABLE_TO_DECODE_ISSUER_PUBLIC_KEY";
		case X509_V_ERR_CERT_SIGNATURE_FAILURE:
			return "X509_V_ERR_CERT_SIGNATURE_FAILURE";
		case X509_V_ERR_CRL_SIGNATURE_FAILURE:
			return "X509_V_ERR_CRL_SIGNATURE_FAILURE";
		case X509_V_ERR_CERT_NOT_YET_VALID:
			return "X509_V_ERR_CERT_NOT_YET_VALID";
		case X509_V_ERR_CERT_HAS_EXPIRED:
			return "X509_V_ERR_CERT_HAS_EXPIRED";
		case X509_V_ERR_CRL_NOT_YET_VALID:
			return "X509_V_ERR_CRL_NOT_YET_VALID";
		case X509_V_ERR_CRL_HAS_EXPIRED:
			return "X509_V_ERR_CRL_HAS_EXPIRED";
		case X509_V_ERR_ERROR_IN_CERT_NOT_BEFORE_FIELD:
			return "X509_V_ERR_ERROR_IN_CERT_NOT_BEFORE_FIELD";
		case X509_V_ERR_ERROR_IN_CERT_NOT_AFTER_FIELD:
			return "X509_V_ERR_ERROR_IN_CERT_NOT_AFTER_FIELD";
		case X509_V_ERR_ERROR_IN_CRL_LAST_UPDATE_FIELD:
			return "X509_V_ERR_ERROR_IN_CRL_LAST_UPDATE_FIELD";
		case X509_V_ERR_ERROR_IN_CRL_NEXT_UPDATE_FIELD:
			return "X509_V_ERR_ERROR_IN_CRL_NEXT_UPDATE_FIELD";
		case X509_V_ERR_OUT_OF_MEM:
			return "X509_V_ERR_OUT_OF_MEM";
		case X509_V_ERR_DEPTH_ZERO_SELF_SIGNED_CERT:
			return "X509_V_ERR_DEPTH_ZERO_SELF_SIGNED_CERT";
		case X509_V_ERR_SELF_SIGNED_CERT_IN_CHAIN:
			return "X509_V_ERR_SELF_SIGNED_CERT_IN_CHAIN";
		case X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT_LOCALLY:
			return "X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT_LOCALLY";
		case X509_V_ERR_UNABLE_TO_VERIFY_LEAF_SIGNATURE:
			return "X509_V_ERR_UNABLE_TO_VERIFY_LEAF_SIGNATURE";
		case X509_V_ERR_CERT_CHAIN_TOO_LONG:
			return "X509_V_ERR_CERT_CHAIN_TOO_LONG";
		case X509_V_ERR_CERT_REVOKED:
			return "X509_V_ERR_CERT_REVOKED";
		case X509_V_ERR_INVALID_CA:
			return "X509_V_ERR_INVALID_CA";
		case X509_V_ERR_PATH_LENGTH_EXCEEDED:
			return "X509_V_ERR_PATH_LENGTH_EXCEEDED";
		case X509_V_ERR_INVALID_PURPOSE:
			return "X509_V_ERR_INVALID_PURPOSE";
		case X509_V_ERR_CERT_UNTRUSTED:
			return "X509_V_ERR_CERT_UNTRUSTED";
		case X509_V_ERR_CERT_REJECTED:
			return "X509_V_ERR_CERT_REJECTED";
		case X509_V_ERR_SUBJECT_ISSUER_MISMATCH:
			return "X509_V_ERR_SUBJECT_ISSUER_MISMATCH";
		case X509_V_ERR_AKID_SKID_MISMATCH:
			return "X509_V_ERR_AKID_SKID_MISMATCH";
		case X509_V_ERR_AKID_ISSUER_SERIAL_MISMATCH:
			return "X509_V_ERR_AKID_ISSUER_SERIAL_MISMATCH";
		case X509_V_ERR_KEYUSAGE_NO_CERTSIGN:
			return "X509_V_ERR_KEYUSAGE_NO_CERTSIGN";
		case X509_V_ERR_UNABLE_TO_GET_CRL_ISSUER:
			return "X509_V_ERR_UNABLE_TO_GET_CRL_ISSUER";
		case X509_V_ERR_UNHANDLED_CRITICAL_EXTENSION:
			return "X509_V_ERR_UNHANDLED_CRITICAL_EXTENSION";
		case X509_V_ERR_KEYUSAGE_NO_CRL_SIGN:
			return "X509_V_ERR_KEYUSAGE_NO_CRL_SIGN";
		case X509_V_ERR_UNHANDLED_CRITICAL_CRL_EXTENSION:
			return "X509_V_ERR_UNHANDLED_CRITICAL_CRL_EXTENSION";
		case X509_V_ERR_INVALID_NON_CA:
			return "X509_V_ERR_INVALID_NON_CA";
		case X509_V_ERR_PROXY_PATH_LENGTH_EXCEEDED:
			return "X509_V_ERR_PROXY_PATH_LENGTH_EXCEEDED";
		case X509_V_ERR_KEYUSAGE_NO_DIGITAL_SIGNATURE:
			return "X509_V_ERR_KEYUSAGE_NO_DIGITAL_SIGNATURE";
		case X509_V_ERR_PROXY_CERTIFICATES_NOT_ALLOWED:
			return "X509_V_ERR_PROXY_CERTIFICATES_NOT_ALLOWED";
		case X509_V_ERR_INVALID_EXTENSION:
			return "X509_V_ERR_INVALID_EXTENSION";
		case X509_V_ERR_INVALID_POLICY_EXTENSION:
			return "X509_V_ERR_INVALID_POLICY_EXTENSION";
		case X509_V_ERR_NO_EXPLICIT_POLICY:
			return "X509_V_ERR_NO_EXPLICIT_POLICY";
		case X509_V_ERR_DIFFERENT_CRL_SCOPE:
			return "X509_V_ERR_DIFFERENT_CRL_SCOPE";
		case X509_V_ERR_UNSUPPORTED_EXTENSION_FEATURE:
			return "X509_V_ERR_UNSUPPORTED_EXTENSION_FEATURE";
		case X509_V_ERR_UNNESTED_RESOURCE:
			return "X509_V_ERR_UNNESTED_RESOURCE";
		case X509_V_ERR_PERMITTED_VIOLATION:
			return "X509_V_ERR_PERMITTED_VIOLATION";
		case X509_V_ERR_EXCLUDED_VIOLATION:
			return "X509_V_ERR_EXCLUDED_VIOLATION";
		case X509_V_ERR_SUBTREE_MINMAX:
			return "X509_V_ERR_SUBTREE_MINMAX";
		case X509_V_ERR_APPLICATION_VERIFICATION:
			return "X509_V_ERR_APPLICATION_VERIFICATION";
		case X509_V_ERR_UNSUPPORTED_CONSTRAINT_TYPE:
			return "X509_V_ERR_UNSUPPORTED_CONSTRAINT_TYPE";
		case X509_V_ERR_UNSUPPORTED_CONSTRAINT_SYNTAX:
			return "X509_V_ERR_UNSUPPORTED_CONSTRAINT_SYNTAX";
		case X509_V_ERR_UNSUPPORTED_NAME_SYNTAX:
			return "X509_V_ERR_UNSUPPORTED_NAME_SYNTAX";
		case X509_V_ERR_CRL_PATH_VALIDATION_ERROR:
			return "X509_V_ERR_CRL_PATH_VALIDATION_ERROR";
		case X509_V_ERR_PATH_LOOP:
			return "X509_V_ERR_PATH_LOOP";
		case X509_V_ERR_SUITE_B_INVALID_VERSION:
			return "X509_V_ERR_SUITE_B_INVALID_VERSION";
		case X509_V_ERR_SUITE_B_INVALID_ALGORITHM:
			return "X509_V_ERR_SUITE_B_INVALID_ALGORITHM";
		case X509_V_ERR_SUITE_B_INVALID_CURVE:
			return "X509_V_ERR_SUITE_B_INVALID_CURVE";
		case X509_V_ERR_SUITE_B_INVALID_SIGNATURE_ALGORITHM:
			return "X509_V_ERR_SUITE_B_INVALID_SIGNATURE_ALGORITHM";
		case X509_V_ERR_SUITE_B_LOS_NOT_ALLOWED:
			return "X509_V_ERR_SUITE_B_LOS_NOT_ALLOWED";
		case X509_V_ERR_SUITE_B_CANNOT_SIGN_P_384_WITH_P_256:
			return "X509_V_ERR_SUITE_B_CANNOT_SIGN_P_384_WITH_P_256";
		case X509_V_ERR_HOSTNAME_MISMATCH:
			return "X509_V_ERR_HOSTNAME_MISMATCH";
		case X509_V_ERR_EMAIL_MISMATCH:
			return "X509_V_ERR_EMAIL_MISMATCH";
		case X509_V_ERR_IP_ADDRESS_MISMATCH:
			return "X509_V_ERR_IP_ADDRESS_MISMATCH";
		case X509_V_ERR_DANE_NO_MATCH:
			return "X509_V_ERR_DANE_NO_MATCH";
		case X509_V_ERR_EE_KEY_TOO_SMALL:
			return "X509_V_ERR_EE_KEY_TOO_SMALL";
		case X509_V_ERR_CA_KEY_TOO_SMALL:
			return "X509_V_ERR_CA_KEY_TOO_SMALL";
		case X509_V_ERR_CA_MD_TOO_WEAK:
			return "X509_V_ERR_CA_MD_TOO_WEAK";
		case X509_V_ERR_INVALID_CALL:
			return "X509_V_ERR_INVALID_CALL";
		case X509_V_ERR_STORE_LOOKUP:
			return "X509_V_ERR_STORE_LOOKUP";
		case X509_V_ERR_NO_VALID_SCTS:
			return "X509_V_ERR_NO_VALID_SCTS";
		case X509_V_ERR_PROXY_SUBJECT_NAME_VIOLATION:
			return "X509_V_ERR_PROXY_SUBJECT_NAME_VIOLATION";
		case X509_V_ERR_OCSP_VERIFY_NEEDED:
			return "X509_V_ERR_OCSP_VERIFY_NEEDED";
		case X509_V_ERR_OCSP_VERIFY_FAILED:
			return "X509_V_ERR_OCSP_VERIFY_FAILED";
		case X509_V_ERR_OCSP_CERT_UNKNOWN:
			return "X509_V_ERR_OCSP_CERT_UNKNOWN";
		case X509_V_ERR_SIGNATURE_ALGORITHM_MISMATCH:
			return "X509_V_ERR_SIGNATURE_ALGORITHM_MISMATCH";
		case X509_V_ERR_NO_ISSUER_PUBLIC_KEY:
			return "X509_V_ERR_NO_ISSUER_PUBLIC_KEY";
		case X509_V_ERR_UNSUPPORTED_SIGNATURE_ALGORITHM:
			return "X509_V_ERR_UNSUPPORTED_SIGNATURE_ALGORITHM";
		case X509_V_ERR_EC_KEY_EXPLICIT_PARAMS:
			return "X509_V_ERR_EC_KEY_EXPLICIT_PARAMS";
		default:
			return to_string(err);
	}
}

static int verify_callback(int preverify, X509_STORE_CTX* x509_ctx) noexcept {
	auto ssl = (SSL*)X509_STORE_CTX_get_ex_data(x509_ctx, SSL_get_ex_data_X509_STORE_CTX_idx());
	auto& c = *(ws::client_ssl*)SSL_get_ex_data(ssl, 0);

	try {
		return c.ssl_verify_cb(preverify, x509_ctx);
	} catch (...) {
		c.exception = current_exception();
		return 0;
	}
}

#ifdef _WIN32
class cert_store_closer {
public:
	typedef HCERTSTORE pointer;

	void operator()(HCERTSTORE h) {
		CertCloseStore(h, 0);
	}
};

class x509_closer {
public:
	typedef X509* pointer;

	void operator()(X509* x) {
		X509_free(x);
	}
};

static void add_certs_to_store(X509_STORE* store) {
	PCCERT_CONTEXT certctx = nullptr;

	unique_ptr<HCERTSTORE, cert_store_closer> h{CertOpenSystemStoreW(0, L"ROOT")};

	if (!h)
		throw formatted_error("CertOpenSystemStore failed (error {})", GetLastError());

	while ((certctx = CertEnumCertificatesInStore(h.get(), certctx))) {
		if (!(certctx->dwCertEncodingType & X509_ASN_ENCODING))
			continue;

		const unsigned char* cert = certctx->pbCertEncoded;

		unique_ptr<X509*, x509_closer> x509{d2i_X509(nullptr, &cert, certctx->cbCertEncoded)};

		if (!x509)
			continue;

		X509_STORE_add_cert(store, x509.get());
	}
}
#endif

namespace ws {
	int client_ssl::ssl_read_cb(std::span<uint8_t> s) {
		int copied = 0;

		if (s.empty())
			return 0;

		if (!ssl_recv_buf.empty()) {
			auto to_copy = min(s.size(), ssl_recv_buf.size());

			memcpy(s.data(), ssl_recv_buf.data(), to_copy);
			ssl_recv_buf.erase(ssl_recv_buf.begin(), ssl_recv_buf.begin() + to_copy);

			if (s.size() == to_copy)
				return s.size();

			copied = to_copy;
			s = s.subspan(to_copy);
		}

		auto ret = ::recv(client.sock, s.data(), s.size(), 0);

#ifdef _WIN32
		if (ret == SOCKET_ERROR) {
			auto err = WSAGetLastError();

			if (err == WSAECONNRESET) {
				client.open = false;
				return copied;
			}

			throw formatted_error("recv failed ({})", wsa_error_to_string(err));
		}
#else
		if (ret == -1) {
			if (errno == ECONNRESET) {
				client.open = false;
				return copied;
			}

			throw formatted_error("recv failed ({})", errno_to_string(errno));
		}
#endif

		if (ret == 0) {
			client.open = false;
			return copied;
		}

		copied += ret;

		return copied;
	}

	int client_ssl::ssl_write_cb(span<const uint8_t> sv) {
		client.send_raw(sv);

		return (int)sv.size();
	}

	long client_ssl::ssl_ctrl_cb(int cmd, long, void*) {
		switch (cmd) {
			case BIO_CTRL_FLUSH:
				return 1;

			case BIO_C_DO_STATE_MACHINE: {
				auto ret = SSL_do_handshake(ssl.get());

				if (ret != 1) {
					if (exception)
						rethrow_exception(exception);

					throw formatted_error("SSL_do_handshake failed (error {})", SSL_get_error(ssl.get(), ret));
				}

				return 1;
			}
		}

		return 0;
	}

	int client_ssl::ssl_verify_cb(int preverify, X509_STORE_CTX* x509_ctx) {
		int err = X509_STORE_CTX_get_error(x509_ctx);

		if (preverify == 0) {
			auto str = x509_err_to_string(err);

			throw formatted_error("Error verifying SSL certificate: {}", str);
		}

		return preverify;
	}

	client_ssl::client_ssl(client_pimpl& client) : client(client) {
		ctx.reset(SSL_CTX_new(SSLv23_method()));
		if (!ctx)
			throw ssl_error("SSL_CTX_new", ERR_get_error());

		if (!SSL_CTX_set_default_verify_paths(ctx.get()))
			throw ssl_error("SSL_CTX_set_default_verify_paths", ERR_get_error());

#ifdef _WIN32
		add_certs_to_store(SSL_CTX_get_cert_store(ctx.get()));
#endif

		SSL_CTX_set_verify(ctx.get(), SSL_VERIFY_PEER, verify_callback);

		SSL_CTX_set_options(ctx.get(), SSL_OP_ALL | SSL_OP_NO_SSLv2 | SSL_OP_NO_SSLv3 | SSL_OP_NO_COMPRESSION);

		meth.reset(BIO_meth_new(BIO_TYPE_MEM, "wscpp"));
		if (!meth)
			throw ssl_error("BIO_meth_new", ERR_get_error());

		BIO_meth_set_read(meth.get(), ssl_bio_read);
		BIO_meth_set_write(meth.get(), ssl_bio_write);
		BIO_meth_set_ctrl(meth.get(), ssl_bio_ctrl);
		BIO_meth_set_destroy(meth.get(), [](BIO*) {
			return 1;
		});

		bio = BIO_new(meth.get());
		if (!bio)
			throw ssl_error("BIO_new", ERR_get_error());

		BIO_set_data(bio, this);

		ssl.reset(SSL_new(ctx.get()));
		if (!ssl) {
			BIO_free_all(bio);
			throw ssl_error("SSL_new", ERR_get_error());
		}

		if (!SSL_set_ex_data(ssl.get(), 0, this)) {
			BIO_free_all(bio);
			throw ssl_error("SSL_set_ex_data", ERR_get_error());
		}

		SSL_set_bio(ssl.get(), bio, bio);

		if (!SSL_set1_host(ssl.get(), client.host.c_str()))
			throw ssl_error("SSL_set1_host", ERR_get_error());

		if (!SSL_set_tlsext_host_name(ssl.get(), client.host.c_str()))
			throw ssl_error("SSL_set_tlsext_host_name", ERR_get_error());

		SSL_set_connect_state(ssl.get());

		SSL_connect(ssl.get());
		if (exception)
			rethrow_exception(exception);

		if (BIO_do_connect(bio) != 1) {
			if (exception)
				rethrow_exception(exception);

			throw ssl_error("BIO_do_connect", ERR_get_error());
		}

		if (BIO_do_handshake(bio) != 1) {
			if (exception)
				rethrow_exception(exception);

			throw ssl_error("BIO_do_handshake", ERR_get_error());
		}
	}

	void client_ssl::send(std::span<const uint8_t> sv) {
		while (!sv.empty()) {
			auto ret = SSL_write(ssl.get(), sv.data(), (int)sv.size());

			if (ret <= 0) {
				if (exception)
					rethrow_exception(exception);

				throw formatted_error("SSL_write failed (error {})", SSL_get_error(ssl.get(), ret));
			}

			sv = sv.subspan(ret);
		}
	}

	unsigned int client_ssl::recv(span<uint8_t> s) {
		auto ret = SSL_read(ssl.get(), s.data(), s.size());

		if (ret <= 0) {
			if (exception)
				rethrow_exception(exception);

			throw formatted_error("SSL_read failed (error {})", SSL_get_error(ssl.get(), ret));
		}

		return ret;
	}
};
#elif defined(_WIN32)
namespace ws {
	client_ssl::client_ssl(client_pimpl& client) : client(client) {
		SECURITY_STATUS sec_status;
		SecBuffer outbuf;
		SecBufferDesc out;
		uint32_t context_attr;
		string outstr;
		SCHANNEL_CRED cred;

		memset(&cred, 0, sizeof(cred));

		cred.dwVersion = SCHANNEL_CRED_VERSION;
		cred.grbitEnabledProtocols = SP_PROT_TLS1_2_CLIENT;
		cred.dwFlags = SCH_CRED_AUTO_CRED_VALIDATION;

		sec_status = AcquireCredentialsHandleW(nullptr, (LPWSTR)UNISP_NAME_W, SECPKG_CRED_OUTBOUND, nullptr, &cred,
											   nullptr, nullptr, &cred_handle, nullptr);

		if (FAILED(sec_status))
			throw formatted_error("AcquireCredentialsHandle returned {}", (enum sec_error)sec_status);

		outbuf.cbBuffer = 0;
		outbuf.BufferType = SECBUFFER_TOKEN;
		outbuf.pvBuffer = nullptr;

		out.ulVersion = SECBUFFER_VERSION;
		out.cBuffers = 1;
		out.pBuffers = &outbuf;

		auto host = utf8_to_utf16(client.host);

		sec_status = InitializeSecurityContextW(&cred_handle, nullptr, (SEC_WCHAR*)host.c_str(),
												ISC_REQ_ALLOCATE_MEMORY, 0, 0, nullptr, 0,
												&ctx_handle, &out, (ULONG*)&context_attr, nullptr);
		if (FAILED(sec_status)) {
			FreeCredentialsHandle(&cred_handle);
			throw formatted_error("InitializeSecurityContext returned {}", (enum sec_error)sec_status);
		}

		outstr = string((char*)outbuf.pvBuffer, outbuf.cbBuffer);

		if (outbuf.pvBuffer)
			FreeContextBuffer(outbuf.pvBuffer);

		ctx_handle_set = true;

		string payload;
		bool read_more = false;

		while (sec_status == SEC_I_CONTINUE_NEEDED || sec_status == SEC_E_INCOMPLETE_MESSAGE) {
			array<SecBuffer, 2> inbuf;
			SecBufferDesc in;

			if (!outstr.empty()) {
				try {
					client.send_raw(span((uint8_t*)outstr.data(), outstr.size()));
					outstr.clear();
				} catch (...) {
					FreeCredentialsHandle(&cred_handle);
					throw;
				}
			}

			if (payload.empty() || read_more) {
				char buf[4096];

				auto bytes = ::recv(client.sock, buf, sizeof(buf), 0);

				if (bytes == SOCKET_ERROR) {
					FreeCredentialsHandle(&cred_handle);
					throw formatted_error("recv failed ({}).", wsa_error_to_string(WSAGetLastError()));
				}

				if (bytes == 0) {
					client.open = false;
					FreeCredentialsHandle(&cred_handle);
					throw runtime_error("Disconnected.");
				}

				payload += string_view(buf, bytes);

				read_more = false;
			}

			outbuf.cbBuffer = 0;
			outbuf.BufferType = SECBUFFER_TOKEN;
			outbuf.pvBuffer = nullptr;

			inbuf[0].cbBuffer = (long)payload.length();
			inbuf[0].BufferType = SECBUFFER_TOKEN;
			inbuf[0].pvBuffer = payload.data();

			inbuf[1].cbBuffer = 0;
			inbuf[1].BufferType = SECBUFFER_EMPTY;
			inbuf[1].pvBuffer = nullptr;

			in.ulVersion = SECBUFFER_VERSION;
			in.cBuffers = inbuf.size();
			in.pBuffers = inbuf.data();

			sec_status = InitializeSecurityContextW(&cred_handle, &ctx_handle, nullptr,
													ISC_REQ_ALLOCATE_MEMORY, 0, 0, &in, 0,
													nullptr, &out, (ULONG*)&context_attr, nullptr);

			if (sec_status == SEC_E_INCOMPLETE_MESSAGE) {
				read_more = true;
				continue;
			}

			if (FAILED(sec_status)) {
				FreeCredentialsHandle(&cred_handle);
				throw formatted_error("InitializeSecurityContext returned {}", (enum sec_error)sec_status);
			}

			outstr = string((char*)outbuf.pvBuffer, outbuf.cbBuffer);

			if (outbuf.pvBuffer)
				FreeContextBuffer(outbuf.pvBuffer);

			if (inbuf[1].BufferType == SECBUFFER_EXTRA)
				payload = payload.substr(payload.length() - inbuf[1].cbBuffer);
			else
				payload.clear();
		}

		if (sec_status != SEC_E_OK) {
			FreeCredentialsHandle(&cred_handle);
			throw formatted_error("InitializeSecurityContext returned unexpected status {}", (enum sec_error)sec_status);
		}

		sec_status = QueryContextAttributes(&ctx_handle, SECPKG_ATTR_STREAM_SIZES, &stream_sizes);
		if (FAILED(sec_status)) {
			FreeCredentialsHandle(&cred_handle);
			throw formatted_error("QueryContextAttributes(SECPKG_ATTR_STREAM_SIZES) returned {}", (enum sec_error)sec_status);
		}
	}

	client_ssl::~client_ssl() {
		if (ctx_handle_set)
			DeleteSecurityContext(&ctx_handle);

		FreeCredentialsHandle(&cred_handle);
	}

	void client_ssl::send(std::span<const uint8_t> sv) {
		SECURITY_STATUS sec_status;
		array<SecBuffer, 4> buf;
		SecBufferDesc bufdesc;
		string payload;

		memset(buf.data(), 0, sizeof(SecBuffer) * buf.size());

		payload.resize(stream_sizes.cbHeader + sv.size() + stream_sizes.cbTrailer);

		buf[0].BufferType = SECBUFFER_STREAM_HEADER;
		buf[0].pvBuffer = payload.data();
		buf[0].cbBuffer = stream_sizes.cbHeader;

		buf[1].cbBuffer = (long)sv.size();
		buf[1].BufferType = SECBUFFER_DATA;
		buf[1].pvBuffer = payload.data() + stream_sizes.cbHeader;

		buf[2].BufferType = SECBUFFER_STREAM_TRAILER;
		buf[2].pvBuffer = payload.data() + stream_sizes.cbHeader + sv.size();
		buf[2].cbBuffer = stream_sizes.cbTrailer;

		buf[3].BufferType = SECBUFFER_EMPTY;

		memcpy(buf[1].pvBuffer, sv.data(), sv.size());

		bufdesc.ulVersion = SECBUFFER_VERSION;
		bufdesc.cBuffers = buf.size();
		bufdesc.pBuffers = buf.data();

		sec_status = EncryptMessage(&ctx_handle, 0, &bufdesc, 0);

		if (FAILED(sec_status))
			throw formatted_error("EncryptMessage returned {}", (enum sec_error)sec_status);

		payload.resize(buf[0].cbBuffer + buf[1].cbBuffer + buf[2].cbBuffer);

		client.send_raw(span((uint8_t*)payload.data(), payload.size()));
	}

	void client_ssl::recv_raw(span<uint8_t> s) {
		while (!s.empty()) {
			auto bytes = ::recv(client.sock, (char*)s.data(), s.size(), 0);

			if (bytes == SOCKET_ERROR)
				throw formatted_error("recv failed ({}).", wsa_error_to_string(WSAGetLastError()));

			if (bytes == 0) {
				client.open = false;
				return;
			}

			s = s.subspan(bytes);
		}
	}

	unsigned int client_ssl::recv(span<uint8_t> s) {
		SECURITY_STATUS sec_status;
		array<SecBuffer, 4> secbuf;
		SecBufferDesc bufdesc;
		vector<uint8_t> recvbuf;
		unsigned int copied = 0;

		if (s.empty())
			return 0;

		if (!ssl_recv_buf.empty()) {
			auto to_copy = min(s.size(), ssl_recv_buf.size());

			memcpy(s.data(), ssl_recv_buf.data(), to_copy);
			ssl_recv_buf.erase(ssl_recv_buf.begin(), ssl_recv_buf.begin() + to_copy);

			copied += to_copy;

			if (s.size() == to_copy)
				return copied;

			s = s.subspan(to_copy);
		}

		recvbuf.resize(stream_sizes.cbHeader);
		recv_raw(recvbuf);

		while (true) {
			bool found = false;

			memset(secbuf.data(), 0, sizeof(SecBuffer) * secbuf.size());
			secbuf[0].BufferType = SECBUFFER_DATA;
			secbuf[0].pvBuffer = recvbuf.data();
			secbuf[0].cbBuffer = (long)recvbuf.size();
			secbuf[1].BufferType = SECBUFFER_EMPTY;
			secbuf[2].BufferType = SECBUFFER_EMPTY;
			secbuf[3].BufferType = SECBUFFER_EMPTY;

			bufdesc.ulVersion = SECBUFFER_VERSION;
			bufdesc.cBuffers = secbuf.size();
			bufdesc.pBuffers = secbuf.data();

			sec_status = DecryptMessage(&ctx_handle, &bufdesc, 0, nullptr);

			if (sec_status == SEC_E_INCOMPLETE_MESSAGE && secbuf[0].BufferType == SECBUFFER_MISSING) {
				recvbuf.resize(recvbuf.size() + secbuf[0].cbBuffer);
				recv_raw(span(recvbuf).last(secbuf[0].cbBuffer));
				continue;
			}

			if (FAILED(sec_status))
				throw formatted_error("DecryptMessage returned {}", (enum sec_error)sec_status);

			for (const auto& b : secbuf) {
				if (b.BufferType == SECBUFFER_DATA) {
					auto bsp = span((uint8_t*)b.pvBuffer, b.cbBuffer);
					auto to_copy = min(s.size(), bsp.size());

					memcpy(s.data(), bsp.data(), to_copy);

					copied += to_copy;
					s = s.subspan(to_copy);

					bsp = bsp.subspan(to_copy);
					ssl_recv_buf.insert(ssl_recv_buf.end(), bsp.begin(), bsp.end());

					found = true;
					break;
				}
			}

			if (!found)
				throw runtime_error("DecryptMessage did not return a SECBUFFER_DATA buffer.");

			return copied;
		}
	}
};
#endif
