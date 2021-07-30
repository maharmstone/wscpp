#include "wsclient-impl.h"
#include "wsexcept.h"
#include <string.h>
#include <sys/types.h>
#ifndef _WIN32
#include <sys/socket.h>
#endif

using namespace std;

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
		return c.ssl_read_cb(data, len);
	} catch (...) {
		c.exception = current_exception();
		return -1;
	}
}

static int ssl_bio_write(BIO* bio, const char* data, int len) noexcept {
	auto& c = *(ws::client_ssl*)BIO_get_data(bio);

	try {
		return c.ssl_write_cb(string_view{data, (size_t)len});
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

namespace ws {
	int client_ssl::ssl_read_cb(char* data, int len) {
		int copied = 0;

		if (len == 0)
			return 0;

		if (!ssl_recv_buf.empty()) {
			auto to_copy = min(len, (int)ssl_recv_buf.length());

			memcpy(data, ssl_recv_buf.data(), to_copy);
			ssl_recv_buf = ssl_recv_buf.substr(to_copy);

			if (len == to_copy)
				return len;

			len -= to_copy;
			copied = to_copy;
			data += to_copy;
		}

		auto ret = ::recv(client.sock, data, len, 0);

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

	int client_ssl::ssl_write_cb(const string_view& sv) {
		client.send_raw(sv);

		return (int)sv.length();
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

	void client_ssl::send(std::string_view sv) {
		while (!sv.empty()) {
			auto ret = SSL_write(ssl.get(), sv.data(), (int)sv.length());

			if (ret <= 0) {
				if (exception)
					rethrow_exception(exception);

				throw formatted_error("SSL_write failed (error {})", SSL_get_error(ssl.get(), ret));
			}

			sv = sv.substr(ret);
		}
	}

	unsigned int client_ssl::recv(unsigned int len, void* buf) {
		auto ret = SSL_read(ssl.get(), buf, len);

		if (ret <= 0) {
			if (exception)
				rethrow_exception(exception);

			throw formatted_error("SSL_read failed (error {})", SSL_get_error(ssl.get(), ret));
		}

		return ret;
	}
};
