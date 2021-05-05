#ifdef _WIN32
#include <winsock2.h>
#include <ws2ipdef.h>
#endif
#include "wscpp.h"
#include "wsexcept.h"

using namespace std;

namespace ws {
#ifdef _WIN32
    sockets_error::sockets_error(const char* func) : err(WSAGetLastError()), msg(string(func) + " failed (error " + wsa_error_to_string(err) + ")") {
#else
    sockets_error::sockets_error(const char* func) : err(errno), msg(string(func) + " failed (error " + errno_to_string(err) + ")") {
#endif
    }
}

#ifdef _WIN32
string wsa_error_to_string(int err) {
	switch (err) {
		case WSA_INVALID_HANDLE: return "WSA_INVALID_HANDLE";
		case WSA_NOT_ENOUGH_MEMORY: return "WSA_NOT_ENOUGH_MEMORY";
		case WSA_INVALID_PARAMETER: return "WSA_INVALID_PARAMETER";
		case WSA_OPERATION_ABORTED: return "WSA_OPERATION_ABORTED";
		case WSA_IO_INCOMPLETE: return "WSA_IO_INCOMPLETE";
		case WSA_IO_PENDING: return "WSA_IO_PENDING";
		case WSAEINTR: return "WSAEINTR";
		case WSAEBADF: return "WSAEBADF";
		case WSAEACCES: return "WSAEACCES";
		case WSAEFAULT: return "WSAEFAULT";
		case WSAEINVAL: return "WSAEINVAL";
		case WSAEMFILE: return "WSAEMFILE";
		case WSAEWOULDBLOCK: return "WSAEWOULDBLOCK";
		case WSAEINPROGRESS: return "WSAEINPROGRESS";
		case WSAEALREADY: return "WSAEALREADY";
		case WSAENOTSOCK: return "WSAENOTSOCK";
		case WSAEDESTADDRREQ: return "WSAEDESTADDRREQ";
		case WSAEMSGSIZE: return "WSAEMSGSIZE";
		case WSAEPROTOTYPE: return "WSAEPROTOTYPE";
		case WSAENOPROTOOPT: return "WSAENOPROTOOPT";
		case WSAEPROTONOSUPPORT: return "WSAEPROTONOSUPPORT";
		case WSAESOCKTNOSUPPORT: return "WSAESOCKTNOSUPPORT";
		case WSAEOPNOTSUPP: return "WSAEOPNOTSUPP";
		case WSAEPFNOSUPPORT: return "WSAEPFNOSUPPORT";
		case WSAEAFNOSUPPORT: return "WSAEAFNOSUPPORT";
		case WSAEADDRINUSE: return "WSAEADDRINUSE";
		case WSAEADDRNOTAVAIL: return "WSAEADDRNOTAVAIL";
		case WSAENETDOWN: return "WSAENETDOWN";
		case WSAENETUNREACH: return "WSAENETUNREACH";
		case WSAENETRESET: return "WSAENETRESET";
		case WSAECONNABORTED: return "WSAECONNABORTED";
		case WSAECONNRESET: return "WSAECONNRESET";
		case WSAENOBUFS: return "WSAENOBUFS";
		case WSAEISCONN: return "WSAEISCONN";
		case WSAENOTCONN: return "WSAENOTCONN";
		case WSAESHUTDOWN: return "WSAESHUTDOWN";
		case WSAETOOMANYREFS: return "WSAETOOMANYREFS";
		case WSAETIMEDOUT: return "WSAETIMEDOUT";
		case WSAECONNREFUSED: return "WSAECONNREFUSED";
		case WSAELOOP: return "WSAELOOP";
		case WSAENAMETOOLONG: return "WSAENAMETOOLONG";
		case WSAEHOSTDOWN: return "WSAEHOSTDOWN";
		case WSAEHOSTUNREACH: return "WSAEHOSTUNREACH";
		case WSAENOTEMPTY: return "WSAENOTEMPTY";
		case WSAEPROCLIM: return "WSAEPROCLIM";
		case WSAEUSERS: return "WSAEUSERS";
		case WSAEDQUOT: return "WSAEDQUOT";
		case WSAESTALE: return "WSAESTALE";
		case WSAEREMOTE: return "WSAEREMOTE";
		case WSASYSNOTREADY: return "WSASYSNOTREADY";
		case WSAVERNOTSUPPORTED: return "WSAVERNOTSUPPORTED";
		case WSANOTINITIALISED: return "WSANOTINITIALISED";
		case WSAEDISCON: return "WSAEDISCON";
		case WSAENOMORE: return "WSAENOMORE";
		case WSAECANCELLED: return "WSAECANCELLED";
		case WSAEINVALIDPROCTABLE: return "WSAEINVALIDPROCTABLE";
		case WSAEINVALIDPROVIDER: return "WSAEINVALIDPROVIDER";
		case WSAEPROVIDERFAILEDINIT: return "WSAEPROVIDERFAILEDINIT";
		case WSASYSCALLFAILURE: return "WSASYSCALLFAILURE";
		case WSASERVICE_NOT_FOUND: return "WSASERVICE_NOT_FOUND";
		case WSATYPE_NOT_FOUND: return "WSATYPE_NOT_FOUND";
		case WSA_E_NO_MORE: return "WSA_E_NO_MORE";
		case WSA_E_CANCELLED: return "WSA_E_CANCELLED";
		case WSAEREFUSED: return "WSAEREFUSED";
		case WSAHOST_NOT_FOUND: return "WSAHOST_NOT_FOUND";
		case WSATRY_AGAIN: return "WSATRY_AGAIN";
		case WSANO_RECOVERY: return "WSANO_RECOVERY";
		case WSANO_DATA: return "WSANO_DATA";
		case WSA_QOS_RECEIVERS: return "WSA_QOS_RECEIVERS";
		case WSA_QOS_SENDERS: return "WSA_QOS_SENDERS";
		case WSA_QOS_NO_SENDERS: return "WSA_QOS_NO_SENDERS";
		case WSA_QOS_NO_RECEIVERS: return "WSA_QOS_NO_RECEIVERS";
		case WSA_QOS_REQUEST_CONFIRMED: return "WSA_QOS_REQUEST_CONFIRMED";
		case WSA_QOS_ADMISSION_FAILURE: return "WSA_QOS_ADMISSION_FAILURE";
		case WSA_QOS_POLICY_FAILURE: return "WSA_QOS_POLICY_FAILURE";
		case WSA_QOS_BAD_STYLE: return "WSA_QOS_BAD_STYLE";
		case WSA_QOS_BAD_OBJECT: return "WSA_QOS_BAD_OBJECT";
		case WSA_QOS_TRAFFIC_CTRL_ERROR: return "WSA_QOS_TRAFFIC_CTRL_ERROR";
		case WSA_QOS_GENERIC_ERROR: return "WSA_QOS_GENERIC_ERROR";
		case WSA_QOS_ESERVICETYPE: return "WSA_QOS_ESERVICETYPE";
		case WSA_QOS_EFLOWSPEC: return "WSA_QOS_EFLOWSPEC";
		case WSA_QOS_EPROVSPECBUF: return "WSA_QOS_EPROVSPECBUF";
		case WSA_QOS_EFILTERSTYLE: return "WSA_QOS_EFILTERSTYLE";
		case WSA_QOS_EFILTERTYPE: return "WSA_QOS_EFILTERTYPE";
		case WSA_QOS_EFILTERCOUNT: return "WSA_QOS_EFILTERCOUNT";
		case WSA_QOS_EOBJLENGTH: return "WSA_QOS_EOBJLENGTH";
		case WSA_QOS_EFLOWCOUNT: return "WSA_QOS_EFLOWCOUNT";
		case WSA_QOS_EUNKOWNPSOBJ: return "WSA_QOS_EUNKOWNPSOBJ";
		case WSA_QOS_EPOLICYOBJ: return "WSA_QOS_EPOLICYOBJ";
		case WSA_QOS_EFLOWDESC: return "WSA_QOS_EFLOWDESC";
		case WSA_QOS_EPSFLOWSPEC: return "WSA_QOS_EPSFLOWSPEC";
		case WSA_QOS_EPSFILTERSPEC: return "WSA_QOS_EPSFILTERSPEC";
		case WSA_QOS_ESDMODEOBJ: return "WSA_QOS_ESDMODEOBJ";
		case WSA_QOS_ESHAPERATEOBJ: return "WSA_QOS_ESHAPERATEOBJ";
		case WSA_QOS_RESERVED_PETYPE: return "WSA_QOS_RESERVED_PETYPE";
		default: return to_string(err);
	}
}
#else
string errno_to_string(int err) {
	switch (err) {
		case E2BIG: return "E2BIG";
		case EACCES: return "EACCES";
		case EADDRINUSE: return "EADDRINUSE";
		case EADDRNOTAVAIL: return "EADDRNOTAVAIL";
		case EAFNOSUPPORT: return "EAFNOSUPPORT";
		case EALREADY: return "EALREADY";
		case EBADE: return "EBADE";
		case EBADF: return "EBADF";
		case EBADFD: return "EBADFD";
		case EBADMSG: return "EBADMSG";
		case EBADR: return "EBADR";
		case EBADRQC: return "EBADRQC";
		case EBADSLT: return "EBADSLT";
		case EBUSY: return "EBUSY";
		case ECANCELED: return "ECANCELED";
		case ECHILD: return "ECHILD";
		case ECHRNG: return "ECHRNG";
		case ECOMM: return "ECOMM";
		case ECONNABORTED: return "ECONNABORTED";
		case ECONNREFUSED: return "ECONNREFUSED";
		case ECONNRESET: return "ECONNRESET";
		case EDEADLOCK: return "EDEADLOCK";
		case EDESTADDRREQ: return "EDESTADDRREQ";
		case EDOM: return "EDOM";
		case EDQUOT: return "EDQUOT";
		case EEXIST: return "EEXIST";
		case EFAULT: return "EFAULT";
		case EFBIG: return "EFBIG";
		case EHOSTDOWN: return "EHOSTDOWN";
		case EHOSTUNREACH: return "EHOSTUNREACH";
		case EHWPOISON: return "EHWPOISON";
		case EIDRM: return "EIDRM";
		case EILSEQ: return "EILSEQ";
		case EINPROGRESS: return "EINPROGRESS";
		case EINTR: return "EINTR";
		case EINVAL: return "EINVAL";
		case EIO: return "EIO";
		case EISCONN: return "EISCONN";
		case EISDIR: return "EISDIR";
		case EISNAM: return "EISNAM";
		case EKEYEXPIRED: return "EKEYEXPIRED";
		case EKEYREJECTED: return "EKEYREJECTED";
		case EKEYREVOKED: return "EKEYREVOKED";
		case EL2HLT: return "EL2HLT";
		case EL2NSYNC: return "EL2NSYNC";
		case EL3HLT: return "EL3HLT";
		case EL3RST: return "EL3RST";
		case ELIBACC: return "ELIBACC";
		case ELIBBAD: return "ELIBBAD";
		case ELIBMAX: return "ELIBMAX";
		case ELIBSCN: return "ELIBSCN";
		case ELIBEXEC: return "ELIBEXEC";
		case ELOOP: return "ELOOP";
		case EMEDIUMTYPE: return "EMEDIUMTYPE";
		case EMFILE: return "EMFILE";
		case EMLINK: return "EMLINK";
		case EMSGSIZE: return "EMSGSIZE";
		case EMULTIHOP: return "EMULTIHOP";
		case ENAMETOOLONG: return "ENAMETOOLONG";
		case ENETDOWN: return "ENETDOWN";
		case ENETRESET: return "ENETRESET";
		case ENETUNREACH: return "ENETUNREACH";
		case ENFILE: return "ENFILE";
		case ENOANO: return "ENOANO";
		case ENOBUFS: return "ENOBUFS";
		case ENODATA: return "ENODATA";
		case ENODEV: return "ENODEV";
		case ENOENT: return "ENOENT";
		case ENOEXEC: return "ENOEXEC";
		case ENOKEY: return "ENOKEY";
		case ENOLCK: return "ENOLCK";
		case ENOLINK: return "ENOLINK";
		case ENOMEDIUM: return "ENOMEDIUM";
		case ENOMEM: return "ENOMEM";
		case ENOMSG: return "ENOMSG";
		case ENONET: return "ENONET";
		case ENOPKG: return "ENOPKG";
		case ENOPROTOOPT: return "ENOPROTOOPT";
		case ENOSPC: return "ENOSPC";
		case ENOSR: return "ENOSR";
		case ENOSTR: return "ENOSTR";
		case ENOSYS: return "ENOSYS";
		case ENOTBLK: return "ENOTBLK";
		case ENOTCONN: return "ENOTCONN";
		case ENOTDIR: return "ENOTDIR";
		case ENOTEMPTY: return "ENOTEMPTY";
		case ENOTRECOVERABLE: return "ENOTRECOVERABLE";
		case ENOTSOCK: return "ENOTSOCK";
		case ENOTSUP: return "ENOTSUP";
		case ENOTTY: return "ENOTTY";
		case ENOTUNIQ: return "ENOTUNIQ";
		case ENXIO: return "ENXIO";
		case EOVERFLOW: return "EOVERFLOW";
		case EOWNERDEAD: return "EOWNERDEAD";
		case EPERM: return "EPERM";
		case EPFNOSUPPORT: return "EPFNOSUPPORT";
		case EPIPE: return "EPIPE";
		case EPROTO: return "EPROTO";
		case EPROTONOSUPPORT: return "EPROTONOSUPPORT";
		case EPROTOTYPE: return "EPROTOTYPE";
		case ERANGE: return "ERANGE";
		case EREMCHG: return "EREMCHG";
		case EREMOTE: return "EREMOTE";
		case EREMOTEIO: return "EREMOTEIO";
		case ERESTART: return "ERESTART";
		case ERFKILL: return "ERFKILL";
		case EROFS: return "EROFS";
		case ESHUTDOWN: return "ESHUTDOWN";
		case ESPIPE: return "ESPIPE";
		case ESOCKTNOSUPPORT: return "ESOCKTNOSUPPORT";
		case ESRCH: return "ESRCH";
		case ESTALE: return "ESTALE";
		case ESTRPIPE: return "ESTRPIPE";
		case ETIME: return "ETIME";
		case ETIMEDOUT: return "ETIMEDOUT";
		case ETOOMANYREFS: return "ETOOMANYREFS";
		case ETXTBSY: return "ETXTBSY";
		case EUCLEAN: return "EUCLEAN";
		case EUNATCH: return "EUNATCH";
		case EUSERS: return "EUSERS";
		case EWOULDBLOCK: return "EWOULDBLOCK";
		case EXDEV: return "EXDEV";
		case EXFULL: return "EXFULL";
		default: return to_string(err);
	}
}
#endif
