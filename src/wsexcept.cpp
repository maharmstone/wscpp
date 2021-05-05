#ifdef _WIN32
#include <winsock2.h>
#include <ws2ipdef.h>
#endif
#include "wscpp.h"
#include "wsexcept.h"

using namespace std;

namespace ws {
#ifdef _WIN32
    sockets_error::sockets_error(const char* func) : err(WSAGetLastError()), msg(string(func) + " failed (error " + to_string(err) + ")") {
#else
    sockets_error::sockets_error(const char* func) : err(errno), msg(string(func) + " failed (error " + errno_to_string(err) + ")") {
#endif
    }
}

#ifndef _WIN32
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
