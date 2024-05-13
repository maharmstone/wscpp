export module wscpp;

#ifdef _WIN32
#define WSCPP __declspec(dllexport)
#else
#define WSCPP __attribute__ ((visibility ("default")))
#endif

namespace ws {
	export int WSCPP foo() {
		return 42;
	}
};
