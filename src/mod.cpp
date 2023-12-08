export module wscpp;

#define WSCPP __attribute__ ((visibility ("default")))

namespace ws {
	export int WSCPP foo() {
		return 42;
	}
};
