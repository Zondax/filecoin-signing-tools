package main

// #cgo LDFLAGS: -L${SRCDIR} -lfilecoin_signer_ffi
// #include "filecoin_signer_ffi.h"
import "C"
import (
	"fmt"
	"os"
)

func main() {
	error := C.filecoin_signer_error_new();
	extended_key := C.filecoin_signer_key_derive(
		C.CString("equip will roof matter pink blind book anxiety banner elbow sun young"),
		C.CString("m/44'/461'/0/0/0"),
		error,
	);

	if C.filecoin_signer_error_code(error) != 0 {
		err := C.filecoin_signer_error_message(error);
		fmt.Fprintln(os.Stderr, C.GoString(err))
	} else {
		private_key := C.filecoin_signer_extended_key_private_key(extended_key);
		if C.GoString(private_key) != "f15716d3b003b304b8055d9cc62e6b9c869d56cc930c3858d4d7c31f5f53f14a" {
			panic("Bad key");
		}
		C.filecoin_signer_string_free(private_key);
	}

	C.filecoin_signer_extended_key_free(extended_key);
	C.filecoin_signer_error_free(error);
}