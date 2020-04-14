#import <Foundation/Foundation.h>

#include "filecoin_signer_ffi.h"

int main(int argc, char *argv[]) {
    NSAutoreleasePool *pool = [[NSAutoreleasePool alloc] init];

    ExternError *error = filecoin_signer_error_new();
    ExtendedKey *extended_key = filecoin_signer_key_derive(
        "equip will roof matter pink blind book anxiety banner elbow sun young",
        "m/44'/461'/0/0/0",
        "",
        error
    );

    if (filecoin_signer_error_code(error) != 0) {
        fprintf(stderr, "%s\n", filecoin_signer_error_message(error));
    }
    else {
        char *private_key = filecoin_signer_extended_key_private_key(extended_key);
        assert([[NSString stringWithUTF8String:private_key] isEqualToString:@"f15716d3b003b304b8055d9cc62e6b9c869d56cc930c3858d4d7c31f5f53f14a"]);
        filecoin_signer_string_free(private_key);
    }

    filecoin_signer_extended_key_free(extended_key);
    filecoin_signer_error_free(error);

    [pool drain];
    return 0;
}
