#include <assert.h>
#include <stdio.h>
#include <string.h>

#include "filecoin_signer_ffi.h"

void free_resources(ExtendedKey *extended_key, ExternError *error) {
    filecoin_signer_extended_key_free(extended_key);
    filecoin_signer_error_free(error);
}

void manage_error(ExtendedKey *extended_key, ExternError *error) {
    if (filecoin_signer_error_code(error) == 0) {
        return;
    }
    fprintf(stderr, "%s\n", filecoin_signer_error_message(error));
    free_resources(extended_key, error);
    exit(EXIT_FAILURE);
}

int main(int argc, char *argv[]) {
    ExternError *error = filecoin_signer_error_new();
    ExtendedKey *extended_key = filecoin_signer_key_derive(
        "equip will roof matter pink blind book anxiety banner elbow sun young",
        "m/44'/461'/0/0/0",
        "",
        "en",
        error
    );
    manage_error(extended_key, error);
    char *private_key = filecoin_signer_extended_key_private_key(extended_key, error);
    manage_error(extended_key, error);
    assert(strcmp(private_key, "f15716d3b003b304b8055d9cc62e6b9c869d56cc930c3858d4d7c31f5f53f14a") == 0);
    filecoin_signer_string_free(private_key);
    free_resources(extended_key, error);
}