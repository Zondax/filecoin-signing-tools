#include "filecoin_signer_ffi.h"

int main(int argc, char *argv[]) {
    ExternError *error = filecoin_signer_error_new();
    char mnemonic[] = "equip will roof matter pink blind book anxiety banner elbow sun young";
    char path[] =  "m/44'/461'/0/0/0";
    ExtendedKey *key_derive = filecoin_signer_key_derive(mnemonic, path, error);
    filecoin_signer_key_derive_free(key_derive);
    filecoin_signer_error_free(error);
}