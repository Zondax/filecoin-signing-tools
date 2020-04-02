import ch.zondax.FilecoinSigner;

class Main {
    public static void main(String[] args) {
        FilecoinSigner filecoinSigner = new FilecoinSigner();
        long error = filecoinSigner.errorNew();
        String mnemonic = "equip will roof matter pink blind book anxiety banner elbow sun young";
        String path =  "m/44'/461'/0/0/0";
        long key_derive = filecoinSigner.keyDerive(mnemonic, path, error);
        filecoinSigner.keyDeriveFree(key_derive);
        filecoinSigner.errorFree(error);
    }
}