package ch.zondax;

public class FilecoinSigner {
    public static native long errorNew();
    public static native long errorCode(long ptr);
    public static native String errorMessage(long ptr);
    public static native void errorFree(long ptr);

    public static native String extendedKeyPrivateKey(long ptr);
    public static native String extendedKeyPublicKey(long ptr);
    public static native String extendedKeyPublicKeyCompressed(long ptr);
    public static native void extendedKeyFree(long ptr);

    public static native long keyDerive(String mnemonic, String path, String password, long ptr);

    static {
        System.loadLibrary("filecoin_signer_ffi");
    }
}
