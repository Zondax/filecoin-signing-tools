package ch.zondax;

public class FilecoinSigner {
    public static native long errorNew();
    public static native int errorCode(long ptr);
    public static native String errorMessage(long ptr);
    public static native void errorFree(long ptr);

    public static native String extendedKeyPrivateKey(long ptr, long err);
    public static native String extendedKeyPublicKey(long ptr, long err);
    public static native void extendedKeyFree(long ptr);

    public static native long keyDerive(String mnemonic, String path, String password, long err);

    static {
        System.loadLibrary("filecoin_signer_ffi");
    }
}
