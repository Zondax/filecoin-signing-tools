package ch.zondax;

public class FilecoinSigner {
    public static native long errorNew();
    public static native void errorFree(long ptr);

    public static native long keyDerive(String mnemonic, String path, long ptr);
    public static native void keyDeriveFree(long ptr);

    static {
        System.loadLibrary("filecoin_signer_ffi");
    }
}