public class Filecoin {
    public static native long filecoin_error_new();
    public static native long filecoin_error_free(long ptr);

    public static native long filecoin_key_derive(String mnemonic, String path);
    public static native void filecoin_key_derive_free(long ptr);

    static {
        System.loadLibrary("filecoin");
    }
}