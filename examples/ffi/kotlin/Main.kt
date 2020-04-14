import ch.zondax.FilecoinSigner;

fun main() {
    var error = FilecoinSigner.errorNew()
    var extendedKey = FilecoinSigner.keyDerive(
        "equip will roof matter pink blind book anxiety banner elbow sun young",
        "m/44'/461'/0/0/0",
        "",
        error
    )

    if (FilecoinSigner.errorCode(error) != 0L) {
        System.err.println(FilecoinSigner.errorMessage(error))
    }
    else {
        val privateKey = FilecoinSigner.extendedKeyPrivateKey(extendedKey);
        assert(privateKey == "f15716d3b003b304b8055d9cc62e6b9c869d56cc930c3858d4d7c31f5f53f14a")
    }

    FilecoinSigner.extendedKeyFree(extendedKey)
    FilecoinSigner.errorFree(error)
}
