# Java bindingds

The API is, unfortunately, too "C-ish" due to FFI.

To use this example, download the `ch.zondax.FilecoinSigner` package and build. Alternatively, choose a build automation system.

# Example 

Assuming that the library, the header and the package are in the same directory.

```bash
javac -cp . Main.java
java -Djava.library.path="." -ea Main
```
