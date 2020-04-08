# Kotlin bindings

Uses the same bindings provided by the Java JNI.

# Running 

Assuming that the library, the header and the package are in the same directory.

```bash
kotlinc -cp . Main.kt -include-runtime -d .
kotlin -Djava.library.path="." -J-ea MainKt
```
