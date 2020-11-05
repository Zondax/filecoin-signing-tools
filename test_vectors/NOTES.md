# Tests vectors

* Each test should be independent and not rely on value in other file
* Have a "description" field in each test explaining the context
* One function; One file ?
* Test vectors are interesting if we have the expected value. If not just get the value in the file itself... (example when we are testing using another known robust module)
* Make human friendly! (We don't have the value directly in the file so field name should be explicit)
* If an error is expected add it to the file under field "error"
* Split into smaller files !

Why test vector file ? Test vector concentrate in one place a test and make it easier to modify/update.