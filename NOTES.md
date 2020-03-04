# NOTES

## Node version
Need latest version of node 13.7.0. Others version wont allow the `--experimental-wasm-modules` flag to import wasm.


## Possible Workflow

USER WANT TO SELL FILECOINS

    /-----------/           /--------------/        /---------/
    /   USER    /           /   EXCHANGE   /        /  NODE   /
    /-----------/           /--------------/        /---------/
          |                        |                     |
          |------Sell Request----->|                     |
          |                        | key_derive()        |
          |<-----Address-----------|                     |
          |                        |                     |
          |------------------Send Transaction----------->|
          |                        |                     |
          |                        |<-----Notify---------|
          |                        |                     |
          |<------Success----------|                     |


USER WANT TO BUY FILECOINS

    /-----------/           /--------------/        /---------/
    /   USER    /           /   EXCHANGE   /        /  NODE   /
    /-----------/           /--------------/        /---------/
          |                        |                     |
          |------Buy (address)---->|                     |
          |                        | key_derive()        |
          |                        | tx_create()         |
          |                        | sign_transaction()  |
          |                        |                     |
          |                        |-----Sentd Tx ------>|
          |                        |                     |
          |                        |                     |
          |                        |<-----Notify---------|
          |                        |                     |
          |<------Success----------|                     |
