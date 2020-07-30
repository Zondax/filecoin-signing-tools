# Temporary Fork of Zondax's Filecoin Signing Tools

This repo is a fork of [Zondax's filecoin-signing-tools](https://github.com/Zondax/filecoin-signing-tools), a Js + Rust WASM library for generating and signing messages for submission to the Filecoin virtual machine.

The purpose of this repo is to extend the original library to carry out Filecoin Payment Channel (PCH) operations on chain, such as creating a new payment channel, settling it, creating and redeeming vouchers within a channel, and so forth.  Once these extensions are developed, they will be made available either as an add-on crate that runs atop Zondax's [filecoin-signing-tools](https://github.com/Zondax/filecoin-signing-tools) or as a series of PRs against [filecoin-signing-tools](https://github.com/Zondax/filecoin-signing-tools) to bring this PCH functionality directly into the [filecoin-signing-tools](https://github.com/Zondax/filecoin-signing-tools) library.

## Development Status of Payment Channel (PCH) Extensions

> Legend: :green_apple: Done &nbsp; :lemon: In Progress &nbsp; :tomato: Not started

| **Payment Channels (PCH)**                   | Status        | Comment                           |
| -------------------------------------------- | :-----------: | :-------------------------------: | 
| Create PCH                                   | :green_apple: |                                   | 
| Update PCH State                             | :tomato:      |                                   | 
| Settle PCH                                   | :tomato:      |                                   | 
| Collect PCH                                  | :tomato:      |                                   | 

| **Payment Vouchers**                         | Status        | Comment                           |
| -------------------------------------------- | :-----------: | :-------------------------------: | 
| Create Voucher                               | :tomato:      |                                   | 
| Verify Voucher                               | :tomato:      |                                   | 
| Add Voucher to PCH                           | :tomato:      |                                   | 
| Submit Best-spendable Voucher                | :tomato:      |                                   | 

## Why?

By developing PCH functionality in Rust, retrieval client developers can develop primarily off-chain retrieval protocols, while still producing enough on-chain artifacts to make the retrieval transactions verifiable.

## How Are Payment Channels (PCH) Used in Filecoin

PCH's provide a mechanism for a buyer of data to receive a small portion of the data (say, 1MB) then make a small payment, then receive another small portion, and so on.  In this manner, if either side fails to fully fulfill its obligation -- either to provide all the data, or provide vouchers summing up to the total price -- both will walk away having been fairly compensated for what they did provide.

![pch diagram](https://github.com/mgoelzer/wasm_filecoin/blob/master/pch-diagram.png)

In the normal case:

1.  Payer (green) creates the payment channel (PCH).

2.  Payer (green) then creates a voucher and passes it to the payee (blue)

3.  Payee (blue) checks it and adds it to the list of vouchers for the lane being used.

4.  The cycle can continue as many times as necessary.  At some point, payer (green) calls Settle.

5-6.  Payee (blue) now has ~12 hours to Submit its best voucher before the channel can be Collected.

The above diagram illustrates the general PCH concept under "normal" retrieval circumstances.  For a complete description of the retrieval client and provider state machines, see [go-fil-markets/retrievalmarket](https://github.com/filecoin-project/go-fil-markets/tree/master/retrievalmarket).

## Compile and Run

A companion repo, [wasm_filecoin](https://github.com/mgoelzer/wasm_filecoin) is developed in parallel that demonstrates use of these Rust PCH exntesions in a browser-based JS application.  Compile and build instructions can be found [over there](https://github.com/mgoelzer/wasm_filecoin).

## Contributing

Contributions are welcome.  Check out the [issues](/issues) for a start.

## License

Licensed under [Apache 2.0](https://github.com/filecoin-project/lotus/blob/master/LICENSE-APACHE) per the Zondax library from which this forked.

## Why the fork?

It is not our intention to maintain a permenant or long-term fork of [filecoin-signing-tools](https://github.com/Zondax/filecoin-signing-tools).  This fork gives our team the ability to focus only on PCH extensions while development continues in the core [filecoin-signing-tools](https://github.com/Zondax/filecoin-signing-tools).  Eventually all work here will either be merged back into [filecoin-signing-tools](https://github.com/Zondax/filecoin-signing-tools), or isolated into a separate crate that runs on top of [filecoin-signing-tools](https://github.com/Zondax/filecoin-signing-tools).