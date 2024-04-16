# Lightning Client

A Rust implementation of the [Lightning Network Protocol][0].

_The Lightning Network is a second layer for Bitcoin (BTC) that uses micropayment channels to scale the blockchain’s capability and handle transactions more efficiently and more cheaply. It is a technological solution designed to solve glitches associated with Bitcoin by introducing off-chain transactions. Its channel is a transaction mechanism between two parties, in which each can make or receive payments from the other._

> ⚠️ This is a personal project I'm doing to learn more about the Lightning Network. It is not meant to be used on real nodes. I will add new features over time. The ultimate goal is to implement all BOLTs.

The implementation currently supports the client version of the [BOLT-8][1] encrypted and authenticated transport protocol, which performs the handshake with a public remote node.

_Note: BOLT stands for Basis of Lightning Technology._

## System requirements

- [Rust][4] _(at least v1.77.2)_

## Testing the handshake

To test the handshake implementation, an address to a public Lightning node is required. A list of public addresses can be found at: https://1ml.com/

A correct format of a node address is:

```text
<NODE_PUBLIC_KEY>@<NODE_IP>:<NODE_PORT>
```

An example of a _currently_ available public node address is:

```text
03864ef025fde8fb587d989186ce6a4a186895ee44a926bfc370e2c366597a3f8f@3.33.236.230:9735
```

The next step is to execute the code:

```sh
$ cargo run -- --node-address 03864ef025fde8fb587d989186ce6a4a186895ee44a926bfc370e2c366597a3f8f@3.33.236.230:9735
```

The expected output of a successful handshake is similar to the following:

```text
Handshake completed!

Successfully read and decrypted the init message from the remote node!

Decrypted message (hex): 001000000006a088288a698101206fe28c0ab6f1b372c1a6a246ae63f74f931e8365e15a089c68d6190000000000
```

**Please note that message decoding according to the custom [format][5] used by the Lighting Network protocol is not yet implemented.**

To confirm that the `init` message has been received, decrypted and is correct, refer to [BOLT-1][2]. The easiest way is to check the first two bytes. The value should be `16` _(BE, dec)_, which is the type of the `init` message.


## Unit tests

There are unit tests that attempt to check each step of the handshake based on the [test vectors][3] provided by the BOLT-8.

To run the tests, the following command should be executed:

```sh
$ cargo test --all-features --all-targets
```

[0]: https://github.com/lightning/bolts/blob/master/00-introduction.md
[1]: https://github.com/lightning/bolts/blob/master/08-transport.md
[2]: https://github.com/lightning/bolts/blob/master/01-messaging.md#the-init-message
[3]: https://github.com/lightning/bolts/blob/master/08-transport.md#appendix-a-transport-test-vectors
[4]: https://www.rust-lang.org/
[5]: https://github.com/lightning/bolts/blob/master/01-messaging.md