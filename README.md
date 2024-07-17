# Ethereum handshaker

This program connects to chosen Ethereum node and does the P2P (without Eth wire handshake) handshake process with it.

[RLPx documentation](https://github.com/ethereum/devp2p/blob/master/rlpx.md)

## How to use

Just pass enode strings as arguments
```cargo run -- <enode> [<enode>...]```

example:
```cargo run -- enode://a576b91dab724c9a845133ff10c1aa01adc2a71a97a63643a6a45ec66a00f383ae55130f2077d55348f8695caa49e4ff6d2bafd91ecc5f31480cc472db61d5ca@20.185.187.186:30303```


### Expected output
```
$ cargo run -- enode://37f31b1b98e4ee338dc4716e54bd0ab049e62446aa88ebbbdb9adea11a56817a7837fe8ad03f72d5016f8de223d4a9e144a486581a7d58810a657d966e9144ed@127.0.0.1:30303 
   Compiling ethereum-handshaker v0.1.0 (/home/muttley/git/ethereum-handshaker)
    Finished `dev` profile [unoptimized + debuginfo] target(s) in 0.34s
     Running `target/debug/ethereum-handshaker 'enode://37f31b1b98e4ee338dc4716e54bd0ab049e62446aa88ebbbdb9adea11a56817a7837fe8ad03f72d5016f8de223d4a9e144a486581a7d58810a657d966e9144ed@127.0.0.1:30303'`
Handshake completed, displaying recipient info:
----
NodeInfo {
    protocol_version: 5,
    client_id: "besu/v24.6.0/linux-x86_64/openjdk-java-22",
    capabilities: [
        NodeCapability {
            name: "eth",
            version: 63,
        },
        NodeCapability {
            name: "eth",
            version: 64,
        },
        NodeCapability {
            name: "eth",
            version: 65,
        },
        NodeCapability {
            name: "eth",
            version: 66,
        },
        NodeCapability {
            name: "eth",
            version: 67,
        },
        NodeCapability {
            name: "eth",
            version: 68,
        },
        NodeCapability {
            name: "snap",
            version: 1,
        },
    ],
    peer_id: 0x37f31b1b98e4ee338dc4716e54bd0ab049e62446aa88ebbbdb9adea11a56817a7837fe8ad03f72d5016f8de223d4a9e144a486581a7d58810a657d966e9144ed,
}
----

```

## How to verify it works

Simply by running it against some existing node. Program should print information about remote node - all information from [Hello](https://github.com/ethereum/devp2p/blob/master/rlpx.md#hello-0x00) message will be printed.

## Areas to improve

- More tests
- Some nodes fail with ingress_mac header signature mismatch
- Generic template for zeroized array types
