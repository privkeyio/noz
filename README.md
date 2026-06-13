# noz

**N**ostr **O**n **Z**ig, a small, fast Nostr command-line tool built on
[libnostr-z](https://github.com/privkeyio/libnostr-z).

A focused tool for the things you actually script: signing and publishing
events, querying relays, counting, reading relay info, and syncing.

## Build

Requires Zig 0.16 and `libssl`/`libsecp256k1` (pulled in transitively by
libnostr-z).

```sh
zig build -Doptimize=ReleaseFast
./zig-out/bin/noz key public <seckey>
```

## Commands

```
noz key public <seckey>   Derive the hex public key from a hex/nsec secret key
noz key generate          Generate a new keypair (hex sec + pub)
noz event <url> ...        sign and publish an event        (in progress)
noz req <url> ...          subscribe and print matching events (in progress)
noz count <url> ...        count matching events            (in progress)
noz relay <url>            print the NIP-11 relay info doc   (in progress)
noz sync <src> <dst> ...   NIP-77 reconcile src into dst     (in progress)
```

## License

MIT. See [LICENSE](LICENSE).
