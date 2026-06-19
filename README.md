# noz

**N**ostr **O**n **Z**ig, a small, fast Nostr command-line tool built on
[libnostr-z](https://github.com/privkeyio/libnostr-z).

A focused tool for the things you actually script: signing and publishing
events, querying relays, counting, reading relay info, syncing, decoding
NIP-19 entities, and verifying events.

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
noz event <url> ...        sign and publish an event
noz req <url> ...          subscribe and print matching events (to EOSE)
noz count <url> ...        count matching events (NIP-45)
noz relay <url>            print the NIP-11 relay info doc
noz sync <src> <dst> ...   NIP-77 reconcile src's events into dst
noz decode <bech32|hex>    decode a NIP-19 entity (npub/nsec/note/nevent/naddr/nprofile)
noz verify [event-json]    verify an event's id and signature (reads stdin if no arg)
```

## License

MIT. See [LICENSE](LICENSE).
