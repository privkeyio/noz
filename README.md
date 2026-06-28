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
noz key public <seckey>      Derive the hex public key from a hex/nsec secret key
noz key generate             Generate a new keypair (hex sec + pub)
noz event <url> ...          Sign and publish an event
noz req <url> [filters..]    Subscribe and print matching events (to EOSE)
noz count <url> [filters..]  Count matching events (NIP-45)
noz relay <url>              Print the NIP-11 relay info doc
noz sync <src> <dst> [..]    NIP-77 reconcile src's events into dst
noz decode <bech32|hex>      Decode a NIP-19 entity (npub/nsec/note/nevent/naddr/nprofile)
noz verify [event-json]      Verify an event's id and signature (reads stdin if no arg)
```

The secret for `key`/`event` can also come from `NOSTR_SECRET_KEY` instead of
`--sec`/`<seckey>`, so it never lands in your shell history.

## Examples

Every example below is taken from a real run. Outputs are reproduced verbatim,
with a few caveats: `key generate` is random by design; event signatures use
BIP-340 with random auxiliary data, so the `sig` field differs on every run
while the `id` (a hash of the content) stays the same; and the live-query
examples (the latest-note `req` and the author `count`) reflect the relay at
the time of writing and will drift. The read examples run against the public
`wss://relay.damus.io`; the publish and sync examples use a local relay on
`ws://127.0.0.1:7777`, but any relay URL works the same way.

### Derive a public key from a secret key

```shell
~> noz key public 0000000000000000000000000000000000000000000000000000000000000001
79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798
```

It also accepts an `nsec`:

```shell
~> noz key public nsec1vl029mgpspedva04g90vltkh6fvh240zqtv9k0t9af8935ke9laqsnlfe5
7e7e9c42a91bfef19fa929e5fda1b72e0ebc1a4c1141673e2794234d86addf4e
```

### Generate a new keypair

```shell
~> noz key generate
sec  845a798e693bc945a66bd6e137179994c8fb9f5fc20dcbde9631bf84135e7c20
pub  2f11b4631faea2677d8c249a500bf419e46e742c36b3f787e03d1eb8c7c14bec
```

### Sign an event without publishing it

Omit the relay URL and `noz` signs and prints the event, ready to pipe
elsewhere (a NIP-98 auth header, a file, another tool):

```shell
~> noz event --sec 0000000000000000000000000000000000000000000000000000000000000001 \
       -k 1 -c "hello from noz" --ts 1700000000
{"id":"76fedeaa407c7f8024edbe4133d3266766ec516a0fbcfccaafe5b98f60e6620b","pubkey":"79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798","created_at":1700000000,"kind":1,"tags":[],"content":"hello from noz","sig":"..."}
```

Add tags as you go: `-t name=value` for an arbitrary tag, and the shortcuts
`-p <pubkey>`, `-e <id>`, `-d <value>` (all repeatable).

```shell
~> noz event --sec 0000000000000000000000000000000000000000000000000000000000000001 \
       -k 1 -c "gm" -t t=gm -p 79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798 --ts 1700000000
{"id":"8010e0a34369bf469db4d175bcf36d0ac30d26748290e05c91b9dc25bd6afa00","pubkey":"79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798","created_at":1700000000,"kind":1,"tags":[["t","gm"],["p","79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"]],"content":"gm","sig":"..."}
```

The key can also come from the environment:

```shell
~> export NOSTR_SECRET_KEY=0000000000000000000000000000000000000000000000000000000000000001
~> noz event -k 1 -c "signed via env key"
```

### Mine proof-of-work into an event (NIP-13)

`--pow <bits>` grinds a `nonce` tag until the event id has that many leading
zero bits:

```shell
~> noz event --sec 0000000000000000000000000000000000000000000000000000000000000001 \
       -k 1 -c "mined" --pow 8 --ts 1700000000
{"id":"000eaca5686e4fda802d7930e09be1504ce15d0d038fe56a614146c221715851","pubkey":"79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798","created_at":1700000000,"kind":1,"tags":[["nonce","104","8"]],"content":"mined","sig":"..."}
```

### Publish an event to a relay

Pass a relay URL and `noz` connects, publishes, and reports the result. The
publish status (`success` / `rejected`) is written to stderr; the signed event
goes to stdout, so you can capture the event while still seeing the status:

```shell
~> noz event --sec 0000000000000000000000000000000000000000000000000000000000000001 \
       -k 1 -c "hello from noz" -t t=nozdemo ws://127.0.0.1:7777
success
{"id":"7cc42c29310a04d32f8b50c63732efa7ae3e9afa23c8ad56b1cbdc68bdc5727e","pubkey":"79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798","created_at":1782662580,"kind":1,"tags":[["t","nozdemo"]],"content":"hello from noz","sig":"bdb5748b2d472ed0a4a8a038ad59b13902272118939fcfab7056afe971702f3c66e0bfc0854c4f7597d10dec9ea09e2525b9100d5986f88ec48ecc227fc5699f"}
```

For relays that gate writes behind NIP-42, add `--auth` and `noz` will answer
the relay's challenge with a kind-22242 auth event and re-publish.

### Query a relay (NIP-01 REQ)

`req` subscribes, prints each matching event as one JSON object per line, and
exits at EOSE. Filter with `-k <kind>`, `-a <author>`, `-i <id>`, `-l <limit>`,
`-t name=value`, `-p/-e/-d <value>`, `-s <since>`, `-u <until>`, `--search`.

```shell
~> noz req -i 97a79d79ed22d8d4316a4cfd556e69bf4649153b7fa2dd44e7069feea5da7be5 wss://relay.damus.io
{"content":"Unifi is garbage. Just use a normal router made in 2005.","created_at":1782655948,"id":"97a79d79ed22d8d4316a4cfd556e69bf4649153b7fa2dd44e7069feea5da7be5","kind":1,"pubkey":"3bf0c63fcb93463407af97a5e5ee64fa883d107ef9e558472c4eb9aaaefa459d","sig":"3374b36278ec7888c7bc9cf1021fa4f756e67ab68dfab43c641531c6809b232b3185eefcb8c2a614490438b483dee0a6d55b2b306fceef957c9df8a287d69e16","tags":[["e","2be7e4af5a88ecdbfb0781fbb9218e8e9a2862964f8226a4004ac5e1aaa70260","wss://nos.lol","root","32e1827635450ebb3c5a7d12c1f8e7b2b514439ac10a67eef3d9fd9c5c68e245"],["e","00008ee61e6a163823e46149f88005e43609a59c765f319c2fc9b33754498856","wss://relay.primal.net/","reply","e2ccf7cf20403f3f2a4a55b328f0de3be38558a7d5f33632fdaaefc726c1c8eb"],["p","32e1827635450ebb3c5a7d12c1f8e7b2b514439ac10a67eef3d9fd9c5c68e245"],["p","e2ccf7cf20403f3f2a4a55b328f0de3be38558a7d5f33632fdaaefc726c1c8eb"]]}
```

One line of JSON per event means it composes with `jq`. Pull the latest note
from an author and print just its text:

```shell
~> noz req -k 1 -l 1 -a 3bf0c63fcb93463407af97a5e5ee64fa883d107ef9e558472c4eb9aaaefa459d \
       wss://relay.damus.io | jq -r .content
Unifi is garbage. Just use a normal router made in 2005.
```

### Count matching events (NIP-45)

`count` takes the same filters as `req` and prints just the number:

```shell
~> noz count -k 1 -a 3bf0c63fcb93463407af97a5e5ee64fa883d107ef9e558472c4eb9aaaefa459d wss://relay.damus.io
76
```

### Fetch an event and verify it end to end

```shell
~> noz req -i 97a79d79ed22d8d4316a4cfd556e69bf4649153b7fa2dd44e7069feea5da7be5 wss://relay.damus.io | noz verify
valid
```

`verify` recomputes the id and checks the Schnorr signature. It reads the event
from an argument or stdin, prints `valid`/`invalid: ...`, and exits non-zero on
any failure, so it drops straight into scripts:

```shell
~> noz verify '{"id":"76fedeaa407c7f8024edbe4133d3266766ec516a0fbcfccaafe5b98f60e6620b","pubkey":"79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798","created_at":1700000000,"kind":1,"tags":[],"content":"hello from noz","sig":"ae3b5ad8406d71be7994717cc16aae90b8dcae49c1d0325a12839c6a8382433009235a4256f85de346797c0a50dc9bbcd51db83baf316e79cc07e1179e58e1a2"}'
valid
```

Tamper with a single byte of content and the recomputed id no longer matches:

```shell
~> noz verify '{"id":"76fedeaa407c7f8024edbe4133d3266766ec516a0fbcfccaafe5b98f60e6620b","pubkey":"79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798","created_at":1700000000,"kind":1,"tags":[],"content":"HELLO from noz","sig":"ae3b5ad8406d71be7994717cc16aae90b8dcae49c1d0325a12839c6a8382433009235a4256f85de346797c0a50dc9bbcd51db83baf316e79cc07e1179e58e1a2"}'
invalid: id does not match content
```

### Read a relay's NIP-11 information document

```shell
~> noz relay wss://relay.damus.io
{"contact":"jb55@jb55.com","description":"Damus strfry relay","icon":"https://damus.io/img/logo.png","limitation":{"max_limit":500,"max_message_length":1000000,"max_subscriptions":200},"name":"damus.io","negentropy":1,"pubkey":"32e1827635450ebb3c5a7d12c1f8e7b2b514439ac10a67eef3d9fd9c5c68e245","software":"git+https://github.com/hoytech/strfry.git","supported_nips":[1,2,4,9,11,28,40,45,70,77],"version":"1.1.0-1-g691a533f11eb"}
```

Pipe it through `jq` for just the parts you care about:

```shell
~> noz relay wss://relay.damus.io | jq -c '{name, software, supported_nips}'
{"name":"damus.io","software":"git+https://github.com/hoytech/strfry.git","supported_nips":[1,2,4,9,11,28,40,45,70,77]}
```

### Reconcile events from one relay into another (NIP-77)

`sync` runs a negentropy reconciliation: it figures out which of `src`'s events
(matching your filter) are missing from `dst` and copies them over, then prints
how many it moved.

```shell
~> noz sync ws://127.0.0.1:7777 ws://127.0.0.1:7778 -t t=nozdemo
synced 1 events
```

With no filter it syncs the whole relay (and tells you so):

```shell
~> noz sync ws://127.0.0.1:7777 ws://127.0.0.1:7778
syncing full relay (no filter)
synced 5 events
```

### Decode NIP-19 entities

`decode` unpacks any `npub`/`nsec`/`note`/`nprofile`/`nevent`/`naddr` (or a bare
hex pubkey) into its underlying fields:

```shell
~> noz decode npub10elfcs4fr0l0r8af98jlmgdh9c8tcxjvz9qkw038js35mp4dma8qzvjptg
pubkey  7e7e9c42a91bfef19fa929e5fda1b72e0ebc1a4c1141673e2794234d86addf4e

~> noz decode note1fntxtkcy9pjwucqwa9mddn7v03wwwsu9j330jj350nvhpky2tuaspk6nqc
id      4cd665db042864ee600ee976d6cfcc7c5ce743859462f94a347cd970d88a5f3b

~> noz decode nsec1vl029mgpspedva04g90vltkh6fvh240zqtv9k0t9af8935ke9laqsnlfe5
seckey  67dea2ed018072d675f5415ecfaed7d2597555e202d85b3d65ea4e58d2d92ffa
```

Entities with extra fields (relays, kind, identifier) print all of them:

```shell
~> noz decode nprofile1qqsrhuxx8l9ex335q7he0f09aej04zpazpl0ne2cgukyawd24mayt8gpp4mhxue69uhhytnc9e3k7mgpz4mhxue69uhkg6nzv9ejuumpv34kytnrdaksjlyr9p
pubkey  3bf0c63fcb93463407af97a5e5ee64fa883d107ef9e558472c4eb9aaaefa459d
relay   wss://r.x.com
relay   wss://djbas.sadkb.com

~> noz decode naddr1qqrx67tnd36kwqg5waehxw309aex2mrp0yhxgctdw4eju6t0qgs8ul5ug253hlh3n75jne0a5xmjur4urfxpzst88cnegg6ds6ka7nsrqsqqqa28hnnte3
kind    30023
pubkey  7e7e9c42a91bfef19fa929e5fda1b72e0ebc1a4c1141673e2794234d86addf4e
ident   myslug
relay   wss://relay.damus.io
```

## License

MIT. See [LICENSE](LICENSE).
