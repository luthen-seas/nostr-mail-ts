# Test Fixtures

## `nip44.vectors.json`

Official NIP-44 test vectors, sourced from
<https://github.com/paulmillr/nip44/blob/main/nip44.vectors.json>.

**SHA256**: `269ed0f69e4c192512cc779e78c555090cebc7c785b609e338a62afc3ce25040`
(matches the canonical checksum published in [NIP-44](https://github.com/nostr-protocol/nips/blob/master/44.md)).

These vectors are bundled here so the conformance test (`test/nip44-compat.test.ts`)
runs hermetically without network access. To refresh:

```sh
curl -fsSL -o test/fixtures/nip44.vectors.json https://raw.githubusercontent.com/paulmillr/nip44/main/nip44.vectors.json
shasum -a 256 test/fixtures/nip44.vectors.json
# verify against the SHA256 published in NIP-44
```
