# GoMesh: Comprehensive Project Documentation

`GoMesh` is a secure messaging application supporting end-to-end encrypted (E2EE) private
chats, group messaging, and file transfers over a custom TCP protocol.

This document describes every mechanism, byte pattern, and component as they exist in the
code today.

---

## Implementation status

The messaging layer was rewritten to a Signal-inspired design. Both flows below are
implemented, tested, and working end to end.

| Area | Status | Notes |
| :--- | :--- | :--- |
| Direct chats | **Working** | Zero round trips. Both peers derive the session from identity keys alone; the recipient is never notified in advance and reconstructs everything from the first ciphertext. |
| Group chats | **Working** | Sender keys. Every member ratchets their own chain; no shared key, no admin role in the crypto. |
| Membership changes | **Working** | Any add or removal rekeys the whole group. |
| Out-of-order / dropped messages | **Working** | Skipped-key tracking up to 2000 ahead; one previous key generation retained per group sender. |
| Deferred delivery | **Working** | Messages whose key has not arrived yet are held and replayed, not dropped. |
| Media transfer | **Working** | Unchanged by the rewrite. Encrypted blobs go directly to Supabase; only a metadata envelope is relayed. |
| Group admin controls | **Working** | Server-enforced. Admin is now purely a membership role and has no part in key distribution. |
| Session persistence | **Not implemented** | Sessions live in memory only. See *Known limitations*. |
| Forward secrecy (direct) | **Not implemented** | Deliberate simplification. See *Known limitations*. |
| Key verification (safety numbers) | **Not implemented** | The server is trusted for key distribution. |

### Tests

69 tests across the three modules, including 9 fuzz targets and 4 end-to-end tests that
run the real server binary and drive the real client code over a socket.

```bash
cd common && go test ./...      # protocol codecs, ID ordering
cd client && go test ./...      # sessions, group chains, pending queue, end-to-end
cd server && go test ./...      # routing, membership authorization

# Fuzz the decoders that parse untrusted bytes
cd common && go test -run '^$' -fuzz='^FuzzDecodeConvInfo$' -fuzztime=60s
```

> **Note:** `.gitignore` currently contains `*_test.go`, so none of the test files are
> tracked by git. Remove that line if you want them committed.

### Known limitations

These are deliberate, not oversights.

- **No forward secrecy on direct chats.** The session root is `X25519(own_identity_private,
  peer_identity_public)` — a fixed function of the two identity keys, with no ephemeral
  input. Anyone who later obtains an identity private key can recompute the root and read
  every message that pair ever exchanged.
- **No session persistence, which interacts badly with the above.** Because the root never
  changes and chains are held only in memory, restarting a client and reopening a chat
  restarts the send chain from the same root and reissues message keys that were already
  used. Repeating a key with a repeated nonce on XChaCha20-Poly1305 leaks the XOR of the
  two plaintexts. Fixing either half (persisting chain state, or mixing an ephemeral into
  the root) removes this.
- **The server is trusted for key distribution.** It hands out identity keys, so a
  malicious server can substitute its own and sit in the middle. Signal answers this with
  safety numbers verified out of band; nothing here does.
- **Group membership is server-authoritative.** Clients trust the member list in the
  broadcast, so a malicious server could add a silent member.

---

## How to run

The repository is a Go workspace. From the root:

```bash
go work init                             # only if go.work is missing
go work use ./client ./common ./server
```

Then run the server and one or more clients in separate terminals:

```bash
# Media send/receive uploads encrypted blobs to a Supabase Storage bucket, so the
# server needs these three variables to mint signed upload/download URLs.
# (Create a private bucket in your Supabase project and copy the service_role key.)
export SUPABASE_URL="https://<your-project>.supabase.co"
export SUPABASE_SERVICE_KEY="<service_role secret key>"
export SUPABASE_BUCKET="gomesh-media"

export LISTEN_ADDR=":8080"   # optional, this is the default

cd server && go run .
```

> If the Supabase variables are unset the server still runs, but logs `Media storage
> DISABLED` and `/file` sends are rejected. Text and group messaging are unaffected.

```bash
cd client && go run .
```

### Client commands

| Command | Effect |
| :--- | :--- |
| `/dm <username>` | Open a private chat |
| `/group <name> <user1,user2>` | Create a group |
| `/chat <number>` | Switch the active conversation |
| `/list` | List conversations |
| `/add`, `/remove` `<username>` | Add or remove a group member (admin) |
| `/admin`, `/remove_admin` `<username>` | Grant or revoke admin |
| `/leave` | Leave the current group |
| `/file <path>` | Send a file |

---

## 1. Cryptography Architecture & E2EE Model (`common/crypto_utils.go`)

The governing principle is that **the server must never be able to read message contents
or file data**. Everything sensitive is encrypted on the sender's device and decrypted
only on the recipients'.

### 1.1 Core Algorithms

- **X25519 (ECDH)**: Elliptic-curve Diffie-Hellman over Curve25519, computed between the
  two parties' long-term identity keys to establish a direct session.
- **XChaCha20-Poly1305 (AEAD)**: Authenticated encryption with a 24-byte extended nonce.
  Encrypts every message body, and separately encrypts media blobs with a fresh random
  32-byte key per file before upload.
- **HMAC-SHA256**: Drives the symmetric ratchet that produces per-message keys.
- **SHA-256**: The conversation ID for a direct chat is derived from the two user IDs, and
  media integrity is verified by hashing the plaintext.
- **HKDF-SHA256**: Available in `DeriveSessionKey`, used by the media path.

### 1.2 Key Types

- **Identity keys**: Long-term X25519 pairs generated on the client (`identity.go`) and
  stored in `identity.key`. The private half never leaves the device; the public half is
  registered with the server at login and handed to peers through it.
- **Ratchet chain keys (direct)**: Each direct session holds one send chain and one
  receive chain, mirrored between the two peers. `RatchetStep` derives a message key and
  the next chain key from the current one.
- **Sender chain keys (group)**: Each member holds one sending chain per group, plus one
  receiving chain per other member. There is no shared group key.

There are **no ephemeral keys**. Direct sessions are derived from identity keys alone,
which is what removes the round trip — and what costs the forward secrecy noted above.

### 1.3 Mechanisms

**Key clamping.** The X25519 private key is clamped per RFC 7748 in `generateKeyPair()`
(`private[0] &= 248`, `private[31] &= 127`, `private[31] |= 64`) to mitigate
small-subgroup attacks.

**Ratchet step.** `HMAC(ChainKey, 0x01)` produces the message key for the current payload;
`HMAC(ChainKey, 0x02)` produces the next chain key. One-way, so a stolen chain key reveals
nothing about earlier messages.

**Role assignment without coordination.** Since neither peer sends a handshake, they cannot
learn from each other which end of the derived root to send on. Instead `DeriveRatchetRoots`
splits the shared secret into `rootA` / `rootB`, and `LowerID` compares the two user IDs
lexicographically: the lower ID sends on `rootA`, the higher on `rootB`. Both machines
reach the same answer alone, and the chains mirror. If both sides picked the same half,
each would encrypt on the chain the other was also encrypting on and nothing would decrypt
in either direction.

**Conversation IDs.** `HashIDs(a, b)` sorts the two user IDs and returns the first 16 bytes
of `SHA-256(lower ‖ higher)`, so both peers compute the same ID independently. It is a
hash, so the peer cannot be recovered from it — sessions store `PeerID` explicitly.

---

## 2. Network Protocol & Byte Patterns (`common/protocol.go`)

### 2.1 Fixed Header

Every packet starts with a 55-byte header, big-endian. The server uses it exclusively for
routing and is oblivious to the payload.

| Field | Size | Description |
| :--- | :--- | :--- |
| **MessageID** | 16 | Unique ID for the message. |
| **ConversationID** | 16 | The group or private chat this belongs to. |
| **SenderID** | 16 | The sender's user ID. **Stamped by the server**, so a client cannot spoof it. |
| **MsgType** | 1 | Packet type. |
| **Flags** | 2 | Bitmask. Only `FlagEncrypted (1 << 0)` is defined. |
| **BodyLen** | 4 | uint32 size of the payload that follows. |

The whole header is fed to the AEAD as associated data, so tampering with any field — the
sender ID included — fails the tag check rather than taking effect.

### 2.2 Message Bodies

**Direct message** (`MsgText`, `MsgMediaMeta` in a 1-to-1 conversation):

```
[SeqNum uint32 (4)] [Nonce (24)] [Ciphertext + Poly1305 tag]
```

**Group message**:

```
[Epoch uint32 (4)] [SeqNum uint32 (4)] [Nonce (24)] [Ciphertext + Poly1305 tag]
```

Both counters travel in the clear but are **appended to the associated data**, so they are
covered by the tag. They are indices, not key material: deriving message key *n* requires
the chain key, which never leaves the client.

The counter is what lets a receiver recover from loss and reordering — both of which this
server causes by design, since the offline queue drops oldest-first at 512 packets. A
receiver that simply ratcheted once per arrival would fall permanently out of step the
first time a message went missing. With the counter it can skip forward, keep the
passed-over keys for a late arrival, and carry on.

The group epoch identifies which generation of a sender's chain the message was sealed
with, so a receiver holding an older generation can tell "they have rekeyed, the new key
is coming" apart from "this is corrupt".

### 2.3 Operations

#### Login (`0x10 CtrlLogin` → `0x11 CtrlLoginAck`)

- **Request**: `[PublicKey 32] [Username]`
- **Reply**: `[Assigned UserID 16]`

The server registers the user, binds their socket, stores their identity key, and flushes
any offline queue.

#### Private chat initialization (`0x15 CtrlDirectInit` → `0x16 CtrlDirectAck`)

- **Request** (client → server only): `[TargetUsername]`
- **Reply to initiator**: `[ConvID 16] [PeerID 16] [PeerPubKey 32] [PeerUsername]`

**The target is not notified.** The server mints the conversation ID, registers it, and
answers the initiator alone. The initiator derives its session immediately and can send
straight away, even if the target is offline.

The target learns of the conversation only when the first message arrives: it holds the
undecryptable packet, asks the server for the roster, derives the mirror session, and
replays what it held. See §4.4.

#### Conversation lookup (`0x1E CtrlConvInfoRq` → `0x1F CtrlConvInfoAck`)

- **Request**: `[ConvID 16]`
- **Reply**: `[ConvID 16] [IsGroup 1] [NameLen 2] [Name] [MemberCount 2]` then per member
  `[UserID 16] [PubKey 32] [NameLen 2] [Name]`

This is the only route by which a client obtains another user's public key. The server
**refuses unless the requester is a member** of that conversation, and answers a
non-member with silence rather than an error, so it cannot be used to probe which
conversation IDs exist.

A single reply serves both purposes: it tells the client whether the conversation is a
group, and supplies every member's identity key so direct sessions can be derived on the
spot rather than costing a lookup each.

#### Creating a group (`0x12 CtrlGroupCreate`)

- **Client → Server**: `[NameLen 1] [GroupName] [MemberCount 1]` then `[UserLen 1] [Username]`…
- **Server → Broadcast**: `[ConvID 16] [NameLen 1] [GroupName] [MemberCount 1]` then per
  member `[UserID 16] [PubKey 32] [NameLen 1] [Name]`

The identity keys ride along so every member can derive a direct session with every other
member immediately. The server also registers the **pairwise conversations** between all
members at this point, so sender-key packets have somewhere to be relayed without each
pair first exchanging a `CtrlDirectInit`.

#### Sender key distribution (`0x1D CtrlSenderKey`)

- **Body**: `[GroupID 16] [Epoch uint32 (4)] [ChainKey 32]`

Sent from one member to one other member, always **inside a packet encrypted with the
direct session** the two share, so the server relays it as ordinary data and never sees
the chain key.

#### Group administration

| Type | Operation |
| :--- | :--- |
| `0x13 CtrlGroupAdd` | Add a member. Broadcast carries the new member's identity key. |
| `0x14 CtrlGroupRemove` | Remove a member, or leave. |
| `0x1B CtrlGroupMakeAdmin` | Elevate to admin. |
| `0x1C CtrlGroupRemoveAdmin` | Revoke admin. |

Admin is a **membership role only**. It confers no part in key distribution — every member
distributes their own sender key regardless.

#### Media transfers (`0x04 MsgMediaMeta`)

Heavy bytes never travel through the chat server. The encrypted blob goes directly to
Supabase Storage and only a small metadata envelope is relayed.

1. **Signed-URL exchange** (plaintext control packets):
   - `0x20 CtrlUploadRq` → `0x21 CtrlUploadAck` `[objectPath] [signed upload URL]`
   - `0x22 CtrlDownloadRq` `[objectPath]` → `0x23 CtrlDownloadAck` `[signed download URL]`

   The server holds the Supabase `service_role` key, scopes the object path to the
   conversation (`<convIDhex>/<random>`), and mints time-limited URLs. It verifies the
   requester is a **member of that conversation** first.

2. **Blob transfer** (client ⇄ Supabase, direct HTTP): the sender generates a random
   32-byte key, encrypts the file, and PUTs the ciphertext. The recipient GETs it from a
   signed download URL.

3. **The envelope**, fully E2E encrypted and relayed like any text message:
   `[NameLen 2] [FileName] [TypeLen 2] [FileType] [FileSize 8] [PathLen 2] [ObjectPath]
   [DecryptKey 32] [FileHash SHA-256 32] [ThumbLen 4] [Thumbnail JPEG]`

The recipient recomputes SHA-256 over the decrypted bytes and drops the file if it does
not match. The server sees neither the file bytes nor the decryption key.

---

## 3. Server Architecture (`server/server.go`)

A TCP broker handling concurrent connections, state, and routing.

### 3.1 State

- **Users** (`users`, `usernames`): user records, identity keys, and per-user offline queues.
- **Connections** (`clients`, `conns`): active sockets, guarded by `sync.RWMutex`.
- **Conversations** (`convs`): both 1-to-1 and group, each with a member list and an admin
  set, used to authorize routing.

### 3.2 Delivery

Each connection has exactly one writer goroutine (`writeLoop`), so packets are framed in
order without a write lock. Producers hand packets over via `enqueue`, which never blocks:
a recipient more than `sendBufferSize` (128) packets behind is treated as stalled and
disconnected, and its backlog spills to the offline queue. The offline queue is capped at
512 packets per user and **drops the oldest first**.

### 3.3 Processing

1. **`handleConnection`** — forces a login packet, binds the socket, flushes the offline
   queue, then reads in a loop. Every inbound packet has its `SenderID` overwritten with
   the authenticated user ID.
2. **`handleData`** — looks the conversation up, verifies the sender is a member, and fans
   out to everyone else. A **blind relay**: with `FlagEncrypted` set it never inspects the
   body. Carries `MsgText`, `MsgMediaMeta`, and `CtrlSenderKey`.
3. **`handleConvInfoRq`** — the membership-gated roster lookup described in §2.3.
4. **`handleUploadRq` / `handleDownloadRq`** (`supabase.go`) — the only endpoints that talk
   to Supabase. They validate membership and mint short-lived signed URLs.
5. **Admin verification** — `handleGroupAdd`, `handleGroupRemove`, `handleGroupMakeAdmin`
   and `handleGroupRemoveAdmin` check `conv.Admins[sender.UserID]` before propagating.
   A member may always remove *themselves*; removing anyone else requires admin. The last
   admin cannot be demoted, and if the last admin leaves, a remaining member is promoted.

---

## 4. Client Internals

### 4.1 `IdentityManager` (`client/identity.go`)

Loads or generates `identity.key`, holding `[Private 32][Public 32]`. The public key is
re-derived from the private key at runtime, so a corrupted public half repairs itself.

### 4.2 `SessionManager` (`client/session.go`)

**Direct sessions.** `DeriveDirectSession(convID, peerID, peerPubKey)` is called by *both*
peers independently and takes no packet. It computes the shared secret, splits it into two
roots, and assigns send/receive by `LowerID`. `PerformHandshake` and `HandleHandshake` no
longer exist.

**Group sessions.** A `GroupSession` holds this client's own sending chain and epoch, plus
one receiving chain per other member and one previous generation per member:

- `RotateSenderKey(groupID)` generates a fresh chain and bumps this member's own epoch.
  **Only the key it returns may be distributed** — the live chain ratchets forward with
  every message, so reading it back later would hand peers a key that cannot open anything
  already sent in that epoch.
- `SetPeerSenderKey` installs a member's chain, retiring the one it replaces. A key at an
  epoch already passed is ignored, so a replayed distribution cannot wind a chain backwards.
- Epochs are **per sender**, not group-wide, so members never have to agree on a number.

**Shared ratchet handling.** `advanceChain` derives the message key for a sequence number
and returns a *prospective* chain state. Nothing is written back until the ciphertext
authenticates. Committing first would let a forged sequence number push the chain past
where real messages can reach it — permanently rejecting everything that follows — and let
a replay consume a stored skipped key that a genuine late message still needed.

**Recoverable failures.** `ErrNoSession`, `ErrNoGroupSession` and `ErrNoSenderKey` mean
"not yet" rather than "never". `Recoverable(err)` distinguishes them from a genuine reject
(bad tag, duplicate, retired epoch), which is what decides whether a packet is held or
dropped.

### 4.3 `pendingQueue` (`client/pending.go`)

Holds packets whose key has not arrived and replays them when it does — released by
conversation when a roster lands, or by conversation *and sender* when a sender key lands,
since that unblocks nothing else.

Bounded three ways, because anything held is memory that arrived unsolicited: 64 packets
per conversation, 512 overall, and a 30-second TTL. The per-conversation cap keeps the
*newest*, since whatever is blocking a conversation is likelier to resolve for recent
traffic than for a long backlog. Global eviction charges the conversation holding the most.
The TTL sweep runs on insertion, so there is no background goroutine to manage.

### 4.4 Flow (`client/client.go`)

`readLoop` decodes from the socket and hands each packet to `deliver`, which decrypts and
dispatches — or, if the key has not arrived, holds it:

```
readLoop  →  deliver  →  dispatch
                 ↓
           park + request roster
                 ↓
        (key arrives)  →  replay  →  deliver
```

Replayed packets re-enter through `deliver`, so they take exactly the same path as fresh
ones. `requestConvInfo` is throttled to one lookup per conversation per 5 seconds, since
the server answers non-members with silence.

**Receiving a first message from an unknown peer**, end to end:

1. Ciphertext arrives for a conversation the client has never seen.
2. `DecryptPacket` returns `ErrNoSession`; the packet is parked and `CtrlConvInfoRq` is sent.
3. The server confirms membership and returns the roster.
4. `applyConvInfo` registers the conversation, derives the session, and replays the held
   packets, which now decrypt.

An unknown *group* message initially takes the direct branch, because `IsGroup` returns
false for anything unregistered. That resolves itself: the roster reply says which it
really is, and the replayed packet takes the correct branch on the second pass.

**Joining or creating a group**: `bootstrapGroupKeys` derives a direct session with every
member from the identity keys in the broadcast, generates this client's own sending chain,
and unicasts it to each member. No round trips — the keys arrived with the roster and the
server already registered the pairwise conversations.

**On any membership change**, every member generates a fresh sender key and redistributes
to the current roster. Removal additionally drops the departed member's chain. This is
mandatory on removal: a removed member holds everyone's chain keys, and a chain ratchets
forward on its own, so without a rekey they would keep reading the group indefinitely.
Rotating on add too means a joiner cannot read anything sent before they arrived.

### 4.5 `ClientManager` (`client/manager.go`)

Tracks conversations, membership, admin sets, usernames, and cached public keys. Public
keys now arrive with rosters and group broadcasts, so there is no blocking fetch.

**Media** (`media.go`, `thumbnail.go`): on `/file`, `sendMedia` detects the MIME type,
hashes and encrypts the file, requests a signed upload URL, PUTs the ciphertext, and sends
the envelope. On receipt the item appears inline immediately (with an ANSI half-block
thumbnail for images) while a background download fetches, decrypts, verifies the hash,
and saves to `downloads/`.

### 4.6 TUI (`client/ui.go`)

A Bubble Tea split-screen: conversation sidebar with unread counts, message viewport, and
a system log. Slash commands with tab completion and parameter hints, plus a progress bar
for transfers.

---

## 5. Security Summary

**What holds:**

- **Server blindness.** Message and file contents are opaque to the server. It sees
  routing headers, control payloads, and packet sizes — nothing more.
- **Per-message keys.** Every message uses a distinct key derived by one-way HMAC ratchet,
  so compromising one message key reveals neither earlier keys nor other messages.
- **Authenticated metadata.** The header and the plaintext counters are covered by the
  AEAD tag, so a forged sender ID, conversation ID, counter or epoch fails verification
  rather than taking effect.
- **Verify-before-commit.** Ratchet state advances only after a ciphertext authenticates,
  so forged packets cannot desynchronize a chain or destroy a stored key.
- **Group removal is meaningful.** Every member rekeys on any membership change, so a
  removed member's keys stop working for traffic sent after they left.
- **Server-enforced authorization.** Group operations are checked against the admin set,
  and public keys are only released to conversation members.
- **Bounded resources.** Skipped keys are capped at 2000 ahead, held packets at 64 per
  conversation and 512 total, offline queues at 512 per user.

**What does not hold** — see *Known limitations* at the top for detail:

- No forward secrecy on direct chats, and no session persistence, which together mean a
  client restart can reissue used message keys.
- No protection against a malicious server substituting identity keys.
- No out-of-band key verification.
