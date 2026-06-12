# Montoya Collaborator API — Reference

> Package: `burp.api.montoya.collaborator`
> Verified against: javadoc (portswigger.github.io) **+** `montoya-api-2026.2.jar` (the version this project links)
> Edition: **Burp Suite Professional only** (Community throws on use)
> Last researched: 2026-06-12

This is the authoritative map of what the Collaborator API lets an extension (and
therefore our MCP server) do — and what it structurally cannot do.

---

## 0. TL;DR — capability matrix

| Capability | Self-managed client | Default generator | Native Collaborator tab |
|---|:---:|:---:|:---:|
| Generate payloads | ✅ `createClient()` → client | ✅ `defaultPayloadGenerator()` | (manual, in UI) |
| Custom data in payload (≤16 alnum) | ✅ | ❌ (no custom-data overload) | n/a |
| **Poll interactions via API** | ✅ `getAllInteractions()` / `getInteractions()` | ❌ **none** | ❌ no API |
| Interactions visible in **native Collaborator tab** | ❌ (private to your client) | ✅ **yes** ("shown in the Collaborator results tab") | ✅ |
| Persist / resume (secret key) | ✅ `getSecretKey()` + `restoreClient()` | ❌ no secret key | ❌ no API |
| Read server address | ✅ `server()` | ❌ | n/a |

**The one-sentence takeaway:** you get **either** API-pollable interactions (your own
private client) **or** visibility in Burp's native Collaborator tab (the default
generator) — **never both**, because the default generator is generate-only.

---

## 1. Entry point

```java
Collaborator c = api.collaborator();   // MontoyaApi.collaborator()
```

`Collaborator` (the whole API surface — only 3 methods):

| Method | Returns | Purpose |
|---|---|---|
| `createClient()` | `CollaboratorClient` | New **self-managed** client: generate + **poll** + persist. |
| `restoreClient(SecretKey)` | `CollaboratorClient` | Re-attach to a previously-created client by its secret key (resumes its payloads/interactions). |
| `defaultPayloadGenerator()` | `CollaboratorPayloadGenerator` | Burp's **default** generator. Payloads are **linked to the Collaborator tab**; their interactions appear in the Collaborator results tab that was open when the payload was generated. **Generate-only.** |

---

## 2. The two access modes (the crux)

### Mode A — Self-managed client  (`createClient` / `restoreClient`)
- Full lifecycle: generate payloads, **poll interactions programmatically**, export/restore via secret key.
- Interactions are **private to this client** — they do **NOT** appear in Burp's native Collaborator tab.
- This is what **BurpMCP-Ultra currently uses** for all 6 collaborator tools.

### Mode B — Default payload generator  (`defaultPayloadGenerator`)
- `CollaboratorPayloadGenerator` exposes **only** `generatePayload(PayloadOption...)`.
- Payloads are tied to Burp's default Collaborator context → interactions **show up in the native Collaborator results tab**.
- **No `getAllInteractions()`, no `getSecretKey()`, no `server()`** — you cannot read the
  hits back through the API. To see them you must look at the native tab, or rely on
  Burp surfacing them as scan issues.

> **Correction to an earlier assumption:** default-generator interactions DO appear in
> the native Collaborator tab — the javadoc states this explicitly. What's still
> impossible is *programmatically polling* them.

---

## 3. Full type reference

### `CollaboratorClient` (extends `CollaboratorPayloadGenerator`)
All methods throw `IllegalStateException` if Burp Collaborator is **disabled**.

| Method | Returns | Notes |
|---|---|---|
| `generatePayload(PayloadOption... options)` | `CollaboratorPayload` | No options → payload **includes server location** (full domain). |
| `generatePayload(String customData, PayloadOption... options)` | `CollaboratorPayload` | `customData` = **max 16 alphanumeric chars**, recoverable from the interaction. |
| `getAllInteractions()` | `List<Interaction>` | All interactions for payloads from **this** client. |
| `getInteractions(InteractionFilter filter)` | `List<Interaction>` | Server-side/where-supported filtered retrieval. |
| `server()` | `CollaboratorServer` | The server config bound to this client. |
| `getSecretKey()` | `SecretKey` | Export to persist/resume across sessions. |

### `CollaboratorPayloadGenerator`
| Method | Returns | Notes |
|---|---|---|
| `generatePayload(PayloadOption... options)` | `CollaboratorPayload` | Generate-only. Throws `IllegalStateException` if Collaborator disabled. |

### `CollaboratorPayload`
| Method | Returns | Notes |
|---|---|---|
| `id()` | `InteractionId` | The payload's interaction id. |
| `customData()` | `Optional<String>` | Embedded custom data, if any. |
| `server()` | `Optional<CollaboratorServer>` | Empty if generated `WITHOUT_SERVER_LOCATION`. |
| `toString()` | `String` | **The payload string itself** (full address — do NOT concatenate server again). |

### `CollaboratorServer`
| Method | Returns | Notes |
|---|---|---|
| `address()` | `String` | Hostname or IP of the Collaborator server (public `*.oastify.com` or private). |
| `isLiteralAddress()` | `boolean` | `true` if `address()` is an IP. |

### `SecretKey`
| Method | Returns | Notes |
|---|---|---|
| `toString()` | `String` | Base64 secret key string. |
| `static secretKey(String encodedKey)` | `SecretKey` | Wrap a base64 key for `restoreClient(...)`. |

### `Interaction` (one captured hit)
| Method | Returns | Notes |
|---|---|---|
| `id()` | `InteractionId` | Interaction id (the payload subdomain label). |
| `type()` | `InteractionType` | `DNS` / `HTTP` / `SMTP`. |
| `timeStamp()` | `ZonedDateTime` | When the hit occurred. |
| `clientIp()` | `InetAddress` | Source IP of the interacting client. |
| `clientPort()` | `int` | Source port. **(Not currently serialized by our bridge.)** |
| `dnsDetails()` | `Optional<DnsDetails>` | Present for DNS. |
| `httpDetails()` | `Optional<HttpDetails>` | Present for HTTP. |
| `smtpDetails()` | `Optional<SmtpDetails>` | Present for SMTP. |
| `customData()` | `Optional<String>` | Custom data echoed from the payload. **(Not currently serialized.)** |

### `DnsDetails`
| Method | Returns | Notes |
|---|---|---|
| `queryType()` | `DnsQueryType` | A, AAAA, CNAME, MX, TXT, … (full list below). |
| `query()` | `ByteArray` | **Raw DNS query bytes** — NOT a clean hostname. `toString()` on it yields binary noise (this is why our Details column looked garbled). Decode the qname instead. |

### `HttpDetails`
| Method | Returns | Notes |
|---|---|---|
| `protocol()` | `HttpProtocol` | e.g. HTTP/HTTPS variant. |
| `requestResponse()` | `HttpRequestResponse` | Full request to + response from the Collaborator server. |

### `SmtpDetails`
| Method | Returns | Notes |
|---|---|---|
| `protocol()` | `SmtpProtocol` | `SMTP` or `SMTPS`. |
| `conversation()` | `String` | The full SMTP conversation transcript. |

### `InteractionId`
- `toString()` → `String` (the interaction id string).

### `InteractionFilter`
| Method | Returns | Notes |
|---|---|---|
| `matches(CollaboratorServer, Interaction)` | `boolean` | Custom predicate; called per interaction. |
| `static interactionIdFilter(String id)` | `InteractionFilter` | Match by interaction id. |
| `static interactionPayloadFilter(String payload)` | `InteractionFilter` | Match by payload. |

### Enums
- **`InteractionType`**: `DNS`, `HTTP`, `SMTP`
- **`PayloadOption`**: `WITHOUT_SERVER_LOCATION` *(the only option — omit the server location from the payload)*
- **`SmtpProtocol`**: `SMTP`, `SMTPS`
- **`DnsQueryType`**: `A`, `AAAA`, `ALL`, `CAA`, `CNAME`, `DNSKEY`, `DS`, `HINFO`, `HTTPS`, `MX`, `NAPTR`, `NS`, `PTR`, `SOA`, `SRV`, `TXT`, `UNKNOWN`

---

## 4. Constraints & failure modes
- **Professional only.** On Community, `api.collaborator()` use throws (`UnsupportedOperationException`); our bridge already catches this.
- If the user has **disabled Collaborator** (project options), generate/poll/server throw `IllegalStateException`.
- **Custom data:** max **16 alphanumeric** characters.
- **No options** on `generatePayload` ⇒ payload embeds the server location (full domain you can use directly). `WITHOUT_SERVER_LOCATION` ⇒ payload omits it.
- The Collaborator **server** (public `*.oastify.com` vs a private server) is whatever is configured in Burp's project/user options — the API has **no method to change it**; clients inherit it.

---

## 5. Mapping to BurpMCP-Ultra (implemented)

Tools (7 total):
- **Mode A** (self-managed clients): `collaborator_create_client`, `collaborator_restore_client`, `collaborator_generate_payload`, `collaborator_poll`, `collaborator_server_info`, `collaborator_get_secret`.
- **Mode B** (default generator): `collaborator_default_payload` (optional `without_server_location`).

Improvements — **all implemented 2026-06-12** (verified, build green, 4 decoder unit tests):
1. **`query().toString()` is wrong** for DNS — it's `ByteArray` raw packet bytes, hence the
   garbled ` …oastifycom` output. Decode the qname for a clean hostname.
2. **Interaction fields not serialized:** `clientPort()` and the interaction-level
   `customData()` are dropped by `serializeInteraction`. Cheap to add.
3. **No Mode-B tool.** A `collaborator_default_payload` wrapping `defaultPayloadGenerator()`
   would let the agent push payloads into Burp's **native** Collaborator tab — but those
   hits are NOT API-pollable (must be read in the native tab / via scan issues).

---

## 6. Answer: "direct access to Burp's original Collaborator via MCP?"

- **Generate payloads on Burp's native/default Collaborator context:** ✅ possible via
  `defaultPayloadGenerator()`. Resulting interactions **appear in the native Collaborator tab.**
- **Programmatically poll/read those native-tab interactions:** ❌ **impossible** — the
  default generator is generate-only; only **self-managed** clients expose
  `getAllInteractions()`. And there is **no API** for the native tab's own client (no
  handle, no secret key).
- **Net:** the API forces a choice — native-tab visibility (generate-only) **or** API
  polling (private client). You cannot have a single client that is both polled by the
  agent and displayed in Burp's native Collaborator tab.

> Indirect read path for default-context hits: Burp may raise **"External service
> interaction"** audit issues, which the MCP can read via its scanner/issue tools.
