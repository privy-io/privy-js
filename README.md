# privy-js

Browser client for the Privy API.

https://www.privy.io

![build](https://github.com/privy-io/privy-js/actions/workflows/tests.yml/badge.svg)
![npm version](https://badge.fury.io/js/@privy-io%2Fprivy-js.svg)

## Installation

```
npm i @privy-io/privy-js
```

## Basic usage

Initialize the Privy client using a session that can fetch tokens from Privy through your backend.

```typescript
import axios from 'axios';
import PrivyClient, {CustomSession} from '@privy-io/privy-js';

const session = new CustomSession(async function authenticate() {
  const response = await axios.post<{token: string}>(
    `/your/custom/endpoint`,
  );
  return response.data.token;
});

const client = new PrivyClient({
  session: session,
});
```

Using the Privy client, read and write some data for a given user.

```typescript
const userId = "0x123";

// To write...
const [email, ssn] = await client.put(userId, [
  {field: "email", value: "foo@example.com"},
  {field: "ssn", value: "123-45-6789"},
]);

// To read...
const [email, ssn] = await client.get(userId, ["email", "ssn"]);
console.log(email.text());
console.log(ssn.text());
```

## Documentation

### Session

Privy clients depend on a session object to handle authentication. There are three Session objects:

1. [`CustomSession`](#customsession)
2. [`SiweSession`](#siwesession)
3. [`PublicSession`](#publicsession)

`Session` objects implement the following properties and methods:

```typescript
interface Session {
  token: string | null;
  isAuthenticated(): Promise<boolean>;
  authenticate(): Promise<void>;
  destroy(): Promise<void>;
}
```

* `token` is the JWT returned by the Privy API upon successfully authenticating.
* `isAuthenticated()` should return `true` if the session is considered authenticated, `false` otherwise.
* `authenticate()` should authenticate with the Privy API (potentially indirectly through a backend). After a successful call, the session should be considered authenticated.
* `destroy()` should remove any state related to authentication. Afterwords, the session should NOT be considered authenticated.

### CustomSession

`CustomSession` implement the [session](#session) interface. `CustomSession` can be used to authenticate to Privy through your own backend.

```typescript
import {CustomSession} from '@privy-io/privy-js';
```

In addition to the interface methods, the following methods are supported:

#### `constructor(authenticate: () => Promise<string>): CustomSession`

* `authenticate: () => Promise<string>` - Custom authenticate function. Must return a valid JWT on success.

### SiweSession

Sign-In With Ethereum sessions, i.e., `SiweSessions`, implement the [session](#session) interface.

Privy's backend is able to issue access tokens using the [Sign-In With Ethereum](https://eips.ethereum.org/EIPS/eip-4361) spec. This enables developers to use Privy for reading/writing user data *without* hosting their own backend to handle authentication. A big win for reducing operational complexity!

```typescript
import {SiweSession} from '@privy-io/privy-js';
```

In addition to the interface methods, the following methods are supported:

#### `constructor(apiKey: string, provider: EthereumProvider): SiweSession`

* `apiKey: string` is your *public* API key.
* `provider: EthereumProvider` is the Ethereum provider, typically `window.ethereum` (injected by MetaMask).

#### `address(): Promise<string | null>`

Get the address of the currently connected wallet. Returns the EIP-55 mixed-case checksum-encoded address of connected wallet or null if not connected.

#### `connect(): Promise<string | null>`

Prompt the user to connect their wallet. Returns the EIP-55 mixed-case checksum-encoded address of connected wallet or null if user does not connect.

#### `chainId(): Promise<string>`

The currently connected EIP-155 chain id. E.g., `1` for Ethereum mainnet.

### PublicSession

`PublicSession` implement the [session](#session) interface. `PublicSession` can be used to authenticate only for data marked as publically assessible.

```typescript
import {PublicSession} from '@privy-io/privy-js';
```

In addition to the interface methods, the following methods are supported:

#### `constructor(apiKey: string): PublicSession`

* `apiKey: string` is your *public* API key.

### PrivyClient

The Privy client performs operations against the Privy API.

```typescript
import PrivyClient from '@privy-io/privy-js';
```

#### `constructor(options: PrivyOptions): Client`

* `options: PrivyOptions`
  * `session: Session` - An object that implements the `Session` interface.
  * `apiURL?: string` - The URL of the Privy API. Defaults to `https://api.privy.io/v0`.
  * `kmsURL?: string` - The URL of the Privy KMS. Defaults to `https://kms.privy.io/v0`.
  * `timeout?: number` - Time in milliseconds after which to timeout requests to the API and KMS. Defaults to `10000` (10 secondse).

#### `get(userId: string, fields: string | Array<string>): Promise<(FieldInstance | null) | Array<FieldInstance | null>>`

`get` fetches either a single field or a list of fields, returning an instance of each field (or null if no data exists for that field and user).

```typescript
// Single field
const email = await client.get("0x123", "email");

// Multiple fields. Resulting list is ordered according to input list.
const [firstName, lastName] = await client.get("0x123", ["first-name", "last-name"]);
```

#### `put(userId: string, field: string | Array<{field: string; value: string}>, value?: string): Promise<FieldInstance | Array<FieldInstance>>`

`put` updates data for field(s) for a given user.

```typescript
// Single field
const email = await client.put("0x123", "email", "foo@example.com");

// Multiple fields. Resulting list is ordered according to input list.
const [firstName, lastName] = await client.put("0x123", [
  {field: "first-name", value: "Jane"},
  {field: "last-name", value: "Doe"},
]);
```

#### `getFile(userId: string, field: string): Promise<FieldInstance | null>`

Download a file stored under a field.

```typescript
const avatar = await client.getFile("0x123", "avatar");
download(avatar);

function download(field: FieldInstance) {
  const data = window.URL.createObjectURL(field.blob());

  // Lookup extension by mime type (included on blob)
  const ext = getExtensionFromMIMEType(blob.type);
  const filename = `${field.integrity_hash}.${ext}`;

  // Create a link pointing to the ObjectURL containing the blob.
  const link = document.createElement("a");
  link.style = "display: none;";
  link.href = data;
  link.download = filename;
  link.click();

  // Cleanup
  window.URL.revokeObjectURL(data);
  link.remove();
}
```

#### `putFile(userId: string, field: string, blob: Blob): Promise<FieldInstance>`

Upload a file for a given field.

```typescript
const onUpdateAvatar = async (avatar: File) => {
  try {
    await client.putFile("0x123", "avatar", avatar);
  } catch (error) {
    console.log(error);
  }
};
```

#### `getByIntegrityHash(integrityHash: string): Promise<FieldInstance | null>`

Lookup a field instance by its integrity hash. This method can be used to verify data in addition to fetching it from Privy. For example, this method will:

1. Lookup data by integrity hash
2. Return the field instance if it exists
3. Re-compute the integrity hash client side. If it is NOT the same as the `integrityHash` argument, this method will throw an error.

```typescript
const ssn = await client.put("0x123", "ssn", "123-45-6789");
const ssnIntegrityHash = ssn.integrity_hash;

// later on...
const ssn = await client.getByIntegrityHash(ssnIntegrityHash);
```

## Testing

The test runner looks for files with a `.test.ts` extension. There are two groups of tests: unit and integration.

### Unit

To run unit tests:

```
npm test
```

### Integration

Some of the tests are currently expected to be run against a running instance of the API. To successfully run those, you will need to create a `.env` file in the root of this repo with the following fields:

```
PRIVY_API_URL=<privy api url>
PRIVY_KMS_URL=<privy kms url>
PRIVY_API_PUBLIC_KEY=<your public key>
PRIVY_API_SECRET_KEY=<your private key>
```

To run integration tests:

```
npm run test-integration
```
