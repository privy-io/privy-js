# privy-js

Browser client for the Privy API.

https://www.privy.io

![build](https://github.com/privy-io/privy-js/actions/workflows/tests.yml/badge.svg)
[![npm version](https://badge.fury.io/js/@privy-io%2Fprivy-js.svg)](https://www.npmjs.com/package/@privy-io/privy-js)

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
