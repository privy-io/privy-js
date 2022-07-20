# @privy-io/privy-browser

Privy's browser client allows you to interact with the Privy API from broswer clients.

For interacting with user data from a node backend, use [@privy-io/privy-node](https://www.npmjs.com/package/@privy-io/privy-node).

https://www.privy.io

![build](https://github.com/privy-io/privy-js/actions/workflows/tests.yml/badge.svg)
[![npm version](https://badge.fury.io/js/@privy-io%2Fprivy-browser.svg)](https://www.npmjs.com/package/@privy-io/privy-browser)

## Documentation

See https://docs.privy.io/.

## Installation

```
npm i @privy-io/privy-browser
```

## Basic usage

Initialize the Privy client using a session that can fetch tokens from Privy through your backend.

```typescript
import axios from 'axios';
import {PrivyClient, CustomSession} from '@privy-io/privy-browser';

const session = new CustomSession(async function authenticate() {
  const response = await axios.post<{token: string}>(`/your/custom/endpoint`);
  return response.data.token;
});

const client = new PrivyClient({
  session: session,
});
```

Using the Privy client, read and write some data for a given user.

```typescript
const userId = '0x123';

// To write...
const [email, ssn] = await client.put(userId, [
  {field: 'email', value: 'foo@example.com'},
  {field: 'ssn', value: '123-45-6789'},
]);

// To read...
const [email, ssn] = await client.get(userId, ['email', 'ssn']);
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

Some of the tests are currently expected to be run against a running instance of the API.

Reset data in the API instance before running tests, e.g. by recreating and seeding the test database.

To successfully run tests, you will need to create a `.env` file in the root of `./privy-browser` with the following fields:

```
PRIVY_API_URL=<privy api url>
PRIVY_KMS_URL=<privy kms url>
PRIVY_API_KEY=<your public key>
PRIVY_API_SECRET=<your private key>
```

To run integration tests:

```
npm run test-integration
```
