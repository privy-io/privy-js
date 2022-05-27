# @privy-io/privy-node

Privy's Node client allows you to interact with the Privy API from server-side Node applications.

For interacting with user data in the browser, use [@privy-io/privy-browser](https://www.npmjs.com/package/@privy-io/privy-browser).

https://www.privy.io

![build](https://github.com/privy-io/privy-js/actions/workflows/tests.yml/badge.svg)
[![npm version](https://badge.fury.io/js/@privy-io%2Fprivy-node.svg)](https://www.npmjs.com/package/@privy-io/privy-node)


## Documentation

See https://docs.privy.io/.

## Requirements

Node 14 and higher is supported.

## Installation

```
npm i @privy-io/privy-node
```

## Basic usage

Initialize the Privy client using a session that can fetch tokens from Privy through your backend.

```typescript
import {PrivyClient} from '@privy-io/privy-node';

const client = new PrivyClient(
  process.env.PRIVY_API_KEY,
  process.env.PRIVY_API_SECRET,
);
```

Using the Privy node client, configure your Privy datastore.

```typescript
// GET fields
const fields = await client.listFields();

// CREATE new field
const field = await client.createField({name: name, description: 'A field'});

// DELETE access group
await client.deleteAccessGroup(accessGroupId);

// GET permisions for a user
const permissions = await client.getUserPermissions(userId);
```

Using the Privy node client, you can also read and write some data for a given user.

TODO

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

