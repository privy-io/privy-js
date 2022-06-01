# privy-js

This is a monorepo for Privy's open source JavaScript libraries:

- [@privy-io/privy-browser](https://github.com/privy-io/privy-js/tree/main/packages/privy-browser)
- [@privy-io/privy-node](https://github.com/privy-io/privy-js/tree/main/packages/privy-node)

and the crypto library backing them:

- [@privy-io/crypto](https://github.com/privy-io/privy-js/tree/main/packages/crypto)

## Set Up

Ensure no pre-existing `node_modules` directory exists.

Install dependencies:

```
npm i
```

Build all packages:

```
npm run build --workspaces
```
