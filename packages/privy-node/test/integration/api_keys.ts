import axios from 'axios';

const PRIVY_USERNAME = process.env.PRIVY_USERNAME || '';
const PRIVY_PASSWORD = process.env.PRIVY_PASSWORD || '';

export async function fetchAPIKeys(consoleUrl: string) {
  const {
    data: {token},
  } = await axios.post(
    '/token',
    {},
    {
      baseURL: consoleUrl,
      auth: {
        username: PRIVY_USERNAME,
        password: PRIVY_PASSWORD,
      },
    },
  );
  const {
    data: {key, secret},
  } = await axios.post(
    '/accounts/api_keys',
    {},
    {
      baseURL: consoleUrl,
      headers: {
        Authorization: `Bearer ${token}`,
      },
    },
  );
  console.log('Generated API key pair:', key, ',', secret);
  return {key, secret};
}
