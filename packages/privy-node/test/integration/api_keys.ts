import axios from 'axios';

export async function fetchAPIKeys(consoleUrl: string) {
  const {
    data: {token},
  } = await axios.post(
    '/token',
    {},
    {
      baseURL: consoleUrl,
      auth: {
        username: 'hi@acme.co',
        password: 'acme-password1',
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
