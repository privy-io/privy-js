import {PrivyClient} from './client';

export {Session} from '@privy-io/client-core/dist/sessions/session';
export {CustomSession} from '@privy-io/client-core/dist/sessions/custom';
export {SiweSession} from './sessions/siwe';
export {PublicSession} from '@privy-io/client-core/dist/sessions/public';

export {FieldInstance} from './fieldInstance';

export {
  PrivyError,
  PrivyApiError,
  PrivyClientError,
  PrivySessionError,
} from '@privy-io/client-core/dist/errors';

export default PrivyClient;
