import {BatchOptions} from './types';

export const userDataPath = (userId: string, fields?: string[]) => {
  const path = `/users/${userId}/data`;
  const query = [];

  if (fields && fields.length > 0) {
    const uriEncodedFields = fields.map(encodeURIComponent);
    query.push(`fields=${uriEncodedFields.join(',')}`);
  }

  return `${path}?${query.join('&')}`;
};

export const batchUserDataPath = (fields: string[], options: BatchOptions) => {
  const path = `/data`;
  const query = [];

  if (options.cursor) {
    query.push(`cursor=${options.cursor}`);
  }
  if (options.limit) {
    query.push(`limit=${options.limit}`);
  }

  if (fields && fields.length > 0) {
    const uriEncodedFields = fields.map(encodeURIComponent);
    query.push(`fields=${uriEncodedFields.join(',')}`);
  }

  return `${path}?${query.join('&')}`;
};

export const dataKeyPath = (userId: string) => {
  return `/key_manager/users/${userId}/data_key`;
};

export const batchDataKeyPath = () => {
  return `/key_manager/data_key`;
};

export const wrapperKeyPath = (userId: string) => {
  return `/key_manager/users/${userId}/wrapper_key`;
};

export const fileUploadsPath = (userId: string, fieldId: string) => {
  return `/users/${userId}/fields/${fieldId}/files`;
};

export const fileDownloadsPath = (userId: string, fieldId: string, fileId: string) => {
  return `/users/${userId}/fields/${fieldId}/files/${fileId}/contents`;
};

export const integrityHashPath = (integrityHash: string) => {
  return `/data/${integrityHash}`;
};

export const siweNoncePath = () => {
  return '/auth/siwe/nonce';
};

export const siwePath = () => {
  return '/auth/siwe';
};
