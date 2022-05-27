import {fromByteArray, toByteArray} from 'base64-js';

type EncodingType = 'utf8' | 'hex' | 'base64';

export default {
  /**
   * Converts a buffer to string using the given encoding.
   *
   * @internal
   * @param {Uint8Array} data data to convert to a string
   * @param {EncodingType} encoding resulting string encoding
   * @returns {string} string
   */
  toString(data: Uint8Array, encoding: EncodingType): string {
    switch (encoding) {
      case 'utf8':
        return bufferToUtf8(data);
      case 'hex':
        return bufferToHex(data);
      case 'base64':
        return bufferToBase64(data);
      default:
        throw new Error(`Unrecognized encoding ${encoding}`);
    }
  },

  /**
   * Converts a string encoded in the given encoding to a buffer.
   *
   * @internal
   * @param {string} data data to convert to a buffer
   * @param {EncodingType} encoding encoding of the string
   * @returns {Uint8Array} Uint8Array
   */
  toBuffer(data: string, encoding: EncodingType): Uint8Array {
    switch (encoding) {
      case 'utf8':
        return utf8ToBuffer(data);
      case 'hex':
        return hexToBuffer(data);
      case 'base64':
        return base64ToBuffer(data);
      default:
        throw new Error(`Unrecognized encoding ${encoding}`);
    }
  },
};

const textEncoder = new TextEncoder();
function utf8ToBuffer(data: string): Uint8Array {
  return textEncoder.encode(data);
}

function hexToBuffer(data: string): Uint8Array {
  if (data.length % 2 !== 0) {
    throw new Error('Hex string must have an even length');
  }
  const bufferLength = data.length / 2;
  const buffer = new Uint8Array(bufferLength);
  for (let i = 0; i < bufferLength; i++) {
    const hex = data.substring(i * 2, i * 2 + 2);
    const byte = parseInt(hex, 16);
    if (Number.isNaN(byte) || byte < 0 || byte > 255) {
      throw new Error(`Invalid hex "${hex}" at index ${i * 2}`);
    }
    buffer[i] = byte;
  }
  return buffer;
}

function base64ToBuffer(data: string): Uint8Array {
  return toByteArray(data);
}

const textDecoder = new TextDecoder('utf8', {fatal: true});
function bufferToUtf8(data: Uint8Array): string {
  return textDecoder.decode(data);
}

function bufferToHex(data: Uint8Array): string {
  return data.reduce(
    (string, byte) =>
      string +
      byte
        // Convert to hex.
        .toString(16)
        // Pad with leading zero if needed.
        .padStart(2, '0'),
    '',
  );
}

function bufferToBase64(data: Uint8Array): string {
  return fromByteArray(data);
}
