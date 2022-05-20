type EncodingType = 'utf8' | 'hex' | 'base64';

/**
 * Wraps the given Uint8Array as a Buffer without copying.
 * The returned Buffer shares the same underlying ArrayBuffer as the input.
 */
export const wrapAsBuffer = (data: Uint8Array): Buffer =>
  Buffer.from(data.buffer, data.byteOffset, data.byteLength);

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
    return wrapAsBuffer(data).toString(encoding);
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
    // Doesn't work:
    // return Buffer.from(data, encoding);

    // Doesn't work (see https://stackoverflow.com/questions/8609289/convert-a-binary-nodejs-buffer-to-javascript-arraybuffer/31394257#31394257):
    // return new Uint8Array(b.buffer, b.byteOffset, b.byteLength / Uint8Array.BYTES_PER_ELEMENT);

    // Works (?):
    const b = Buffer.from(data, encoding);
    return toArrayBuffer(b);
  },
};

function toArrayBuffer(buf: Buffer) {
  const ab = new ArrayBuffer(buf.length);
  const view = new Uint8Array(ab);
  for (let i = 0; i < buf.length; ++i) {
    view[i] = buf[i];
  }
  return view;
}
