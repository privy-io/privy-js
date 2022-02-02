// Concatenate Buffers (compatible with TypedArrays and DataViews)
export const concatBuffers = (...inBuffers: ArrayBufferView[]): Buffer => {
  // Allocate byte array equal to the cumulative size of input buffers.
  const concatBufLength: number = inBuffers.reduce(
    (sumLength, buff) => sumLength + buff.byteLength,
    0,
  );
  const concatBuf = new Uint8Array(concatBufLength);

  // Concatenate buffers into concatBuf.
  let offset = 0;
  inBuffers.forEach((buf) => {
    if (ArrayBuffer.isView(buf)) {
      // Note: We need to break down ArrayBufferView to create Uint8Array.
      const {buffer, byteOffset, byteLength} = buf;
      concatBuf.set(new Uint8Array(buffer, byteOffset, byteLength), offset);
    } else {
      concatBuf.set(new Uint8Array(buf), offset);
    }
    offset += buf.byteLength;
  });

  return Buffer.from(concatBuf);
};

// Constants storing the size of a uint64 value.
const UINT64_SIZE_BYTES = 8;
const BITS_PER_BYTE = 8;
const UINT64_SIZE_BITS = UINT64_SIZE_BYTES * BITS_PER_BYTE;

// Returns an 8-byte buffer representing a uint64 value.
export const bufferFromUInt64 = (uint64Value: number): Buffer => {
  const uint64Buf = new ArrayBuffer(UINT64_SIZE_BYTES);
  const uint64DataView = new DataView(uint64Buf);

  // We write the value into into the buffer in big-endian format. This is architecture-agnostic
  // and just means we have to read the data back in the same format.
  uint64DataView.setBigUint64(0, BigInt(uint64Value), false); // Big endian.
  return Buffer.from(uint64DataView.buffer);
};

// Reads a uint64 integer value from the buffer, starting at the given offset.
// Returns the (uint64Value, endOffset) as a tuple.
export const uint64FromBuffer = (inputBuffer: Buffer, startOffset: number): [number, number] => {
  // Create a new buffer containing a copy of the bytes to read.
  const endOffset = startOffset + UINT64_SIZE_BYTES;
  const uint64Buf = inputBuffer.slice(startOffset, endOffset);
  const uint64DataView = new DataView(uint64Buf.buffer, uint64Buf.byteOffset, UINT64_SIZE_BYTES);

  // Read the integer from the buffer in big-endian because that is the format used to write it.
  // Clamps the value to an unsigned 64-bit integer value.
  const uint64Value = Number(
    BigInt.asUintN(UINT64_SIZE_BITS, uint64DataView.getBigUint64(0, false)), // Big endian.
  );
  return [uint64Value, endOffset];
};
