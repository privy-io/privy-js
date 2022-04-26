export function toBuffer(str: string): Uint8Array {
  return new TextEncoder().encode(str);
}

export function toString(buf: Uint8Array): string {
  return new TextDecoder().decode(buf);
}

export function toHex(buf: Uint8Array) {
  return Buffer.from(buf).toString('hex');
}
