const isNodeProcess = !!(
  typeof process !== 'undefined' &&
  process.versions &&
  process.versions.node
);

export const isNode = isNodeProcess;
