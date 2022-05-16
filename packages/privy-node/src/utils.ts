/**
 * Wrap ensures an object is an array.
 * ```
 *     wrap("str")   => ["str"]
 *     wrap(["str"]) => ["str"]
 * ```
 */
export const wrap = <T>(object: T | T[]): T[] => {
  return Array.isArray(object) ? object : [object];
};

/**
 * Loops over each array position, runs the callback with the corresponding items, and collects the results.
 */
export const mapPairs = <Left, Right, Result>(
  left: Left[],
  right: Right[],
  fn: (left: Left, right: Right) => Result,
): Result[] => {
  if (left.length !== right.length) {
    throw new Error('input arrays must be the same length');
  }
  return left.map((x, i) => fn(x, right[i]));
};
