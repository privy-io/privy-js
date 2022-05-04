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
