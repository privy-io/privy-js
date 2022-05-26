const seed = new Date().getTime();

let id = 0;

export default function uniqueId() {
  return `${seed}${++id}`;
}
