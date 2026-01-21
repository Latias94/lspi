import { add, mul } from "./math";

export function run(): number {
  const x = add(1, 2);
  const y = mul(x, 3);
  return y;
}
