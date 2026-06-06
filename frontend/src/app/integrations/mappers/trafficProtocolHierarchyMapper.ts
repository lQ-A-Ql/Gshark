import type { TrafficProtocolTreeNode } from "../../core/types";
import { asArray, asPlainObject } from "./mapperPrimitives";

export function asTrafficProtocolTreeNode(input: unknown): TrafficProtocolTreeNode {
  const obj = asPlainObject(input) ?? {};
  return {
    name: String(obj.name ?? ""),
    count: Number(obj.count ?? 0),
    children: asArray(obj.children).map(asTrafficProtocolTreeNode),
  };
}
