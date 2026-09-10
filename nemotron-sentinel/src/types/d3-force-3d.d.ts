declare module "d3-force-3d" {
  export function forceSimulation<Node = any, Link = any>(nodes?: Node[], numDimensions?: number): any;
  export function forceLink<Node = any, Link = any>(links?: Link[]): any;
  export function forceManyBody<Node = any>(): any;
  export function forceCenter<Node = any>(x?: number, y?: number, z?: number): any;
  export function forceCollide<Node = any>(radius?: number | ((d: Node) => number)): any;
  export function forceRadial<Node = any>(radius?: number, x?: number, y?: number, z?: number): any;
  export function forceX<Node = any>(x?: number): any;
  export function forceY<Node = any>(y?: number): any;
  export function forceZ<Node = any>(z?: number): any;
}
