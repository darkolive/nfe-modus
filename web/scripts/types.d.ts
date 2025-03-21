// Type definitions for modules without official type declarations

declare module 'dgraph-js' {
  export class DgraphClient {
    constructor(clientStub: DgraphClientStub);
    alter(op: Operation): Promise<any>;
    newTxn(): any;
  }
  
  export class DgraphClientStub {
    constructor(addr: string, credentials: any);
    close(): void;
  }
  
  export class Operation {
    setDropAll(flag: boolean): void;
    setSchema(schema: string): void;
  }
  
  export class Mutation {
    setSetJson(data: any): void;
    setCommitNow(flag: boolean): void;
  }
}

// Declare grpc module if needed
declare module '@grpc/grpc-js' {
  export const credentials: {
    createInsecure(): any;
  };
}
