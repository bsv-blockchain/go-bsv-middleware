import process from 'node:process';

export function createDebugHandler(parsedArgs: any) {
  const isDebug =
    process.env.REGRESSION_TEST_DEBUG === 'true' ||
    parsedArgs.verbous === true ||
    parsedArgs.v === true;

  return new Show(isDebug);
}

export class Show {
  constructor(public readonly debug: boolean) {}

  message(...args: any[]) {
    console.log(`---------------------------------------------------`);
    if (this.debug) {
      console.log(...args);
    }
    console.log(`---------------------------------------------------`);
  }

  that(title: string, ...args: any[]) {
    if (this.debug) {
      console.log(`----------------- ${title} -----------------`);
      args.forEach((item: any) => {
        console.log(item);
      });
      console.log(`---------------------------------------------------`);
    }
  }

  result(result: any) {
    console.log(result);
  }
}
