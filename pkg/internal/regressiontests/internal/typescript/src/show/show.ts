export class Show {
    constructor(public readonly debug: boolean) {
    }

    message(...args: any[]) {
        if (this.debug) {
            console.log(`---------------------------------------------------------------------`);

            console.log(...args);

            console.log(`---------------------------------------------------------------------`);
            console.log()
        }
    }

    that(title: string, ...args: any[]) {
        if (this.debug) {
            console.log(`---------------------------- ${title}---------------------------- `);
            args.forEach((item: any) => {
                console.log(item);
            });
            console.log(`-------------------------------------------------------------------`);
        }
    }
}
