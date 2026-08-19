"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.Show = void 0;
class Show {
    constructor(debug) {
        this.debug = debug;
    }
    message(...args) {
        if (this.debug) {
            console.log(`---------------------------------------------------------------------`);
            console.log(...args);
            console.log(`---------------------------------------------------------------------`);
            console.log();
        }
    }
    that(title, ...args) {
        if (this.debug) {
            console.log(`---------------------------- ${title}---------------------------- `);
            args.forEach((item) => {
                console.log(item);
            });
            console.log(`-------------------------------------------------------------------`);
        }
    }
}
exports.Show = Show;
