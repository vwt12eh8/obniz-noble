import events = require("events");
import {Peripheral, Descriptor, Characteristic, Service} from "noble";
import Obniz from "obniz";

// pass thorough
export {Peripheral, Descriptor, Characteristic, Service, noble};

// this is cannot import as type, so I rewrite.
interface noble {
    startScanning(callback?: (error?: Error) => void): void;

    startScanning(serviceUUIDs: string[], callback?: (error?: Error) => void): void;
    startScanning(serviceUUIDs: string[], allowDuplicates: boolean, callback?: (error?: Error) => void): void;
    stopScanning(callback?: () => void): void;

    on(event: "stateChange", listener: (state: string) => void): events.EventEmitter;
    on(event: "scanStart", listener: () => void): events.EventEmitter;
    on(event: "scanStop", listener: () => void): events.EventEmitter;
    on(event: "discover", listener: (peripheral: Peripheral) => void): events.EventEmitter;
    on(event: string, listener: Function): events.EventEmitter;

    removeListener(event: "stateChange", listener: (state: string) => void): events.EventEmitter;
    removeListener(event: "scanStart", listener: () => void): events.EventEmitter;
    removeListener(event: "scanStop", listener: () => void): events.EventEmitter;
    removeListener(event: "discover", listener: (peripheral: Peripheral) => void): events.EventEmitter;
    removeListener(event: string, listener: Function): events.EventEmitter;

    removeAllListeners(event?: string): events.EventEmitter;

    state:string;

}

export default function obnizNoble(id:string, options?:any, obnizClass?: Obniz):noble;

