# obniz-noble


A Node.js BLE (Bluetooth Low Energy) central module for [obniz](https://obniz.io).

Want to implement a peripheral? Checkout [obniz-bleno](https://github.com/obniz/bleno)


## How to convert from noble


1. Install obniz-noble and uninstall noble.

```sh
npm install obniz-noble
npm uninstall noble
```

2. Change require method for noble

```javascript

  // before
  const noble = require("noble");


  // after
  const obnizNoble = require("obniz-noble");
  const obniz = require("obniz");
  const noble = obnizNoble("OBNIZ_ID_HERE");
  // or  const noble = obnizNoble("OBNIZ_ID_HERE", {obnizOptions}, obniz);

```

3. Setup obniz device and run your script!

## Install & Usage

For node.js

```sh
npm install obniz-noble
```


```javascript
var obnizNoble = require('obniz-noble');
var obniz = require("obniz");
var noble = obnizNoble("OBNIZ_ID_HERE");
// or  var noble = obnizNoble("OBNIZ_ID_HERE", {obnizOptions}, obniz);

```




For browser 

```html
<script src="https://unpkg.com/obniz/obniz.js"></script> 
<script src="https://unpkg.com/obniz-noble/obniz-noble.js" crossorigin="anonymous"></script>

<script>
  var noble = obnizNoble("OBNIZ_ID_HERE"); 
  // or  var noble = obnizNoble("OBNIZ_ID_HERE", {obnizOptions}, Obniz);
  ...
</script>
```


### Actions

#### Start scanning

```javascript
noble.startScanning(); // any service UUID, no duplicates


noble.startScanning([], true); // any service UUID, allow duplicates


var serviceUUIDs = ["<service UUID 1>", ...]; // default: [] => all
var allowDuplicates = <false|true>; // default: false

noble.startScanning(serviceUUIDs, allowDuplicates[, callback(error)]); // particular UUID's
```

__NOTE:__ ```noble.state``` must be ```poweredOn``` before scanning is started. ```noble.on('stateChange', callback(state));``` can be used register for state change events.

#### Stop scanning

```javascript
noble.stopScanning();
```

#### Peripheral

##### Connect

```javascript
peripheral.connect([callback(error)]);
```

##### Disconnect or cancel pending connection

```javascript
peripheral.disconnect([callback(error)]);
```

##### Update RSSI

```javascript
peripheral.updateRssi([callback(error, rssi)]);
```

##### Discover services

```javascript
peripheral.discoverServices(); // any service UUID

var serviceUUIDs = ["<service UUID 1>", ...];
peripheral.discoverServices(serviceUUIDs[, callback(error, services)]); // particular UUID's
```

##### Discover all services and characteristics

```javascript
peripheral.discoverAllServicesAndCharacteristics([callback(error, services, characteristics)]);
```

##### Discover some services and characteristics

```javascript
var serviceUUIDs = ["<service UUID 1>", ...];
var characteristicUUIDs = ["<characteristic UUID 1>", ...];
peripheral.discoverSomeServicesAndCharacteristics(serviceUUIDs, characteristicUUIDs, [callback(error, services, characteristics));
```
#### Service

##### Discover included services

```javascript
service.discoverIncludedServices(); // any service UUID

var serviceUUIDs = ["<service UUID 1>", ...];
service.discoverIncludedServices(serviceUUIDs[, callback(error, includedServiceUuids)]); // particular UUID's
```

##### Discover characteristics

```javascript
service.discoverCharacteristics() // any characteristic UUID

var characteristicUUIDs = ["<characteristic UUID 1>", ...];
service.discoverCharacteristics(characteristicUUIDs[, callback(error, characteristics)]); // particular UUID's
```

#### Characteristic

##### Read

```javascript
characteristic.read([callback(error, data)]);
```

##### Write

```javascript
characteristic.write(data, withoutResponse[, callback(error)]); // data is a buffer, withoutResponse is true|false
```

* ```withoutResponse```:
  * ```false```: send a write request, used with "write" characteristic property
  * ```true```: send a write command, used with "write without response" characteristic property

##### Broadcast

```javascript
characteristic.broadcast(broadcast[, callback(error)]); // broadcast is true|false
```

##### Subscribe

```javascript
characteristic.subscribe([callback(error)]);
```

  * subscribe to a characteristic, triggers `'data'` events when peripheral sends an notification or indication
  * use for characteristics with notify or indicate properties

##### Unsubscribe

```javascript
characteristic.unsubscribe([callback(error)]);
```

  * unsubscribe to a characteristic
  * use for characteristics with notify or indicate properties

##### Discover descriptors

```javascript
characteristic.discoverDescriptors([callback(error, descriptors)]);
```

##### Read value

```javascript
descriptor.readValue([callback(error, data)]);
```

##### Write value

```javascript
descriptor.writeValue(data[, callback(error)]); // data is a buffer
```

#### Handle

##### Read

```javascript
peripheral.readHandle(handle, callback(error, data));
```

##### Write

```javascript
peripheral.writeHandle(handle, data, withoutResponse, callback(error));
```

### Events

See [Node.js EventEmitter docs](https://nodejs.org/api/events.html) for more info. on API's.

#### Adapter state change

```javascript
state = <"unknown" | "resetting" | "unsupported" | "unauthorized" | "poweredOff" | "poweredOn">

noble.on('stateChange', callback(state));
```

#### Scan started:

```javascript
noble.on('scanStart', callback);
```

The event is emitted when scanning is started or if another application enables scanning or changes scanning settings.

#### Scan stopped

```javascript
noble.on('scanStop', callback);
```

The event is emitted when scanning is stopped or if another application stops scanning.

#### Peripheral discovered

```javascript
peripheral = {
  id: "<id>",
  address: "<BT address">, // Bluetooth Address of device, or 'unknown' if not known
  addressType: "<BT address type>", // Bluetooth Address type (public, random), or 'unknown' if not known
  connectable: <connectable>, // true or false, or undefined if not known
  advertisement: {
    localName: "<name>",
    txPowerLevel: <int>,
    serviceUuids: ["<service UUID>", ...],
    serviceSolicitationUuid: ["<service solicitation UUID>", ...],
    manufacturerData: <Buffer>,
    serviceData: [
        {
            uuid: "<service UUID>"
            data: <Buffer>
        },
        ...
    ]
  },
  rssi: <rssi>
};

noble.on('discover', callback(peripheral));
```

__Note:__ on OS X the address will be set to 'unknown' if the device has not been connected previously.

#### Warnings

```javascript
noble.on('warning', callback(message));
```

#### Peripheral

##### Connected

```javascript
peripheral.once('connect', callback);
```

##### Disconnected:

```javascript
peripheral.once('disconnect', callback);
```

##### RSSI update

```javascript
peripheral.once('rssiUpdate', callback(rssi));
```

##### Services discovered

```javascript
peripheral.once('servicesDiscover', callback(services));
```

#### Service

##### Included services discovered

```javascript
service.once('includedServicesDiscover', callback(includedServiceUuids));
```

##### Characteristics discovered

```javascript
characteristic = {
  uuid: "<uuid>",
   // properties: 'broadcast', 'read', 'writeWithoutResponse', 'write', 'notify', 'indicate', 'authenticatedSignedWrites', 'extendedProperties'
  properties: [...]
};

service.once('characteristicsDiscover', callback(characteristics));
```

#### Characteristic

##### Data

Emitted when characteristic read has completed, result of ```characteristic.read(...)``` or characteristic value has been updated by peripheral via notification or indication - after having been enabled with ```notify(true[, callback(error)])```.

```javascript
characteristic.on('data', callback(data, isNotification));

characteristic.once('read', callback(data, isNotification)); // legacy
```

**Note:** `isNotification` event parameter value MAY be `undefined` depending on platform support. The parameter is **deprecated** after version 1.8.1, and not supported when on macOS High Sierra and later.

##### Write

Emitted when characteristic write has completed, result of ```characteristic.write(...)```.

```javascript
characteristic.once('write', withoutResponse, callback());
```

##### Broadcast

Emitted when characteristic broadcast state changes, result of ```characteristic.broadcast(...)```.

```javascript
characteristic.once('broadcast', callback(state));
```

##### Notify

Emitted when characteristic notification state changes, result of ```characteristic.notify(...)```.

```javascript
characteristic.once('notify', callback(state));
```

##### Descriptors discovered

```javascript
descriptor = {
  uuid: '<uuid>'
};

characteristic.once('descriptorsDiscover', callback(descriptors));
```

#### Descriptor

##### Value read

```javascript
descriptor.once('valueRead', data);
```

##### Value write

```javascript
descriptor.once('valueWrite');
```

