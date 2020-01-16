
var obnizNoble =  require('./index');
var noble = obnizNoble("54371148");


console.log('noble');

noble.on('stateChange', function(state) {
  console.log('on -> stateChange: ' + state);

  if (state === 'poweredOn') {
    noble.startScanning();
  } else {
    noble.stopScanning();
  }
});

noble.on('scanStart', function() {
  console.log('on -> scanStart');
});

noble.on('scanStop', function() {
  console.log('on -> scanStop');
});



noble.on('discover', function(peripheral) {
  console.log('on -> discover: ' + peripheral);
  if(!peripheral.advertisement.localName
      || !peripheral.advertisement.localName.startsWith("MESH-100LE1002073")){
    return;
  }
  console.log("find");

  noble.stopScanning();

  peripheral.connect(function(err) {
    //
    // Once the peripheral has been connected, then discover the
    // services and characteristics of interest.
    //
    peripheral.discoverServices(["72C90001-57A9-4D40-B746-534E22EC9F9E"], function(err, services) {
      services.forEach(function(service) {
        //
        // This must be the service we were looking for.
        //
        console.log('found service:', service.uuid);

        //
        // So, discover its characteristics.
        //
        service.discoverCharacteristics(["72C90002-57A9-4D40-B746-534E22EC9F9E"], function(err, characteristics) {

          characteristics.forEach(function(characteristic) {
            //
            // Loop through each characteristic and match them to the
            // UUIDs that we know about.
            //
            console.log('found characteristic:', characteristic.uuid);
            characteristic.write(Buffer.from([0x01 ,0x00,0x0c,0x00,0x0c,0x00,0x0c,0x64,0x00,0x64,0x00,0x00,0x00,0x01,0xee]));

            // if (pizzaCrustCharacteristicUuid == characteristic.uuid) {
            //   pizzaCrustCharacteristic = characteristic;
            // }
            // else if (pizzaToppingsCharacteristicUuid == characteristic.uuid) {
            //   pizzaToppingsCharacteristic = characteristic;
            // }
            // else if (pizzaBakeCharacteristicUuid == characteristic.uuid) {
            //   pizzaBakeCharacteristic = characteristic;
            // }
          })

          //
          // Check to see if we found all of our characteristics.
          //
          if (pizzaCrustCharacteristic &&
              pizzaToppingsCharacteristic &&
              pizzaBakeCharacteristic) {
            //
            // We did, so bake a pizza!
            //
            bakePizza();
          }
          else {
            console.log('missing characteristics');
          }
        })
      })
    })
  })


  //
  // peripheral.on('connect', function() {
  //   console.log('on -> connect');
  //   this.updateRssi();
  //   // this.discoverServices();
  // });

  peripheral.on('disconnect', function() {
    console.log('on -> disconnect');
  });

  peripheral.on('rssiUpdate', function(rssi) {
    console.log('on -> RSSI update ' + rssi);
    this.discoverServices();
  });

  peripheral.on('servicesDiscover', function(services) {
    console.log('on -> peripheral services discovered ' + services);

    var serviceIndex = 0;

    services[serviceIndex].on('includedServicesDiscover', function(includedServiceUuids) {
      console.log('on -> service included services discovered ' + includedServiceUuids);
      this.discoverCharacteristics();
    });

    services[serviceIndex].on('characteristicsDiscover', function(characteristics) {
      console.log('on -> service characteristics discovered ' + characteristics);

      var characteristicIndex = 0;

      characteristics[characteristicIndex].on('read', function(data, isNotification) {
        console.log('on -> characteristic read ' + data + ' ' + isNotification);
        console.log(data);

        peripheral.disconnect();
      });

      characteristics[characteristicIndex].on('write', function() {
        console.log('on -> characteristic write ');

        peripheral.disconnect();
      });

      characteristics[characteristicIndex].on('broadcast', function(state) {
        console.log('on -> characteristic broadcast ' + state);

        peripheral.disconnect();
      });

      characteristics[characteristicIndex].on('notify', function(state) {
        console.log('on -> characteristic notify ' + state);

        peripheral.disconnect();
      });

      characteristics[characteristicIndex].on('descriptorsDiscover', function(descriptors) {
        console.log('on -> descriptors discover ' + descriptors);

        var descriptorIndex = 0;

        descriptors[descriptorIndex].on('valueRead', function(data) {
          console.log('on -> descriptor value read ' + data);
          console.log(data);
          peripheral.disconnect();
        });

        descriptors[descriptorIndex].on('valueWrite', function() {
          console.log('on -> descriptor value write ');
          peripheral.disconnect();
        });

        descriptors[descriptorIndex].readValue();
        //descriptors[descriptorIndex].writeValue(new Buffer([0]));
      });


      // characteristics[characteristicIndex].read();
      // characteristics[characteristicIndex].write(new Buffer([01:00:0c:00:0c:00:0c:64:00:64:00:00:00:01:ee]));
      //characteristics[characteristicIndex].broadcast(true);
      //characteristics[characteristicIndex].notify(true);
      // characteristics[characteristicIndex].discoverDescriptors();
    });


    services[serviceIndex].discoverIncludedServices();
  });

  peripheral.connect();
});

