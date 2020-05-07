var debug = require('debug')('smp');

var events = require('events');
var util = require('util');

var crypto = require('./crypto');

var SMP_CID = 0x0006;

var SMP_PAIRING_REQUEST = 0x01;
var SMP_PAIRING_RESPONSE = 0x02;
var SMP_PAIRING_CONFIRM = 0x03;
var SMP_PAIRING_RANDOM = 0x04;
var SMP_PAIRING_FAILED = 0x05;
var SMP_ENCRYPT_INFO = 0x06;
var SMP_MASTER_IDENT = 0x07;

var Smp = function (aclStream, localAddressType, localAddress, remoteAddressType, remoteAddress) {
  this._aclStream = aclStream;
  this._stk = new Buffer([]);
  this._ltk = new Buffer([]);
  this._iat = new Buffer([(localAddressType === 'random') ? 0x01 : 0x00]);
  this._ia = new Buffer(localAddress.split(':').reverse().join(''), 'hex');
  this._rat = new Buffer([(remoteAddressType === 'random') ? 0x01 : 0x00]);
  this._ra = new Buffer(remoteAddress.split(':').reverse().join(''), 'hex');

  this.onAclStreamDataBinded = this.onAclStreamData.bind(this);
  this.onAclStreamEndBinded = this.onAclStreamEnd.bind(this);

  this._aclStream.on('data', this.onAclStreamDataBinded);
  this._aclStream.on('end', this.onAclStreamEndBinded);
};

util.inherits(Smp, events.EventEmitter);

Smp.prototype.sendPairingRequest = function (options) {
  this._options = options;

  if (this.isPasskeyMode()) {
    this._preq = Buffer.from([
      SMP_PAIRING_REQUEST,
      0x02, // IO capability: Keyboard
      0x00, // OOB data: Authentication data not present
      0x05, // Authentication requirement: Bonding - MITM
      0x10, // Max encryption key size
      0x00, // Initiator key distribution: <none>
      0x01, // Responder key distribution: EncKey
    ]);
  } else {
    this._preq = Buffer.from([
      SMP_PAIRING_REQUEST,
      0x03, // IO capability: NoInputNoOutput
      0x00, // OOB data: Authentication data not present
      0x01, // Authentication requirement: Bonding - No MITM
      0x10, // Max encryption key size
      0x00, // Initiator key distribution: <none>
      0x01, // Responder key distribution: EncKey
    ]);
  }
  this.write(this._preq);
};

Smp.prototype.onAclStreamData = function (cid, data) {
  if (cid !== SMP_CID) {
    return;
  }

  var code = data.readUInt8(0);

  if (SMP_PAIRING_RESPONSE === code) {
    this.handlePairingResponse(data);
  } else if (SMP_PAIRING_CONFIRM === code) {
    this.handlePairingConfirm(data);
  } else if (SMP_PAIRING_RANDOM === code) {
    this.handlePairingRandom(data);
  } else if (SMP_PAIRING_FAILED === code) {
    this.handlePairingFailed(data);
  } else if (SMP_ENCRYPT_INFO === code) {
    this.handleEncryptInfo(data);
  } else if (SMP_MASTER_IDENT === code) {
    this.handleMasterIdent(data);
  }
};

Smp.prototype.onAclStreamEnd = function () {
  this._aclStream.removeListener('data', this.onAclStreamDataBinded);
  this._aclStream.removeListener('end', this.onAclStreamEndBinded);

  this.emit('end');
};

Smp.prototype.handlePairingResponse = function (data) {
  this._pres = data;


  if (this.isPasskeyMode()) {

    this._options.passkeyCallback( (passkeyNumber)=> {
      const passkey = new Array(16);
      for (let i = 0; i < 3; i++) {
        passkey[i] = (passkeyNumber >> (i * 8)) & 0xff;
      }

      this._tk = Buffer.from(passkey);

      this._r = crypto.r();

      this.write(Buffer.concat([
        new Buffer([SMP_PAIRING_CONFIRM]),
        crypto.c1(this._tk, this._r, this._pres, this._preq, this._iat, this._ia, this._rat, this._ra)
      ]));
    });

  } else {
    this._tk = Buffer.from("00000000000000000000000000000000", "hex");

    this._r = crypto.r();

    this.write(Buffer.concat([
      new Buffer([SMP_PAIRING_CONFIRM]),
      crypto.c1(this._tk, this._r, this._pres, this._preq, this._iat, this._ia, this._rat, this._ra)
    ]));
  }


};

Smp.prototype.handlePairingConfirm = function (data) {
  this._pcnf = data;

  this.write(Buffer.concat([
    new Buffer([SMP_PAIRING_RANDOM]),
    this._r
  ]));
};

Smp.prototype.handlePairingRandom = function (data) {
  var r = data.slice(1);

  var pcnf = Buffer.concat([
    new Buffer([SMP_PAIRING_CONFIRM]),
    crypto.c1(this._tk, r, this._pres, this._preq, this._iat, this._ia, this._rat, this._ra)
  ]);

  if (this._pcnf.toString('hex') === pcnf.toString('hex')) {
    this._stk = crypto.s1(this._tk, r, this._r);

    this.emit('stk', this._stk);
  } else {
    this.write(new Buffer([
      SMP_PAIRING_RANDOM,
      SMP_PAIRING_CONFIRM
    ]));

    this.emit('fail');
  }
};

Smp.prototype.handlePairingFailed = function (data) {
  this.emit('fail');
};

Smp.prototype.handleEncryptInfo = function (data) {
  this._ltk = data.slice(1);

  this.emit('ltk', this._ltk);
};

Smp.prototype.handleMasterIdent = function (data) {
  var ediv = data.slice(1, 3);
  var rand = data.slice(3);

  this.emit('masterIdent', ediv, rand);
};

Smp.prototype.write = function (data) {
  this._aclStream.write(SMP_CID, data);
};


Smp.prototype.setKeys = function (keyStringBase64) {
  const keyString = Buffer.from(keyStringBase64, "base64").toString("ascii");
  const keys = JSON.parse(keyString);
  this._stk = Buffer.from(keys.stk);
  this._preq = Buffer.from(keys.preq);
  this._pres = Buffer.from(keys.pres);
  this._tk = Buffer.from(keys.tk);
  this._r = Buffer.from(keys.r);
  this._pcnf = Buffer.from(keys.pcnf);
  this._ltk = Buffer.from(keys.ltk);
}

Smp.prototype.getKeys = function () {
  const keys = {
    stk: this._stk.toString("hex"),
    preq: this._preq.toString("hex"),
    pres: this._pres.toString("hex"),
    tk: this._tk.toString("hex"),
    r: this._r.toString("hex"),
    pcnf: this._pcnf.toString("hex"),
    ltk: this._ltk.toString("hex"),
  };
  const jsonString = JSON.stringify(keys);
  const keyString = Buffer.from(jsonString, "ascii").toString("base64");
  return keyString;
}

Smp.prototype.isPasskeyMode = function () {
  if (this._options && this._options.passkeyCallback) {
    return true;
  }
  return false;
}
module.exports = Smp;
