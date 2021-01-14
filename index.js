let Noble = require('./lib/noble');
let Obniz = require('obniz');
let bindings = require('./lib/obniz-hci-socket/bindings');
let nobles = {};

function idFilter(obnizId) {
  let str = "" + obnizId;
  return str.split("-").join("");
}

const obnizNoble = (obnizId, params) => {
  let id = idFilter(obnizId);
  if (!nobles[id]) {
    let bind = new bindings(obnizId, params);
    nobles[id] = new Noble(bind);
    nobles[id].obniz = bind._obniz;
  }

  return nobles[id];
};


obnizNoble.Obniz = Obniz;

module.exports = obnizNoble;
