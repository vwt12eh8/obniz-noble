let Noble = require('./lib/noble');
let bindings = require('./lib/obniz-hci-socket/bindings');
let nobles = {};

function idFilter(obnizId) {
  let str = "" + obnizId;
  return str.split("-").join("");
}

const obnizNoble = (obnizId, params, obnizClass) => {
  let id = idFilter(obnizId);
  let obniz = obnizClass;
  if (obnizClass === undefined) obniz = require('obniz');
  if (!nobles[id]) {
    let bind = new bindings(obnizId, params, obniz);
    nobles[id] = new Noble(bind);
    nobles[id].obniz = bind._obniz;
  }

  return nobles[id];
};

module.exports = obnizNoble;
