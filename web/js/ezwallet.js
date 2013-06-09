(function($){

    var gen_from = 'pass';
    var gen_compressed = false;
    var gen_eckey = null;
    var gen_pt = null;
    var gen_ps_reset = false;
    var TIMEOUT = 600;
    var timeout = null;

// Me - added these for the fast generation wallet
    var Seed = {}
    var Keys = {}
    var Unspent = {}
    var Bal = {}
    var TotBal = 0  // this is ReadyBal + PendingBal
    var PendingBal = 0  // this is amount we received but not yet confirmed
    var ReadyBal = 0  // this is the confirmed amount we received and ready to spend
    var WsizeDefault = 10
    var WsizeMax = 100
    var G = {}
    var UI = {}
    var WaitingIcon = "<img src='img/wait.gif' border=0 align=left>"

    function parseBase58Check(address) {
        var bytes = Bitcoin.Base58.decode(address);
        var end = bytes.length - 4;
        var hash = bytes.slice(0, end);
        var checksum = Crypto.SHA256(Crypto.SHA256(hash, {asBytes: true}), {asBytes: true});
        if (checksum[0] != bytes[end] ||
            checksum[1] != bytes[end+1] ||
            checksum[2] != bytes[end+2] ||
            checksum[3] != bytes[end+3])
                throw new Error("Wrong checksum");
        var version = hash.shift();
        return [version, hash];
    }

    encode_length = function(len) {
        if (len < 0x80)
            return [len];
        else if (len < 255)
            return [0x80|1, len];
        else
            return [0x80|2, len >> 8, len & 0xff];
    }
    
    encode_id = function(id, s) {
        var len = encode_length(s.length);
        return [id].concat(len).concat(s);
    }

    encode_integer = function(s) {
        if (typeof s == 'number')
            s = [s];
        return encode_id(0x02, s);
    }

    encode_octet_string = function(s)  {
        return encode_id(0x04, s);
    }

    encode_constructed = function(tag, s) {
        return encode_id(0xa0 + tag, s);
    }

    encode_bitstring = function(s) {
        return encode_id(0x03, s);
    }

    encode_sequence = function() {
        sequence = [];
        for (var i = 0; i < arguments.length; i++)
            sequence = sequence.concat(arguments[i]);
        return encode_id(0x30, sequence);
    }

    function getEncoded(pt, compressed) {
       var x = pt.getX().toBigInteger();
       var y = pt.getY().toBigInteger();
       var enc = integerToBytes(x, 32);
       if (compressed) {
         if (y.isEven()) {
           enc.unshift(0x02);
         } else {
           enc.unshift(0x03);
         }
       } else {
         enc.unshift(0x04);
         enc = enc.concat(integerToBytes(y, 32));
       }
       return enc;
    }

    function getDER(eckey, compressed) {
        var curve = getSECCurveByName("secp256k1");
        var _p = curve.getCurve().getQ().toByteArrayUnsigned();
        var _r = curve.getN().toByteArrayUnsigned();
        var encoded_oid = [0x06, 0x07, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x01, 0x01];

        var secret = integerToBytes(eckey.priv, 32);
        var encoded_gxgy = getEncoded(curve.getG(), compressed);
        var encoded_pub = getEncoded(gen_pt, compressed);

        return encode_sequence(
            encode_integer(1),
            encode_octet_string(secret),
            encode_constructed(0,
                encode_sequence(
                    encode_integer(1),
                    encode_sequence(
                        encoded_oid, //encode_oid(*(1, 2, 840, 10045, 1, 1)), //TODO
                        encode_integer([0].concat(_p))
                    ),
                    encode_sequence(
                        encode_octet_string([0]),
                        encode_octet_string([7])
                    ),
                    encode_octet_string(encoded_gxgy),
                    encode_integer([0].concat(_r)),
                    encode_integer(1)
                )
            ),
            encode_constructed(1, 
                encode_bitstring([0].concat(encoded_pub))
            )
        );
    }

    function pad(str, len, ch) {
        padding = '';
        for (var i = 0; i < len - str.length; i++) {
            padding += ch;
        }
        return padding + str;
    }

    function setErrorState(field, err, msg) {
        group = field.closest('.control-group');

        if (err) {
            group.addClass('error');
        } else {
            group.removeClass('error');
        }

        var e = group.find('.errormsg');
        if (e) {
            e.text(msg||'');
        }
    }

// --- util functions ---

// removes spaces, tabs, form feed and new line 
// characters, ' ', '\t', '\r', '\n'
    function removeWhiteSpace(s){ return s.replace(/\s/g, '') }

// removes white spaces from ends and squeeze white spaces in the 
// middle to just one
    function trimWhiteSpace(s){ 
        return s.replace(/\s+/g, ' ').replace(/^\s/, '').replace(/\s$/, '') 
    }

// return a random hex string
function randomHex32(){ return bytes2hex(Crypto.util.randomBytes(32)); }

// given a decimal float as string return a big int
function str2bigInt(s){ return Bitcoin.Util.parseValue(s) }

// given a hex string return a big int
function hex2bigInt(s){ return new BigInteger(removeWhiteSpace(s), 16); }

// given a big int return a hex string
function bigInt2hex(i){ return i.toString(16); }

// given a big int return a big int that is in the range of a valid private key
// makes sure that the big int is not greater than the max valid private key
// The priviate key is a 32 byte number in the range of 0 to N where N is defined by the secp256k1 ECDSA standard
//      See https://en.bitcoin.it/wiki/Private_key
function bigInt2bigIntKey(i){ return i.mod(getSECCurveByName("secp256k1").getN()); }

// given a hex string converts it to a big int in the valid private key range
function hex2bigIntKey(s){ return bigInt2bigIntKey(hex2bigInt(removeWhiteSpace(s))); }

// given a byte array return a hex string
function bytes2hex(b){ return Crypto.util.bytesToHex(b); }

// given a hex string return a byte array
function hex2bytes(s){ return Crypto.util.hexToBytes(s); }

// given a hex string return a base64 string
function hex2base64(s){ return Crypto.util.bytesToBase64(hex2bytes(s)) }

// given a base64 string convert it to a hes string
function base642hex(s){ return bytes2hex(Crypto.util.base64ToBytes(s)) }

// given a base 58 string convert it to a hex string
function base582hex(s){ 
  var res, bytes
  try { res = parseBase58Check(s); bytes = res[1]; } 
  catch (err) { bytes = Bitcoin.Base58.decode(s); }
  return bytes2hex(bytes) 
}

// given any string returns a hex string of 32 bytes (256 bits)
function hash256(s){ return bytes2hex(new Crypto.SHA256(s, {asBytes:true})); }

// given a hex string converts it to a hex string in the valid private key range
function hex2hexKey(s){ return bigInt2hex(hex2bigIntKey(removeWhiteSpace(s))); }

// given the seed (in hex) and key number or string, returns the private key (in hex)
function seed2key(pk, c){ return hex2hexKey(hash256(pk+c)); }

// given a key as a big int return the EC object for that key
function bigInt2ECKey(i){ return new Bitcoin.ECKey(bigInt2bigIntKey(i)); }

// given the private key (in hex) returns the public key (in hex)
//function key2pubKey(k){  return bigInt2hex(bigInt2ECKey(hex2bigInt(k)).getPub()); }
function key2pubKey(k){  return bytes2hex(bigInt2ECKey(hex2bigInt(k)).getPub()); }

// given the private key in hex and a hash in hex, returns the signed hash in hex
function hash2sign(h, k){ return  bytes2hex(bigInt2ECKey(hex2bigInt(k)).sign(hex2bytes(h))); }

// given a hash in hex, a signature in hex and the public key in hex return 1 if the hash and signature match
function verifySign(h, s, k){ return Bitcoin.ECDSA.verify(hex2bytes(h), hex2bytes(s), hex2bytes(k)) }

// given a signature in hex and the public key in hex, use the hash of the public key for the hash and return 1 if the hash and signature match
function verifySpend(s, k){ return Bitcoin.ECDSA.verify(hex2bytes(h), hex2bytes(s), hex2bytes(k)) }

// given a public key in hex return the bitcoin hash of the public key in hex
function pubKey2pubKeyHash(k){ return bytes2hex(Bitcoin.Util.sha256ripe160(hex2bytes(k))); }

// given the bitcoin hash of a public key in hex return the bitcoin address
function pubKeyHash2bitAdd(k){
  var b = new Bitcoin.Address(hex2bytes(k));
  return b.toString();
}

// given a public key in hex return the base64 bitcoin address
function pubKey2bitAdd(k){
  var b = new Bitcoin.Address(hex2bytes(pubKey2pubKeyHash(k)));
  return b.toString()
}

// given a private key in hex return the base64 bitcoin address
function key2bitAdd(k){ return pubKey2bitAdd(key2pubKey(k)) }

// given a ScriptPubKey as a string convert it to bytes
function parseScript(script) {
        var newScript = new Bitcoin.Script();
        var s = script.split(" ");
        for (var i in s) {
                if (Bitcoin.Opcode.map.hasOwnProperty(s[i])){
                        newScript.writeOp(Bitcoin.Opcode.map[s[i]]);
                } else {
                        newScript.writeBytes(Crypto.util.hexToBytes(s[i]));
                }
        }
        return newScript;
}

// given a ScriptHex as a string convert it to bytes
function parseScriptHex_old(script) {
        var newScript = new Bitcoin.Script();
//      newScript.writeBytes(Crypto.util.hexToBytes(script)[3:17]);
        var b = Crypto.util.hexToBytes(script)
        newScript.writeOp(b[0]);
        newScript.writeOp(b[1]);
        newScript.writeBytes(b.slice(3,23));
        newScript.writeOp(b[23]);
        newScript.writeOp(b[24]);
        return newScript;
}

// given a ScriptHex as a string convert it to ScriptPubKey format
function parseScriptHex(script) {
        var b = Crypto.util.hexToBytes(script)
        var newScript = new Bitcoin.Script(b);
// the dumpScript() comes from tx.js
        var d = dumpScript(newScript)
        return d;
}

// reverse a string two bytes at a time
//  123456   would become
//  563412   - this is applied to the transaction hash
function endian(string) {
        var out = []
        for(var i = string.length; i > 0; i-=2) {
                out.push(string.substring(i-2,i));
        }
//      console.debug(string);
//      console.debug(out.join(""));
        return out.join("");
}

// given a number (float or int) return the number
// use round instead of floor so that we don't lose small amounts due to floating percision
function num2sathoshi(f){ return Math.round(f*100000000.0) }

// given a number (float or int) return the number
function sathoshi2num(f){ return f/100000000.0 }

// given an integer return a bit int
function int2bigInt(n){ return new BigInteger(n.toString())}

// given a number (float or int) return it in satoshi as big int
function num2sathoshiBigInt(n){ return int2bigInt(num2sathoshi(n)) }

// given a string return an array of words in the string
function str2wordArr(s){
  var r = []
  if (typeof(s) != 'string'){ return r }
  s = s.replace(/^\s+/, '').replace(/\s+$/, '')
  if (s == ''){ return r }
  r = s.split(/\s+/)
  return r
}

// no easy way to select the text in a div or span
//   found this here: http://coderzone.org/library/Select-text-in-a-DIV-SPAN-or-table-cell_1047.htm
function selectText(objId) {
  deSelectText()
  if (document.selection) {
    var range = document.body.createTextRange();
    range.moveToElementText(document.getElementById(objId));
    range.select();
  }
  else if (window.getSelection) {
    var range = document.createRange();
    range.selectNode(document.getElementById(objId));
    window.getSelection().addRange(range);
  }
}

function deSelectText() {
  if (document.selection) document.selection.empty(); 
  else if (window.getSelection)
  window.getSelection().removeAllRanges();
}



// from - a string of zero or more addresses seperated by space; 
//        the provided addresses will be used before picking other addresses to meet the amount+fee
//        "" or "address1" or "address1 address2 ..."
// to - a string of one or more address and amount pairs (seperated by space) sperated by space; 
//        "address amount" or "address1 amount1 address2 amount2 ..."
// change - a string of zero or one address to return excess change;
//        if not provided then the change is returned to the first from address given
//        or the first picked address if the from address was not given
// fee - a float or int or empty string which specifies the amount to pay in transaction fees
//        "" or "0" or "4" or "2.4"
function makeTxObj(from, to, change, fee){
  var fa, ta, feeTot, amtTot, th, tha, i, adr, amt, amtFloat, amtTot, traz, tra, fundTot, returnTot
  var sendTx, sentTot, amountBigInt, toAddr, hashType, inCount, tr, script, hash, tx, signHash, key, sign
  var pkh, pk

  fa = str2wordArr(from)
  ta = str2wordArr(to)
//  if (ta.length < 1){ alert('Please complete the form.'); return }
  if (ta.length < 2){ alert('Please complete the form.'); return }
  change = trimWhiteSpace(change)
  if ((fee == undefined) || (fee == '')){ fee = '0' }
//  fee = fee.replace(/[^\d\.]/g, '')  
  if (fee == ''){ fee = 0 }
  feeFloat = parseFloat(fee)
  amtTot = feeFloat
// go through the to addresses and amounts and put them in th
  th = []
  tha = []  
  for(i=0;i<ta.length;i+=2){
    adr = ta[i]
    amt = ta[i+1].replace(/[^\d\.]/g, '')
    if (amt == ''){ amt = '0' }
    amtFloat = parseFloat(amt)
    amtTot += amtFloat
    th[adr] = amtFloat
    tha.push(adr)
  }
  if (amtTot<=0.0){ alert('Amount must be greater than 0.'); return }
  
// get a list of unspent transaction we can send from; make sure the from address isn't also a to address
  traz = bitAddArr2transRefArr(fa, amtTot, tha)

  if (traz == 0){ alert('Insufficient funds.'); return }
  tra = traz[0]
  fundTot = traz[1]
  returnTot = fundTot - amtTot
  returnTot = sathoshi2num(num2sathoshi(returnTot))

  sendTx = new Bitcoin.Transaction()
// create the outputs
  sentTot = 0.0
  for(adr in th){
    amt = th[adr]
    amountBigInt = num2sathoshiBigInt(amt)
    toAddr = new Bitcoin.Address(adr)
    sendTx.addOutput(toAddr, amountBigInt)
    sentTot += amt
// add the address so it is easy to see on the debug page
    sendTx.outs[sendTx.outs.length-1].address = adr
  }
  if (returnTot>0){
    amountBigInt = num2sathoshiBigInt(returnTot)
    if (change == ''){
      if (fa.length > 0){ adr = fa[0] }
      else{ adr = tra[0].address }
    }
    else{ adr = change }
//alert(JSON.stringify(tra, '', '  '))
    toAddr = new Bitcoin.Address(adr)
    sendTx.addOutput(toAddr, amountBigInt)
// add the address so it is easy to see on the debug page
    sendTx.outs[sendTx.outs.length-1].address = adr
  }
//console.log(JSON.stringify(sendTx, '', '  '))

// create the inputs
//   we have to do this in two loop instead of one loop, otherwise it does not work
//   all the inputs have to be created before they are signed.
//   The signing looks at the whole transaction.

  hashType = 1   // SIGHASH_ALL
  for(i in tra){
    tr = tra[i]
// the script can be provided as scriptPubKey or scriptHex
    if (typeof(tr.scriptPubKey) == 'string'){
      script = parseScript(tr.scriptPubKey)
    }
    if (typeof(tr.scriptHex) == 'string'){
      script = parseScriptHex(tr.scriptHex)
      script = parseScript(script)
//console.debug('script is '+script+'\n')
//console.debug('script is '+JSON.stringify(script,'','  ')+'\n')
    }
    hash = hex2base64(endian(tr.transHash))
    tx = new Bitcoin.TransactionIn({outpoint: {hash: hash, index: tr.n}, script: script, sequence: 4294967295})
    sendTx.addInput(tx)
  }

// now sign the input in the second loop
//console.log(JSON.stringify(tra, '', '  '))
  inCount = 0
  for(i in tra){
    script = sendTx.ins[inCount].script;
    signHash = sendTx.hashTransactionForSignature(script, inCount, hashType)
//console.debug(signHash+'\n')
    key = bigInt2ECKey(hex2bigInt(Keys[tr.address]))
    pkh = script.simpleOutPubKeyHash()
    sign = key.sign(signHash)
    sign.push(parseInt(hashType, 10))
    pk = key.getPub()
    sendTx.ins[inCount].script = Bitcoin.Script.createInputScript(sign, pk)
// add this just so we can easily see what address was used to send from
    sendTx.ins[inCount].address = tra[inCount].address
    sendTx.ins[inCount].value = tra[inCount].value
    inCount += 1
  }
//console.log(JSON.stringify(sendTx, '', '  '))

//jd = JSON.stringify(sendTx,'','   ')
//alert(jd)
//showit(Bitcoin.Transaction.objectify([sendTx]))

  return sendTx;

}

// given an array of bitcoin addresses and an amount, return a list of
//    transaction references which have a total value greater then or
//    equal to the given amount and which use older transactions first
//    while trying to use the given addresses before other address.
//    Do you get what I mean; probably not. Just read the code :-)
// we are also given a list of the addresses not to use in 'tha'
function bitAddArr2transRefArr(baa, amount, tha){
  var save, res, tot, i, t, ta
  save = []
  res = []
  tot = 0.0
// first sort the unspent transactions with the oldest first
// but skip unconfirmed transactions; where block=0
  for(i in Unspent){
    t = Unspent[i]
//    ta = t.address
    if (t.block > 0){
      save.push(t)
    }
  }
  save.sort(compareBlockDesc)
  // try to pick from the given bitcoin addresses
  for (i in save){
    t = save[i]
    ta = t.address
    if (baa.indexOf(ta)>=0){
      res.push(t)
      tot += parseFloat(t.value)
      if (tot >= amount){ return [res, tot] }
    }
  }
  // now pick from the other addresses, since the given address did not have enough
  for (i in save){
    t = save[i]
    ta = t.address
    if (tha.indexOf(ta) >= 0){ continue; } // skip it if the address is in the don't use list
    if (baa.indexOf(ta)<0){
      res.push(t)
      tot += parseFloat(t.value)
      if (tot >= amount){ break }
    }
  }
  if (tot < amount){ return 0 }
  // now remove any excess that we picked up
  //   for example we needed to send 10, we picked up 1, 2, then 12, so we don't need
  //   the 1 and 2 since 12 has enough. To remove them reverse the order and go through
  //   until we have enough and any left after than can be removed.
  res = res.reverse()
  tot = 0.0
  enough = 0
  i = 0
  for (i=0; i<res.length; i++){
    t = res[i]
    tot += parseFloat(t.value)
    if (tot >= amount){ 
      i += 1
      if (i<res.length){
        res.splice(i)
        break
      }
    }
  }
  return [res, tot]
}

function compareBlockDesc(a, b){
  return (parseInt(b.block) - parseInt(a.block))
}




    // --- Home ---

    function homeOpenWallet(){
        var wn, wp, i, k1, p1, b1, s
// if the home wallet is still open, warn and close it before opening new wallet
        if (! $.isEmptyObject(Keys)){
          a = confirm('Close the currently open wallet?')
          if (! a){ return }
          advancedCloseWallet()
        }
        G.email = removeWhiteSpace($('#homeEmail').val().toLowerCase())
        G.pin = $('#homeSessionPin').val()
// we don't hold wallet name or wallet pass in memory
        wn = trimWhiteSpace($('#homeWalletName').val().toLowerCase())
        wp = $('#homeWalletPassword').val()
        if (G.email == ''){ alert("Enter email."); return }
        if (wn == ''){ alert("Enter wallet name."); return }
        if (wp == ''){ alert("Enter wallet password."); return }
        Seed.master = hash256(G.email+wn+wp+'master')
        Seed.main = hash256(Seed.master+'main')
        Wsize = WsizeDefault
        for(i=0; i<Wsize; i++){
          k1 = seed2key(Seed.main, i)
          p1 = key2pubKey(k1)
          b1 = pubKey2bitAdd(p1)
          Keys[b1] = k1
          Bal[b1] = 0.0
        }
        $('#homeOpenForm').hide()
        $('#homeMainForm').show()
        $('#homeEmail').val('')
        $('#homeWalletName').val('')
        $('#homeWalletPassword').val('')
        $('#homeSessionPin').val('')
        $('#debugKeys').val(JSON.stringify(Keys, '', '  '))
        homeUpdateBalance()
    }

    function homeCloseWalletAsk(){
        var a = confirm('Close the EZ wallet?')
        if (! a){ return }
        homeCloseWallet()
    }

    function homeCloseWallet(){
        var s
        G = {};
        Keys = {}
        Seed = {}
        Unspent = {}
        Bal = {}
        TotBal = 0
        PendingBal = 0
        ReadyBal = 0
        $('#homeMainForm').hide()
        $('#homeSendForm').hide()
        $('#homeReceiveForm').hide()
        $('#homeOpenForm').show()
    }

    function homeSendForm(){
        $('#homeSendForm').show()
        $('#homeMainForm').hide()
    }

    function homeSendByAddressForm(){
        $('#homeSendMessageDiv').hide()
        $('#homeSendPasswordDiv').hide()
        $('#homeSendToEmailDiv').hide()
        $('#homeSendFromEmailDiv').hide()
        $('#homeSendToDiv').show()
        UI.sendBy = 'address'
    }

    function homeSendByEmailForm(){
        $('#homeSendMessageDiv').show()
        $('#homeSendPasswordDiv').show()
        $('#homeSendToEmailDiv').show()
        $('#homeSendFromEmailDiv').show()
        $('#homeSendFromEmail').html(G.email)
        $('#homeSendToDiv').hide()
        UI.sendBy = 'email'
    }

    function homeSendCodeDone(){
        $('#homeSendCodeForm').hide()
        $('#homeMainForm').show()
    }

    function homeScan(){
        var r
        alert('Currently only these browsers support this feature:\n  on PC, Chrome and Opera;\n  on mobile, Opera v12.')
        var opts = {
            fps: 4,
            width: 320,
            height: 240
        }
        $('#qrscanText').html('')
        $('#qrscanImage').html('')
        Miniqr.reader(homeScanVideoPass, homeScanVideoFail, homeScanCodePass, homeScanCodeFail, opts)
    }

    function homeScanClose(){
        $('#homeSendForm').show()
        $('#qrscanForm').hide()
        Miniqr.stop()
        $('#qrscanText').html('')
        $('#qrscanImage').html('')
    }

    function homeScanVideoPass(video, stream){
        $('#qrscanForm').show()
        $('#homeSendForm').hide()
        $('#qrscanImage').html(video)
    }

    function homeScanVideoFail(error){
        if (error == undefined){ return }
        if (error.message != undefined){ alert(error.message) }
//        $('#qrscanText').html('Could not access the webcam.')
    }

    function homeScanCodePass(code){
        $('#homeSendTo').val(code)
        homeScanClose()
    }

    function homeScanCodeFail(error){
//        $('#qrscanText').html('Could not read the QR code.')
    }


    function homeReceiveForm(){
        $('#homeReceiveForm').show()
        $('#homeSendForm').hide()
        $('#homeMainForm').hide()
    }

    function homeRedeemForm(){
        $('#homeRedeemForm').show()
        $('#homeMainForm').hide()
    }

    function homeRedeemCancel(){
        $('#homeMainForm').show()
        $('#homeRedeemForm').hide()
    }

    function homeRedeemNow(){
alert('about to redeem now')
        $('#homeMainForm').show()
        $('#homeRedeemForm').hide()
    }

    function homeRecoverForm(){
        $('#homeRecoverForm').show()
        $('#homeMainForm').hide()
    }

    function homeRecoverCancel(){
        $('#homeMainForm').show()
        $('#homeRecoverForm').hide()
    }

    function homeSendCancel(){
        $('#homeMainForm').show()
        $('#homeSendForm').hide()
    }

    function homeReceiveBack(){
        $('#homeMainForm').show()
        $('#homeReceiveForm').hide()
    }

    function homeUpdateBalance(){
        var addrArr, addrStr, ba, s
        addrArr = []
        for(ba in Keys){
            addrArr.push(ba)
        }
        $('#homeBalanceLabel').html(WaitingIcon)
        $('#homeReceiveBalance').html(s)
        addrStr = JSON.stringify(addrArr)
        $.post('cgi-bin/unspent.py', addrStr, homeUpdateBalanceFill, 'text')
    }

    function parseUnspentData(data){
        var i, res, tr, script, sa, addr
        res = JSON.parse(data, '', '  ')
        Unspent = []
        for(i in res){
            tr = res[i]
            if ((tr.value == undefined) || (tr.value == '')){
              if (typeof(tr.sathoshi) == 'number'){
                tr.value = sathoshi2num(tr.sathoshi)
                res[i].value = tr.value
              }
            }
            if ((tr.address == undefined) || (tr.address == '')){
// try to find it from the Script
// the script can be provided as scriptPubKey or scriptHex
              if (typeof(tr.scriptPubKey) == 'string'){
                script = tr.scriptPubKey
              }
              if (typeof(tr.scriptHex) == 'string'){
                script = parseScriptHex(tr.scriptHex)
                res[i].scriptPubKey = script
//console.debug('script is '+script+'\n')
//console.debug('script is '+JSON.stringify(script,'','  ')+'\n')
              }
              sa = script.split(/ +/)
//              addr = endian(sa[2])
              addr = sa[2]
              addr = pubKeyHash2bitAdd(addr)
              tr.address = addr
              res[i].address = addr
            }
            if (Keys[tr.address] != undefined){
                Unspent[i] = res[i] // save only if we have the private key
            }
        }
        var x = JSON.stringify(res, '', '  ')
        $('#debugUnspent').val(x)
    }

    function homeUpdateBalanceFill(data){
        parseUnspentData(data) // fills the Unspent obj
        setBalance() // gets data from the Unspent obj
        homeBalanceShow()
    }

    function setBalance(){
        var i, k, t, v
        TotBal = 0.0
        PendingBal = 0.0
        ReadyBal = 0.0
        Bal = {}
        for(k in Keys){
            Bal[k] = 0.0
        }
        for(i in Unspent){
            t = Unspent[i]
            k = t.address
            if (k != undefined){
                v = 0.0
                if (typeof(t.value)=='string'){
                    v = parseFloat(t.value)
                }
                if (typeof(t.value)=='number'){
                    v = t.value
                }
                Bal[k] += v
                Bal[k] = sathoshi2num(num2sathoshi(Bal[k]))
                TotBal += v
                if (t.block > 0){
                    ReadyBal += v
                }
                else{
                    PendingBal += v
                }
            }
        }
        TotBal = sathoshi2num(num2sathoshi(TotBal))
        PendingBal = sathoshi2num(num2sathoshi(PendingBal))
        ReadyBal = sathoshi2num(num2sathoshi(ReadyBal))
    }

    function homeBalanceShow(){
        var i, b, s, c
//        s = '' + TotBal 
//        s = '<nobr>'+TotBal+' = <font color=green title="Ready to spend">'+ReadyBal+' + <font color=red title="Pending confirmation">'+PendingBal+'</nobr>'
        s = bal2html(TotBal, ReadyBal, PendingBal)
        $('#homeBalanceLabel').html(s)
        $('#homeReceiveBalance').html(s)
        $('#homeSendBalanceBefore').html(s)
        s = ''
        c = 0
        for(i in Keys){
            b = Bal[i]
            s = s +'<nobr><a href="javascript:addressShow(\''+i+'\')">'+i+' = '+b.toString()+'</a></nobr><br>'
            c += 1
        }
        $('#homeReceiveAddresses').html(s)
    }

    function addressShow(a){
        $('#qrcodeText').html(a)
        $('#qrcodeImage').html('')
        $('#qrcodeImage').qrcode(a)
        $('#qrcodeModal').modal('show')
        selectText('qrcodeText')
//alert(i)
    }
    this.addressShow = addressShow

    function homeSetBalanceAfterSend(){
        var bbal, sa, fee, ebal
        bbal = TotBal
        sa = parseFloat(removeWhiteSpace($('#homeSendAmount').val()))
        fee = parseFloat(removeWhiteSpace($('#homeSendFee').val()))
        if (isNaN(sa)){ sa = 0 }
        if (isNaN(fee)){ fee = 0 }
        ebal = bbal - sa - fee
        ebal = sathoshi2num(num2sathoshi(ebal))
        $('#homeSendBalanceAfter').html(ebal)
    }

    function homeSetRedeemInfo(){
        var code, password, fee, rawCode, info
        var dkey, redeem, rand, key, bita, addrArr, addrStr
        code = removeWhiteSpace($('#homeRedeemCode').val())
        password = trimWhiteSpace($('#homeRedeemPassword').val())
        fee = parseFloat(removeWhiteSpace($('#homeSendFee').val()))
        if (isNaN(fee)){ fee = 0 }
        try{ rawCode = AESdecrypt(code, G.email) }
        catch(e){ rawCode = '' }
        if (rawCode != ''){
            info = rawCode
            info = info.replace(/\nredeem: [\s\S]*/, '\n')
            dkey = password
            if (password == ''){ dkey = G.email }
            redeem = rawCode.match(/\nredeem: (\S*)/)[1]
            try{ rand = AESdecrypt(redeem, dkey) }
            catch(e){ rand = '' }
            if (rand != ''){ 
                key = hex2hexKey(hash256(info+rand))
                bita = key2bitAdd(key)
// now check if the bitcoins are still there
                addrArr = []
                addrArr.push(bita)
                addrStr = JSON.stringify(addrArr)
                $('#homeRedeemBalanceDiv').show()
                $('#homeRedeemBalance').html(WaitingIcon)
                $.post('cgi-bin/unspent.py', addrStr, homeRedeemBalanceFill, 'text')
            }
            else{
                if (password == ''){ info = info + '<font color=red>Password needed.</font>' }
                else{ info = info + '<font color=red>Incorrect password.</font>' }
                $('#homeRedeemBalanceDiv').hide()
            }
            $('#homeRedeemInfoDiv').show()
            $('#homeRedeemInfo').html('<pre><tt>'+info+'<tt></pre>')
        }
        else{
            $('#homeRedeemInfoDiv').show()
            $('#homeRedeemInfo').html("<pre>Code could not be deciphered.</pre>")
        }
        if (code == ''){
            $('#homeRedeemInfoDiv').hide()
        }
    }

    function homeRedeemBalanceFill(data){
        var res, unspent, bal
        res = JSON.parse(data, '', '  ')
        unspent = []
        for(i in res){
            unspent[i] = cookUnspentRec(res[i])
        }
        bal = balOfUnspentAddr(unspent)
        k = Object.keys(bal)[0]
        if (k == undefined){
            b = {}
            b.total = 0
            b.ready = 0
            b.pending = 0
        }
        else{
            b = bal[k]
        }
        s = bal2html(b.total, b.ready, b.pending)
        $('#homeRedeemBalance').html(s)
    }

    function bal2html(total, ready, pending){
        s = '<nobr><pre>'+total+' = <font color=green title="Ready to spend">'+ready+' + <font color=red title="Pending confirmation">'+pending+'</pre></nobr>'
        return s
    }

    function cookUnspentRec(tr){
      var script, sa, addr;
      if ((tr.value == undefined) || (tr.value == '')){
        if (typeof(tr.sathoshi) == 'number'){
          tr.value = sathoshi2num(tr.sathoshi)
        }
      }
      if ((tr.address == undefined) || (tr.address == '')){
// try to find it from the Script
// the script can be provided as scriptPubKey or scriptHex
        if (typeof(tr.scriptPubKey) == 'string'){
          script = tr.scriptPubKey
        }
        if (typeof(tr.scriptHex) == 'string'){
          script = parseScriptHex(tr.scriptHex)
          tr.scriptPubKey = script
        }
        sa = script.split(/ +/)
        addr = sa[2]
        addr = pubKeyHash2bitAdd(addr)
        tr.address = addr
      }
      return tr
    }

// given an array of unspent records returns an array of unspent addresses
    function balOfUnspentAddr(unspent){
        var bal, i, t, k, v
        bal = {}
        for(i in unspent){
            t = unspent[i]
            k = t.address
            if (k != undefined){
                bal[k] = {}
            }
        }
        for(i in unspent){
            t = unspent[i]
            k = t.address
            if (k != undefined){
                v = 0.0
                if (typeof(t.value)=='string'){
                    v = parseFloat(t.value)
                }
                if (typeof(t.value)=='number'){
                    v = t.value
                }
                v = sathoshi2num(num2sathoshi(v))
                bal[k].total += v
                bal.total.total += v
                if (t.block > 0){
                    bal[k].ready += v
                    bal.total.ready += v
                }
                else{
                    bal[k].pending += v
                    bal.total.pending += v
                }
            }
        }
        return bal;
    }

    function homeSendShowTx(){
        var tx, txs, txj
        tx = homeMakeTx()
        if (tx == undefined){ return; }
//        txs = {tx: tx}
//        txj = JSON.stringify(txs)
//alert($('#debugTransaction').val())
//        $.post('cgi-bin/send.py', txj, homeSentTx, 'text')
    }

    function homeSendTx(){
        var tx, txs, txj
        if (UI.sendBy == 'email'){
          if (! homeMakeEmailTx()){ return }
        }
        tx = homeMakeTx()
        if (tx == undefined){ return; }
        txs = {tx: tx}
        txj = JSON.stringify(txs)
//alert(tx)
        $.post('cgi-bin/send.py', txj, homeSentTx, 'text')
    }

    function homeSentTx(data){
        var res
//alert(data)
        res = JSON.parse(data, '', ' ')
        if (res.status == 'OK'){
            alert('Sent\n'+res.message)
            if (UI.sendBy == 'email'){
                $('#homeSendToEmail').val('')
                $('#homeSendTo').val('')
                $('#homeSendAmount').val('')
                $('#homeSendFee').val('')
                $('#homeSendCodeForm').show()
                $('#homeSendForm').hide()
            }
            else{
                $('#debugSendResult').val(res.message)
                $('#homeSendTo').val('')
                $('#homeSendAmount').val('')
                $('#homeSendFee').val('')
                $('#homeMainForm').show()
                $('#homeSendForm').hide()
            }
            //TODO mark the Unspent transactions so that we don't try to spend them again.
            //   actually, it should be in the network as an unconfirmed transaction, so we
            //   just need to refresh the balance.
            homeUpdateBalance()
        }
        else{
            $('#debugSendResult').val(res.error)
            alert('Error: '+res.error)
        }
    }

    function homeMakeTx(){
        var amount, to, toad, from, changeAddr, fee, txo, tx, txJSON
        to = removeWhiteSpace($('#homeSendTo').val())
        if (to == ''){ alert('To Address must be given.'); return }
        try{
          toad = Bitcoin.Address(to)
        }
        catch(err){
          alert('To Address is not valid.'); return;
        }
        amount = parseFloat(removeWhiteSpace($('#homeSendAmount').val()))
        if (isNaN(amount)){ alert('Amount must be given.'); return }
        to = to+' '+amount
//        from = removeWhiteSpace($('#homeSendFrom').val())
        from = ''
        fee = parseFloat(removeWhiteSpace($('#homeSendFee').val()))
        if (isNaN(fee)){ fee = 0; $('#homeSendFee').val('0') }
        if (ReadyBal - amount - fee < 0){ alert('Insufficient funds.'); return }
        if ((G.pin != undefined) && (G.pin != '')){
          spin = prompt("Enter session pin: ");
          if (spin != G.pin){ return }
        }
        $('#debugTransaction').val('')
        $('#debugHexTransaction').val('')
        changeAddr = ''
        txo = makeTxObj(from, to, changeAddr, fee)
//return(JSON.stringify(txo,'','   '))
        if (txo == undefined){ alert('Problem creating the transaction'); return }
        txJSON = TX.toBBE(txo);
        $('#debugTransaction').val(txJSON)
        tx = txo.serialize()
        if (tx == undefined){ alert('Problem serializing the transaction'); return }
        tx = bytes2hex(tx)
        $('#debugHexTransaction').val(tx)
//alert(tx)
//  wireTx(tx)
//  amount = parseFloat(amount) + parseFloat(fee)
//  alert('sent '+amount+' '+G.units)
        return tx
    }

/*
Here is how the email feature works.
We move the bitcoins to be sent over to a new random bitcoin address and email the recipient
the a code containing the private key matching the bitcoin address.
The recipient can then move the bitcoins to their own bitcoin address. So the whole
process actually requires two bitcoin transactions.

The code sent by email is an encrypted message (encrypted using the recipients email address)
which contains:

To: email of recipient
From: email of sender
Amount: BTC amount being sent
Date: date and time in UTC of when the send was initiated
Message: an optional message from the sender to the recipient
Redeem: the private key encrypted with a password provided by the sender or if no password 
        was provided then encrypted with the recipients email address
Recover: the private key encrypted with a private key owned by the sender, used if the
        recipient does not redeem and the sender wants to recover the bitcoins

To redeem the recipient just needs to provide the code they were emailed and also
a password if the sender chose to add one. The email of the recipient needed to decrypt
the above message will already be known from the EZWallet info.

To recover the sender just needs to provide the code and the email of the recipient.
If the sender added a password to redeem, it is not required to be recalled.
The private key needed to decrypt the Recover field of the above message will already
be in the senders EZWallet.

If the sender does not add a password then anyone who intercepts the email
can redeem the bitcoins. If the recipient redeems the bitcoins first, the 
email will not be of use to anyone intercepting it. Adding a password should be
highly recommended, even though it adds some inconvience of having to tell the
recipient the password by phone.

*/
    function homeMakeEmailTx(){
      var to, from, amount, date, message, rawCode, rand, key, bita, pw
      var k1, redeem, recover, code
      to = removeWhiteSpace($('#homeSendToEmail').val().toLowerCase())
      if (to == ''){ alert('To Email must be given.'); return 0 }
      from = G.email
      amount = parseFloat(removeWhiteSpace($('#homeSendAmount').val()))
      if (isNaN(amount)){ alert('Amount must be given.'); return 0 }
      date = new Date().toUTCString()
      message =  trimWhiteSpace($('#homeSendMessage').val())
      pw = trimWhiteSpace($('#homeSendPassword').val())
// create the raw code string:
      rawCode = "\
To: "+to+"\n\
From: "+from+"\n\
Amount: "+amount+"\n\
Date: "+date+"\n\
Message: "+message+"\n\
"
// pick a random string
      rand = randomHex32()
// create the key using hash of the rawCode and random number so that if anyone
//   changes the rawCode in transit, the key cannot be found; thus preventing someone
//   from fooling the recipient by changing the info in the rawCode
      key = hex2hexKey(hash256(rawCode+rand))
// convert to bitcoin address
      bita = key2bitAdd(key)
// 
      if (pw == ''){ pw = to }
      k1 = seed2key(Seed.main, 0)
      redeem = AESencrypt(rand, pw)
      recover = AESencrypt(rand, k1)
      rawCode = rawCode + "\
redeem: "+redeem+"\n\
recover: "+recover+"\n\
rand: "+rand+"\n\
"
// encrypt the rawCode using the recipients email
      code = AESencrypt(rawCode, to)
//      alert(rawCode)
//      alert(bita)
//      alert(code)
      code = code.match(/.{1,40}/g).join('\n')
//      $('#homeSendCodeForm').show()
      $('#debugSendCode').val(code)
      $('#homeSendCode').val(code)
      $('#homeSendCode').select()
//      $('#homeSendForm').hide()
      $('#homeSendTo').val(bita)
//alert($('#homeSendTo').val())

      return 1
    }

    // --- Advanced ---

    function advancedEZBtn(){
      $('#advancedEmailDiv').show()
      $('#advancedWalletNameDiv').show()
      $('#advancedRangeDiv').show()
      $('#advancedDecryptDiv').hide()
      $('#advancedSecretLabel').html('*Wallet Passphrase')
      $('#advancedSecret').attr('title','Copy and paste some sentences from a book; then insert a few of your own words in the sentence. Be alone when entering this. Capitalization and extra spaces do NOT matter.')
      UI.walletType = 'easy';
    }

    function advancedArmoryBtn(){
      $('#advancedEmailDiv').hide()
      $('#advancedWalletNameDiv').hide()
      $('#advancedRangeDiv').show()
      $('#advancedDecryptDiv').hide()
      $('#advancedSecretLabel').html('*Armory Wallet Seed')
      $('#advancedSecret').attr('title','Armory Wallet Seed')
      UI.walletType = 'armory';
    }

    function advancedElectrumBtn(){
      $('#advancedEmailDiv').hide()
      $('#advancedWalletNameDiv').hide()
      $('#advancedRangeDiv').show()
      $('#advancedDecryptDiv').hide()
      $('#advancedSecretLabel').html('*Electrum Wallet Seed')
      $('#advancedSecret').attr('title','Electrum Wallet Seed')
      UI.walletType = 'electrum';
    }

    function advancedKeysBtn(){
      $('#advancedEmailDiv').hide()
      $('#advancedWalletNameDiv').hide()
      $('#advancedRangeDiv').hide()
      $('#advancedDecryptDiv').show()
      $('#advancedSecretLabel').html('*Keys')
      $('#advancedSecret').attr('title','Enter the private keys in any format, if encrypted enter the decryption password also.')
      UI.walletType = 'keys';
    }

    function advancedOpenWallet(){
      var wn, wp, i, k1, p1, b1, s
      var se, de, i, we, w
// if the home wallet is still open, warn and close it before opening new wallet
      if (! $.isEmptyObject(Keys)){
        a = confirm('Close the currently open wallet?')
        if (! a){ return }
        homeCloseWallet()
      }
      if (UI.walletType == undefined){ UI.walletType = 'easy' }
      if (UI.walletType == 'easy'){
        G.email = removeWhiteSpace($('#advancedEmail').val().toLowerCase())
        G.pin = $('#advancedSessionPin').val()
// we don't hold wallet name or wallet pass in memory
        wn = removeWhiteSpace($('#advancedWalletName').val().toLowerCase())
        wp = trimWhiteSpace($('#advancedSecret').val().toLowerCase())
        if (G.email == ''){ alert("Enter email."); return }
        if (wn == ''){ alert("Enter wallet name."); return }
        if (wp == ''){ alert("Enter wallet password."); return }
        Wsize = parseInt($('#advancedRange').val())
        if (isNaN(Wsize)){ Wsize = WsizeDefault }
        if (Wsize > WsizeMax){ Wsize = WsizeMax; alert('Keys in wallet limited to '+WsizeMax) }
        Seed.master = hash256(G.email+wn+wp+'master')
        Seed.main = hash256(Seed.master+'main')
        for(i=0; i<Wsize; i++){
          k1 = seed2key(Seed.main, i)
          p1 = key2pubKey(k1)
          b1 = pubKey2bitAdd(p1)
          Keys[b1] = k1
          Bal[b1] = 0.0
        }
      }
      if (UI.walletType == 'keys'){
        se = $('#advancedSecret').val()
        de = $('#advancedDecrypt').val()
        if (removeWhiteSpace(de) != ''){
alert('not yet implemented'); return
// for now we assume AES encryption
        }
// try to figure out the keys and convert them to hex
// replace non-base64 characters with spaces
        se = se.replace(/[^a-zA-Z0-9\+\/=]+/g, ' ')
        ws = se.split(/\s+/)
        for(i=0;i<ws.length;i++){
          w = ws[i]
          k1 = ''
          if (w.length < 40){ continue } // even in base64 the length of a key will be >40
          if ((w.length == 64) && (! w.match(/[^0-9A-Fa-f]/))){ k1 = w } 
          if ((w.length == 51 || w.length == 44) && (! w.match(/[^0-9A-Za-z]/)) && (! w.match(/[0IOl]/))){ k1 = base582hex(w) }
          if (w.length == 44 && k1==''){ k1 = base642hex(w) }
          if (k1 != ''){
            p1 = key2pubKey(k1)
            b1 = pubKey2bitAdd(p1)
            Keys[b1] = k1
            Bal[b1] = 0.0
          }
        }
      }
      if (UI.walletType == 'electrum'){
alert('not implemented yet'); return
      }
      if (UI.walletType == 'armory'){
alert('not implemented yet'); return
      }
      if (! $.isEmptyObject(Keys)){
        $('#advancedOpenForm').hide()
        $('#advancedMainForm').show()
        $('#advancedEmail').val('')
        $('#advancedWalletName').val('')
        $('#advancedWalletPassword').val('')
        $('#advancedSecret').val('')
        $('#advancedSessionPin').val('')
        $('#debugKeys').val(JSON.stringify(Keys, '', '  '))
        advancedUpdateBalance()
      }
      else{
alert('No keys found.')
      }
    }

    function advancedSendForm(){
        $('#advancedSendForm').show()
        $('#advancedMainForm').hide()
    }

    function advancedReceiveForm(){
        $('#advancedReceiveForm').show()
        $('#advancedSendForm').hide()
        $('#advancedMainForm').hide()
    }

    function advancedSendCancel(){
        $('#advancedMainForm').show()
        $('#advancedSendForm').hide()
    }

    function advancedReceiveBack(){
        $('#advancedMainForm').show()
        $('#advancedReceiveForm').hide()
    }

    function advancedUpdateBalance(){
        var addrArr, addrStr, ba, s
        addrArr = []
        for(ba in Keys){
            addrArr.push(ba)
        }
        $('#advancedBalanceLabel').html(WaitingIcon)
        $('#advancedReceiveBalance').html(s)
        addrStr = JSON.stringify(addrArr)
        $.post('cgi-bin/unspent.py', addrStr, advancedUpdateBalanceFill, 'text')
    }

    function advancedUpdateBalanceFill(data){
        parseUnspentData(data) // fills the Unspent obj
        setBalance() // this is general and can be used by advanced also
        advancedBalanceShow()
    }

    function advancedBalanceShow(){
        var i, b, s
//        s = '' + TotBal 
//        s = '<nobr>'+TotBal+' = <font color=green title="Ready to spend">'+ReadyBal+' + <font color=red title="Pending confirmation">'+PendingBal+'</nobr>'
        s = bal2html(TotBal, ReadyBal, PendingBal)
        $('#advancedBalanceLabel').html(s)
        $('#advancedReceiveBalance').html(s)
        $('#advancedSendBalanceBefore').html(s)
        s = ''
        c = 0
        for(i in Keys){
            b = Bal[i]
            s = s +'<nobr><a href="javascript:addressShow(\''+i+'\')">'+i+' = '+b.toString()+'</a></nobr><br>'
            c += 1
        }
        $('#advancedReceiveAddresses').html(s)
    }

    function advancedCloseWalletAsk(){
        var a = confirm('Close the Advanced wallet?')
        if (! a){ return }
        advancedCloseWallet()
    }

    function advancedCloseWallet(){
        var s
        G = {};
        Keys = {}
        Seed = {}
        Unspent = {}
        Bal = {}
        TotBal = 0
        PendingBal = 0
        ReadyBal = 0
        $('#advancedMainForm').hide()
        $('#advancedSendForm').hide()
        $('#advancedReceiveForm').hide()
        $('#advancedOpenForm').show()
    }

    function advancedSetBalanceAfterSend(){
        var
        bbal = TotBal
        sa = parseFloat(removeWhiteSpace($('#advancedSendAmount').val()))
        fee = parseFloat(removeWhiteSpace($('#advancedSendFee').val()))
        if (isNaN(sa)){ sa = 0 }
        if (isNaN(fee)){ fee = 0 }
        ebal = bbal - sa - fee
        ebal = sathoshi2num(num2sathoshi(ebal))
        $('#advancedSendBalanceAfter').html(ebal)
    }

    function advancedSendSaveTx(){
        var tx, txs, txj
        tx = advancedMakeTx()
        if (tx == undefined){ return; }
        alert("Transaction saved on Details page.")
    }

    function advancedSendTx(){
        var tx, txs, txj
        tx = advancedMakeTx()
        if (tx == undefined){ return; }
        txs = {tx: tx}
        txj = JSON.stringify(txs)
//alert(tx)
        $.post('cgi-bin/send.py', txj, advancedSentTx, 'text')
    }

    function advancedSentTx(data){
        var res
//alert(data)
        res = JSON.parse(data, '', ' ')
        if (res.status == 'OK'){
            alert('Sent\n'+res.message)
            $('#debugSendResult').val(res.message)
            $('#advancedSendFrom').val('')
            $('#advancedSendTo').val('')
            $('#advancedChangeAddress').val('')
            $('#advancedSendFee').val('')
            $('#advancedSendBalanceAfter').html('')
            $('#advancedMainForm').show()
            $('#advancedSendForm').hide()
            //TODO mark the Unspent transactions so that we don't try to spend them again.
            //   actually, it should be in the network as an unconfirmed transaction, so we
            //   just need to refresh the balance.
            advancedUpdateBalance()
        }
        else{
            $('#debugSendResult').val(res.error)
            alert('Error: '+res.error)
        }
    }

    function advancedMakeTx(){
        var amount, to, toad, from, changeAddr, fee, txo, tx, txJSON
//        amount = parseFloat(removeWhiteSpace($('#advancedSendAmount').val()))
//        if (isNaN(amount)){ alert('Amount must be given.'); return }
        to = $('#advancedSendTo').val()
//        try{
//          toad = Bitcoin.Address(to)
//        }
//        catch(err){
//          alert('To Address is not right.'); return;
//        }
//        to = to+' '+amount
        from = $('#advancedSendFrom').val()
        fee = parseFloat(removeWhiteSpace($('#advancedSendFee').val()))
        if (isNaN(fee)){ fee = 0; $('#advancedSendFee').val('0') }
        if ((G.pin != undefined) && (G.pin != '')){
          spin = prompt("Enter session pin: ");
          if (spin != G.pin){ return }
        }
        $('#debugTransaction').val('')
        $('#debugHexTransaction').val('')
        changeAddr = removeWhiteSpace($('#advancedChangeAddress').val())
        txo = makeTxObj(from, to, changeAddr, fee)
//return(JSON.stringify(txo,'','   '))
        if (txo == undefined){ alert('Problem creating the transaction'); return }
        txJSON = TX.toBBE(txo);
        $('#debugTransaction').val(txJSON)
        tx = txo.serialize()
        if (tx == undefined){ alert('Problem serializing the transaction'); return }
        tx = bytes2hex(tx)
        $('#debugHexTransaction').val(tx)
//alert(tx)
//  wireTx(tx)
//  amount = parseFloat(amount) + parseFloat(fee)
//  alert('sent '+amount+' '+G.units)
        return tx
    }

    // --- generator ---

    function gen_random() {
        $('#pass').val('');
        $('#hash').focus();
        gen_from = 'hash';
        $('#from_hash').button('toggle');
        update_gen();
        var bytes = Crypto.util.randomBytes(32);
        $('#hash').val(Crypto.util.bytesToHex(bytes));
        generate();
    }

    function update_gen() {
        setErrorState($('#hash'), false);
        setErrorState($('#sec'), false);
        $('#pass').attr('readonly', gen_from != 'pass');
        $('#hash').attr('readonly', gen_from != 'hash');
        $('#sec').attr('readonly', gen_from != 'sec');
        $('#sec').parent().parent().removeClass('error');
    }

    function update_gen_from() {
        gen_from = $(this).attr('id').substring(5);
        update_gen();
        if (gen_from == 'pass') {
            if (gen_ps_reset) {
                gen_ps_reset = false;
                onChangePass();
            }
            $('#pass').focus();
        } else if (gen_from == 'hash') {
            $('#hash').focus();
        } else if (gen_from == 'sec') {
            $('#sec').focus();
        }
    }

    function update_gen_from_focus() {
        gen_from = $(this).attr('id');
        update_gen();
        if (gen_from == 'pass') {
            if (gen_ps_reset) {
                gen_ps_reset = false;
                onChangePass();
            }
        }
        $('#from_'+gen_from).button('toggle');
    }

    function generate() {
        var hash_str = pad($('#hash').val(), 64, '0');

        var hash = Crypto.util.hexToBytes(hash_str);

        eckey = new Bitcoin.ECKey(hash);

        gen_eckey = eckey;

        try {
            var curve = getSECCurveByName("secp256k1");
            gen_pt = curve.getG().multiply(eckey.priv);
            gen_eckey.pub = getEncoded(gen_pt, gen_compressed);
            gen_eckey.pubKeyHash = Bitcoin.Util.sha256ripe160(gen_eckey.pub);
            var addr = eckey.getBitcoinAddress();
            setErrorState($('#hash'), false);
        } catch (err) {
            //console.info(err);
            setErrorState($('#hash'), true, 'Invalid secret exponent (must be non-zero value)');
            return;
        }

        gen_update();
    }

    function update_gen_compressed() {
        setErrorState($('#hash'), false);
        setErrorState($('#sec'), false);
        gen_compressed = $(this).attr('id') == 'compressed';
        gen_eckey.pub = getEncoded(gen_pt, gen_compressed);
        gen_eckey.pubKeyHash = Bitcoin.Util.sha256ripe160(gen_eckey.pub);
        gen_update();
    }

    function gen_update() {

        var eckey = gen_eckey;
        var compressed = gen_compressed;

        var hash_str = pad($('#hash').val(), 64, '0');
        var hash = Crypto.util.hexToBytes(hash_str);

        var hash160 = eckey.getPubKeyHash();

        var addr = eckey.getBitcoinAddress();
        $('#addr').val(addr);

        var h160 = Crypto.util.bytesToHex(hash160);
        $('#h160').val(h160);

        var payload = hash;

        if (compressed)
            payload.push(0x01);

        var sec = new Bitcoin.Address(payload); sec.version = 128;
        $('#sec').val(sec);

        var pub = Crypto.util.bytesToHex(getEncoded(gen_pt, compressed));
        $('#pub').val(pub);

        var der = Crypto.util.bytesToHex(getDER(eckey, compressed));
        $('#der').val(der);

        var img = '<img src="http://chart.apis.google.com/chart?cht=qr&chs=255x250&chl='+addr+'">';

        if (true) {
            var qr = qrcode(3, 'M');
            var text = $('#addr').val();
            text = text.replace(/^[\s\u3000]+|[\s\u3000]+$/g, '');
            qr.addData(text);
            qr.make();
            img = qr.createImgTag(5);
        }

        var url = 'http://blockchain.info/address/'+addr;
        $('#qr').html('<a href="'+url+'" title="'+addr+'" target="_blank">'+img+'</a>');
        $('#qr_addr').text($('#addr').val());
    }


    function calc_hash() {
        var hash = Crypto.SHA256($('#pass').val(), { asBytes: true });
        $('#hash').val(Crypto.util.bytesToHex(hash));
    }

    function onChangePass() {
        calc_hash();
        clearTimeout(timeout);
        timeout = setTimeout(generate, TIMEOUT);
    }

    function onChangeHash() {
        $('#pass').val('');
        gen_ps_reset = true;
        clearTimeout(timeout);

        if (/[^0123456789abcdef]+/i.test($('#hash').val())) {
            setErrorState($('#hash'), true, 'Erroneous characters (must be 0..9-a..f)');
            return;
        } else {
            setErrorState($('#hash'), false);
        }

        timeout = setTimeout(generate, TIMEOUT);
    }

    function onChangePrivKey() {

        clearTimeout(timeout);

        $('#pass').val('');
        gen_ps_reset = true;

        var sec = $('#sec').val();

        try { 
            var res = parseBase58Check(sec); 
            var version = res[0];
            var payload = res[1];
        } catch (err) {
            setErrorState($('#sec'), true, 'Invalid private key checksum');
            return;
        };

        if (version != 128) {
            setErrorState($('#sec'), true, 'Invalid private key version (must be 128)');
            return;
        } else if (payload.length < 32) {
            setErrorState($('#sec'), true, 'Invalid payload (must be 32 or 33 bytes)');
            return;
        }

        setErrorState($('#sec'), false);

        if (payload.length > 32) {
            payload.pop();
            gen_compressed = true;
            $('#compressed').button('toggle');
        } else {
            gen_compressed = false;
            $('#uncompressed').button('toggle');
        }

        $('#hash').val(Crypto.util.bytesToHex(payload));

        timeout = setTimeout(generate, TIMEOUT);
    }

    var from = 'hex';
    var to = 'hex';

    function update_enc_from() {
        from = $(this).attr('id').substring(5);
        translate();
    }

    function update_enc_to() {
        to = $(this).attr('id').substring(3);
        translate();
    }

    function strToBytes(str) {
        var bytes = [];
        for (var i = 0; i < str.length; ++i)
           bytes.push(str.charCodeAt(i));
        return bytes;
    }

    function bytesToString(bytes) {
        var str = '';
        for (var i = 0; i < bytes.length; ++i)
            str += String.fromCharCode(bytes[i]);
        return str;
    }

    function isHex(str) {
        return !/[^0123456789abcdef:, ]+/i.test(str);
    }

    function isBase58(str) {
        return !/[^123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz]+/.test(str);
    }

    function isBase64(str) {
        return !/[^ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=]+/.test(str) && (str.length % 4) == 0;
    }

    function issubset(a, ssv) {
        var b = ssv.trim().split(' ');
        for (var i = 0; i < b.length; i++) {
            if (a.indexOf(b[i].toLowerCase()) == -1 
                && a.indexOf(b[i].toUpperCase()) == -1)
            return false;
        }
        return true;
    }

    function autodetect(str) {
        var enc = [];
        if (isHex(str)) 
            enc.push('hex');
        if (isBase58(str))
            enc.push('base58');
        if (issubset(mn_words, str)) 
            enc.push('mnemonic');
        if (issubset(rfc1751_wordlist, str)) 
            enc.push('rfc1751');
        if (isBase64(str))
            enc.push('base64');
        if (str.length > 0)
            enc.push('text');
        return enc;
    }

    function update_toolbar(enc) {
        var reselect = false;
        $.each($('#enc_from').children(), function() {
            var id = $(this).attr('id').substring(5);
            var disabled = (enc && enc.indexOf(id) == -1);
            if (disabled && $(this).hasClass('active')) {
                $(this).removeClass('active');
                reselect = true;
            }
            $(this).attr('disabled', disabled);
        });
        if (enc && enc.length > 0 && reselect) {
            $('#from_' + enc[0]).addClass('active');
            from = enc[0];
        }
    }

    function enct(id) {
        return $('#from_'+id).text();
    }

    function translate() {

        var str = $('#src').val();

        if (str.length == 0) {
            update_toolbar(null);
            return;
        }

        text = str;

        var enc = autodetect(str);

        update_toolbar(enc);

        bytes = strToBytes(str);

        var type = '';

        if (bytes.length > 0) {
            if (from == 'base58') {
                try { 
                    var res = parseBase58Check(str); 
                    type = 'Check ver.' + res[0];
                    bytes = res[1];
                } catch (err) {
                    bytes = Bitcoin.Base58.decode(str);
                }
            } else if (from == 'hex') {
                bytes = Crypto.util.hexToBytes(str.replace(/[ :,]+/g,''));
            } else if (from == 'rfc1751') {
                try { bytes = english_to_key(str); } catch (err) { type = ' ' + err; bytes = []; };
            } else if (from == 'mnemonic') {
                bytes = Crypto.util.hexToBytes(mn_decode(str.trim()));
            } else if (from == 'base64') {
                try { bytes = Crypto.util.base64ToBytes(str); } catch (err) {}
            }

            var ver = '';
            if (to == 'base58') {
                if (bytes.length == 20 || bytes.length == 32) {
                    var addr = new Bitcoin.Address(bytes);
                    addr.version = bytes.length == 32 ? 128 : 0;
                    text = addr.toString();
                    ver = 'Check ver.' + addr.version;
                } else {
                    text = Bitcoin.Base58.encode(bytes);
                }
            } else if (to == 'hex') {
                text = Crypto.util.bytesToHex(bytes);
            } else if (to == 'text') {
                text = bytesToString(bytes);
            } else if (to == 'rfc1751') {
                text = key_to_english(bytes);
            } else if (to == 'mnemonic') {
                text = mn_encode(Crypto.util.bytesToHex(bytes));
            } else if (to == 'base64') {
                text = Crypto.util.bytesToBase64(bytes);
            } 
        }

        $('#hint_from').text(enct(from) + type + ' (' + bytes.length + ' byte' + (bytes.length == 1 ? ')' : 's)'));
        $('#hint_to').text(enct(to) + ver + ' (' + text.length + ' character' + (text.length == 1 ? ')' : 's)'));
        $('#dest').val(text);
    }

    function onChangeFrom() {
        clearTimeout(timeout);
        timeout = setTimeout(translate, TIMEOUT);
    }

    function onInput(id, func) {
        $(id).bind("input keyup keydown keypress change blur", function() {
            if ($(this).val() != jQuery.data(this, "lastvalue")) {
                func();
            }
            jQuery.data(this, "lastvalue", $(this).val());
        });
        $(id).bind("focus", function() {
           jQuery.data(this, "lastvalue", $(this).val());
        });
    }

    // --- chain ---
    var chain_mode = 'csv';
    var addresses = [];
    var chain_range = parseInt($('#range').val());
    var chain_type = 'chain_armory';

    function onChangeMethod() {
        var id = $(this).attr('id');

        if (chain_type != id) {
            $('#seed').val('');
            $('#expo').val('');
            $('#memo').val('');
            $('#progress').text('');
            $('#chain').text('');
            chOnStop();
        }

        $('#elChange').attr('disabled', id != 'chain_electrum');

        chain_type = id;
    }

    function onChangeFormat() {
        chain_mode = $(this).attr('id');
        update_chain();
    }

    function addr_to_csv(i, r) {
        return i + ', "' + r[0] +'", "' + r[1] +'"\n';
    }

    function update_chain() {
        if (addresses.length == 0)
            return;
        var str = '';
        if (chain_mode == 'csv') {
            for (var i = 0; i < addresses.length; i++)
                str += addr_to_csv(i+1, addresses[i]);

        } else if (chain_mode == 'json') {

            var w = {};
            w['keys'] = [];
            for (var i = 0; i < addresses.length; i++)
                w['keys'].push({'addr':addresses[i][0],'sec':addresses[i][1]});
            str = JSON.stringify(w, null, 4);
        }
        $('#chain').text(str);

        chain_range = parseInt($('#range').val());
        if (addresses.length >= chain_range)
            chOnStop();

    }

    function onChangeSeed() {
        $('#expo').val('');
        $('#progress').text('');
        chOnStop();
        $('#memo').val( mn_encode(seed) );
        clearTimeout(timeout);
        timeout = setTimeout(chain_generate, TIMEOUT);
    }

    function onChangeMemo() {
        var str =  $('#memo').val();

        if (str.length == 0) {
            chOnStop();
            return;
        }

        if (chain_type == 'chain_electrum') {
            if (issubset(mn_words, str))  {
                var seed = mn_decode(str);
                $('#seed').val(seed);
            }
        }

        if (chain_type == 'chain_armory') {
            var keys = armory_decode_keys(str);
            if (keys != null) {
                var cc = keys[1];
                var pk = keys[0];
                $('#seed').val(Crypto.util.bytesToHex(cc));
                $('#expo').val(Crypto.util.bytesToHex(pk));
            }
        }

        clearTimeout(timeout);
        timeout = setTimeout(chain_generate, TIMEOUT);
    }

    function chOnPlay() {
        var cc = Crypto.util.randomBytes(32);
        var pk = Crypto.util.randomBytes(32);

        if (chain_type == 'chain_armory') {
            $('#seed').val(Crypto.util.bytesToHex(cc));
            $('#expo').val(Crypto.util.bytesToHex(pk));
            var codes = armory_encode_keys(pk, cc);
            $('#memo').val(codes);
        }

        if (chain_type == 'chain_electrum') {
            var seed = Crypto.util.bytesToHex(pk.slice(0,16));
            //nb! electrum doesn't handle trailing zeros very well
            if (seed.charAt(0) == '0') seed = seed.substr(1);
            $('#seed').val(seed);
            var codes = mn_encode(seed);
            $('#memo').val(codes);
        }
        chain_generate();
    }

    function chOnStop() {
        Armory.stop();
        Electrum.stop();
        $('#chStop').hide();
        $('#chPlay').show();

        if (chain_type == 'chain_electrum') {
            $('#progress').text('');
        }
    }

    function onChangeChange() {
        chain_range = parseInt($('#range').val());
        if (addresses.length >= chain_range)
            onChangeRange();
    }

    function onChangeRange() {
        chain_range = parseInt($('#range').val());
        clearTimeout(timeout);
        timeout = setTimeout(update_chain_range, TIMEOUT);
    }

    function addr_callback(r) {
        addresses.push(r);
        $('#chain').append(addr_to_csv(addresses.length,r));
    }

    function electrum_seed_update(r, seed) {
        $('#progress').text('key stretching: ' + r + '%');
        $('#expo').val(Crypto.util.bytesToHex(seed));
    }

    function electrum_seed_success(privKey) {
        $('#progress').text('');
        $('#expo').val(Crypto.util.bytesToHex(privKey));
        var addChange = $('#elChange').is(':checked');
        Electrum.gen(chain_range, addr_callback, update_chain, addChange);
    }

    function update_chain_range() {
        chain_range = $('#range').val();

        addresses = [];
        $('#chain').text('');

        if (chain_type == 'chain_electrum') {
            var addChange = $('#elChange').is(':checked');
            Electrum.gen(chain_range, addr_callback, update_chain, addChange);
        }

        if (chain_type == 'chain_armory') {
            var codes = $('#memo').val();
            Armory.gen(codes, chain_range, addr_callback, update_chain);
        }
    }

    function chain_generate() {
        clearTimeout(timeout);

        var seed = $('#seed').val();
        var codes = $('#memo').val();

        addresses = [];
        $('#progress').text('');
        $('#chain').text('');

        Electrum.stop();

        if (chain_type == 'chain_electrum') {
           if (seed.length == 0)
               return;
            Electrum.init(seed, electrum_seed_update, electrum_seed_success);
        }

        if (chain_type == 'chain_armory') {
            var uid = Armory.gen(codes, chain_range, addr_callback, update_chain);
            if (uid)
                $('#progress').text('uid: ' + uid);
            else
                return;
        }

        $('#chPlay').hide();
        $('#chStop').show();
    }

    // -- transactions --

    var txType = 'txBCI';

    function txGenSrcAddr() {
        var sec = $('#txSec').val();
        var addr = '';

        try {
            var res = parseBase58Check(sec); 
            var version = res[0];
            var payload = res[1];
            var compressed = false;
            if (payload.length > 32) {
                payload.pop();
                compressed = true;
            }
            var eckey = new Bitcoin.ECKey(payload);
            var curve = getSECCurveByName("secp256k1");
            var pt = curve.getG().multiply(eckey.priv);
            eckey.pub = getEncoded(pt, compressed);
            eckey.pubKeyHash = Bitcoin.Util.sha256ripe160(eckey.pub);
            addr = eckey.getBitcoinAddress();
        } catch (err) {
        }

        $('#txAddr').val(addr);
        $('#txBalance').val('0.00');

        if (addr != "")
            txGetUnspent();
    }

    function txOnChangeSec() {
        clearTimeout(timeout);
        timeout = setTimeout(txGenSrcAddr, TIMEOUT);
    }
    
    function txSetUnspent(text) {
        var r = JSON.parse(text);
        txUnspent = JSON.stringify(r, null, 4);
        $('#txUnspent').val(txUnspent);
        var address = $('#txAddr').val();
        TX.parseInputs(txUnspent, address);
        var value = TX.getBalance();
        var fval = Bitcoin.Util.formatValue(value);
        var fee = parseFloat($('#txFee').val());
        $('#txBalance').val(fval);
        $('#txValue').val(fval - fee);
        txRebuild();
    }

    function txUpdateUnspent() {
        txSetUnspent($('#txUnspent').val());
    }

    function txOnChangeUnspent() {
        clearTimeout(timeout);
        timeout = setTimeout(txUpdateUnspent, TIMEOUT);
    }

    function txParseUnspent(text) {
        if (text == '')
            alert('No data');
        txSetUnspent(text);
    }

    function txGetUnspent() {
        var addr = $('#txAddr').val();

        var url = (txType == 'txBCI') ? 'http://blockchain.info/unspent?address=' + addr :
            'http://blockexplorer.com/q/mytransactions/' + addr;

        url = prompt('Download transaction history:', url);
        if (url != null && url != "") {
            $('#txUnspent').val('');
            tx_fetch(url, txParseUnspent);
        }
    }

    function txOnChangeJSON() {
        var str = $('#txJSON').val();
        var sendTx = TX.fromBBE(str);
        var bytes = sendTx.serialize();
        var hex = Crypto.util.bytesToHex(bytes);
        $('#txHex').val(hex);
    }

    function txOnChangeHex() {
        var str = $('#txHex').val();
        str = str.replace(/[^0-9a-fA-f]/g,'');
        $('#txHex').val(str);
        var bytes = Crypto.util.hexToBytes(str);
        var sendTx = TX.deserialize(bytes);
        var text = TX.toBBE(sendTx);
        $('#txJSON').val(text);
    }

    function txOnAddDest() {
        var list = $(document).find('.txCC');
        var clone = list.last().clone();
        clone.find('.help-inline').empty();
        clone.find('.control-label').text('Cc');
        var dest = clone.find('#txDest');
        var value = clone.find('#txValue');
        clone.insertAfter(list.last());
        onInput(dest, txOnChangeDest);
        onInput(value, txOnChangeDest);
        dest.val('');
        value.val('');
        $('#txRemoveDest').attr('disabled', false);
        return false;
    }

    function txOnRemoveDest() {
        var list = $(document).find('.txCC');
        if (list.size() == 2)
            $('#txRemoveDest').attr('disabled', true);
        list.last().remove();
        return false;
    }

    function txSent(text) {
        alert(text ? text : 'No response!');
    }

    function txSend() {
        var txAddr = $('#txAddr').val();
        var address = TX.getAddress();

        var r = '';
        if (txAddr != address)
            r += 'Warning! Source address does not match private key.\n\n';

        var tx = $('#txHex').val();

        //url = 'http://bitsend.rowit.co.uk/?transaction=' + tx;
        url = 'http://blockchain.info/pushtx';
        postdata = 'tx=' + tx;
        url = prompt(r + 'Send transaction:', url);
        if (url != null && url != "") {
            tx_fetch(url, txSent, txSent, postdata);
        }
        return false;
    }

    function txSendElectrum() {
        var txAddr = $('#txAddr').val();
        var address = TX.getAddress();

        var r = '';
        if (txAddr != address)
            r += 'Warning! Source address does not match private key.\n\n';

        var tx = $('#txHex').val();
        var txs = {tx: tx}
        var txj = JSON.stringify(txs)
alert(tx)
        $.post('cgi-bin/send.py', txj, homeSentTx, 'text')
        return false;
    }

    function txRebuild() {
        var sec = $('#txSec').val();
        var addr = $('#txAddr').val();
        var unspent = $('#txUnspent').val();
        var balance = parseFloat($('#txBalance').val());
        var fee = parseFloat('0'+$('#txFee').val());

        try {
            var res = parseBase58Check(sec); 
            var version = res[0];
            var payload = res[1];
        } catch (err) {
            $('#txJSON').val('');
            $('#txHex').val('');
            return;
        }

        var compressed = false;
        if (payload.length > 32) {
            payload.pop();
            compressed = true;
        }

        var eckey = new Bitcoin.ECKey(payload);

        TX.init(eckey);

        var fval = 0;
        var o = txGetOutputs();
        for (i in o) {
            TX.addOutput(o[i].dest, o[i].fval);
            fval += o[i].fval;
        }

        // send change back or it will be sent as fee
        if (balance > fval + fee) {
            var change = balance - fval - fee;
            TX.addOutput(addr, change);
        }

        try {
            var sendTx = TX.construct();
            var txJSON = TX.toBBE(sendTx);
            var buf = sendTx.serialize();
            var txHex = Crypto.util.bytesToHex(buf);
            $('#txJSON').val(txJSON);
            $('#txHex').val(txHex);
        } catch(err) {
            $('#txJSON').val('');
            $('#txHex').val('');
        }
    }

    function txOnChangeDest() {
        var balance = parseFloat($('#txBalance').val());
        var fval = parseFloat('0'+$('#txValue').val());
        var fee = parseFloat('0'+$('#txFee').val());

        if (fval + fee > balance) {
            fee = balance - fval;
            $('#txFee').val(fee > 0 ? fee : '0.00');
        }

        clearTimeout(timeout);
        timeout = setTimeout(txRebuild, TIMEOUT);
    }

    function txShowUnspent() {
        var div = $('#txUnspentForm');

        if (div.hasClass('hide')) {
            div.removeClass('hide');
            $('#txShowUnspent').text('Hide Outputs');
        } else {
            div.addClass('hide');
            $('#txShowUnspent').text('Show Outputs');
        }
    }

    function txChangeType() {
        txType = $(this).attr('id');
        txGetUnspent();
    }

    function txOnChangeFee() {

        var balance = parseFloat($('#txBalance').val());
        var fee = parseFloat('0'+$('#txFee').val());

        var fval = 0;
        var o = txGetOutputs();
        for (i in o) {
            TX.addOutput(o[i].dest, o[i].fval);
            fval += o[i].fval;
        }

        if (fval + fee > balance) {
            fval = balance - fee;
            $('#txValue').val(fval < 0 ? 0 : fval);
        }

        if (fee == 0 && fval == balance - 0.0005) {
            $('#txValue').val(balance);
        }

        clearTimeout(timeout);
        timeout = setTimeout(txRebuild, TIMEOUT);
    }

    function txGetOutputs() {
        var res = [];
        $.each($(document).find('.txCC'), function() {
            var dest = $(this).find('#txDest').val();
            var fval = parseFloat('0' + $(this).find('#txValue').val());
            res.push( {"dest":dest, "fval":fval } );
        });
        return res;
    }

    // -- sign --

    function updateAddr(from, to) {
        var sec = from.val();
        var addr = '';
        var eckey = null;
        var compressed = false;
        try {
            var res = parseBase58Check(sec); 
            var version = res[0];
            var payload = res[1];
            if (payload.length > 32) {
                payload.pop();
                compressed = true;
            }
            eckey = new Bitcoin.ECKey(payload);
            var curve = getSECCurveByName("secp256k1");
            var pt = curve.getG().multiply(eckey.priv);
            eckey.pub = getEncoded(pt, compressed);
            eckey.pubKeyHash = Bitcoin.Util.sha256ripe160(eckey.pub);
            addr = eckey.getBitcoinAddress();
            setErrorState(from, false);
        } catch (err) {
            setErrorState(from, true, "Bad private key");
        }
        to.val(addr);
        return {"key":eckey, "compressed":compressed};
    }

    function sgGenAddr() {
        updateAddr($('#sgSec'), $('#sgAddr'));
    }

    function sgOnChangeSec() {
        $('#sgSig').val('');
        clearTimeout(timeout);
        timeout = setTimeout(sgGenAddr, TIMEOUT);
    }

    function sgSign() {
        var message = $('#sgMsg').val();
        var p = updateAddr($('#sgSec'), $('#sgAddr'));
        var sig = sign_message(p.key, message, p.compressed);
        $('#sgSig').val(sig);
    }

    function sgOnChangeMsg() {
        $('#sgSig').val('');
        clearTimeout(timeout);
        timeout = setTimeout(sgUpdateMsg, TIMEOUT);
    }

    function sgUpdateMsg() {
        $('#vrMsg').val($('#sgMsg').val());
    }

    // -- verify --

    function vrVerify() {
        var message = $('#vrMsg').val();
        var sig = $('#vrSig').val();
        var res = verify_message(sig, message);

        if (res) {
            var href = 'https://blockchain.info/address/' + res;
            var a = '<a href=' + href + ' target=_blank>' + res + '</a>';
            $('#vrRes').html('Verified to: ' + a);
        } else {
            $('#vrRes').text('false');
        }
        return false;
    }

    function vrClearRes() {
        $('#vrRes').text('');
    }

    function debugShowKeys(){
      if ($('#debugShowKeys').attr('checked')){
        $('#debugKeys').show()
      }
      else{
        $('#debugKeys').hide()
      }
    }

    function settingsInit(){
      $('#settingsPassword').val('')
      settingsGet()
    }

    function settingsGet(){
        var jo, jos, ba, s
        jo = {}
        jo.action = 'get'
        jos = JSON.stringify(jo)
        $.post('cgi-bin/settings.py', jos, settingsGetShow, 'text')
    }

    function settingsSet(e){
//      alert(e.data.f + ' ' +e.data.v)
        var jo, jos, ba, s
        jo = {}
        jo.action = 'set'
        jo.field = e.data.f
        jo.value = e.data.v
        jo.password = $('#settingsPassword').val()
        jos = JSON.stringify(jo)
        $.post('cgi-bin/settings.py', jos, settingsGetShow, 'text')
    }

    var SettingsPasswordHash = ''
    function settingsGetShow(data){
        res = JSON.parse(data, '', '  ')
        if (res.status == 'Error'){
          alert(res.message)
        }
        $('#settingsSendBtn_'+res.send).button('toggle')
        $('#settingsUnspentBtn_'+res.unspent).button('toggle')
        SettingsPasswordHash = res.hash
    }

    $(document).ready( function() {
//alert('ready')

        if (window.location.hash)
            $('#tab-' + window.location.hash.substr(1)).tab('show');

        $('a[data-toggle="tab"]').on('shown', function (e) {
            window.location.hash = $(this).attr('href');
        });

        // home
        $('#homeOpenWallet').click(homeOpenWallet);
        $('#homeCloseBtn').click(homeCloseWalletAsk);
        $('#homeSendBtn').click(homeSendForm);
        $('#homeSendByAddressBtn').click(homeSendByAddressForm);
        $('#homeSendByEmailBtn').click(homeSendByEmailForm);
        $('#homeSendCodeDoneBtn').click(homeSendCodeDone);
        $('#homeSendCancelBtn').click(homeSendCancel);
        $('#homeSendSendBtn').click(homeSendTx);
        $('#homeScanBtn').click(homeScan);
        $('#homeScanCloseBtn').click(homeScanClose);
        $('#homeReceiveBtn').click(homeReceiveForm);
        $('#homeReceiveBackBtn').click(homeReceiveBack);
        $('#homeRedeemBtn').click(homeRedeemForm);
        $('#homeRedeemCancelBtn').click(homeRedeemCancel);
        $('#homeRedeemNowBtn').click(homeRedeemNow);
        $('#homeRecoverBtn').click(homeRecoverForm);
        $('#homeRecoverCancelBtn').click(homeRecoverCancel);
        $('#homeReloadBalBtn').click(homeUpdateBalance);
//        $('#homeSendShowBtn').click(homeSendShowTx);
        onInput($('#homeSendAmount'), homeSetBalanceAfterSend);
        onInput($('#homeSendFee'), homeSetBalanceAfterSend);
        onInput($('#homeRedeemCode'), homeSetRedeemInfo);
        onInput($('#homeRedeemPassword'), homeSetRedeemInfo);


        // advanced
        $('#advancedEZBtn').click(advancedEZBtn);
        $('#advancedArmoryBtn').click(advancedArmoryBtn);
        $('#advancedElectrumBtn').click(advancedElectrumBtn);
        $('#advancedKeysBtn').click(advancedKeysBtn);
        $('#advancedOpenWallet').click(advancedOpenWallet);
        $('#advancedCloseBtn').click(advancedCloseWalletAsk);
        $('#advancedSendBtn').click(advancedSendForm);
        $('#advancedReceiveBtn').click(advancedReceiveForm);
        $('#advancedSendCancelBtn').click(advancedSendCancel);
        $('#advancedSendSendBtn').click(advancedSendTx);
        $('#advancedReceiveBackBtn').click(advancedReceiveBack);
        $('#advancedReloadBalBtn').click(advancedUpdateBalance);
        $('#advancedSendSaveBtn').click(advancedSendSaveTx);
        onInput($('#advancedSendAmount'), advancedSetBalanceAfterSend);
        onInput($('#advancedSendFee'), advancedSetBalanceAfterSend);
        $('#advancedDecryptDiv').hide()

        $('#debugShowKeys').click(debugShowKeys);

        $('#settingsLink').click(settingsInit);
        $('#settingsSendBtn_blockchain').click({f:'send', v:'blockchain'}, settingsSet);
        $('#settingsSendBtn_electrum').click({f:'send', v:'electrum'}, settingsSet);
        $('#settingsUnspentBtn_blockchain').click({f:'unspent', v:'blockchain'}, settingsSet);
        $('#settingsUnspentBtn_electrum').click({f:'unspent', v:'electrum'}, settingsSet);
        $('#settingsUnspentBtn_blockexplorer').click({f:'unspent', v:'blockexplorer'}, settingsSet);



/*
        // generator

        onInput('#pass', onChangePass);
        onInput('#hash', onChangeHash);
        onInput('#sec', onChangePrivKey);

        $('#from_pass').click(update_gen_from);
        $('#from_hash').click(update_gen_from);
        $('#from_sec').click(update_gen_from);

        $('#random').click(gen_random);

        $('#uncompressed').click(update_gen_compressed);
        $('#compressed').click(update_gen_compressed);

        $('#pass').val('correct horse battery staple');
        calc_hash();
        generate();
        $('#pass').focus();

        // chains

        $('#chPlay').click(chOnPlay);
        $('#chStop').click(chOnStop);

        $('#csv').click(onChangeFormat);
        $('#json').click(onChangeFormat);

        $('#chain_armory').click(onChangeMethod);
        $('#chain_electrum').click(onChangeMethod);

        onInput($('#range'), onChangeRange);
        onInput($('#seed'), onChangeSeed);
        onInput($('#memo'), onChangeMemo);
        $('#elChange').change(onChangeChange);

        // transactions

        $('#txSec').val(tx_sec);
        $('#txAddr').val(tx_addr);
        $('#txDest').val(tx_dest);

        txSetUnspent(tx_unspent);

        $('#txGetUnspent').click(txGetUnspent);

        $('#txBCI').click(txChangeType);
        $('#txBBE').click(txChangeType);

        onInput($('#txSec'), txOnChangeSec);
        onInput($('#txUnspent'), txOnChangeUnspent);
        onInput($('#txHex'), txOnChangeHex);
        onInput($('#txJSON'), txOnChangeJSON);
        onInput($('#txDest'), txOnChangeDest);
        onInput($('#txValue'), txOnChangeDest);
        onInput($('#txFee'), txOnChangeFee);

        $('#txAddDest').click(txOnAddDest);
        $('#txRemoveDest').click(txOnRemoveDest);
        $('#txSend').click(txSend);
        $('#txSendElectrum').click(txSendElectrum);
        $('#txRebuild').click(txRebuild);

        // converter

        onInput('#src', onChangeFrom);
        $("body").on("click", "#enc_from .btn", update_enc_from);
        $("body").on("click", "#enc_to .btn", update_enc_to);

        // sign
        $('#sgSec').val('5JeWZ1z6sRcLTJXdQEDdB986E6XfLAkj9CgNE4EHzr5GmjrVFpf');
        $('#sgAddr').val('17mDAmveV5wBwxajBsY7g1trbMW1DVWcgL');
        $('#sgMsg').val("C'est par mon ordre et pour le bien de l'Etat que le porteur du présent a fait ce qu'il a fait.");

        onInput('#sgSec', sgOnChangeSec);
        onInput('#sgMsg', sgOnChangeMsg);

        $('#sgSign').click(sgSign);
        $('#sgForm').submit(sgSign);

        // verify
        $('#vrMsg').val($('#sgMsg').val());

        onInput('#vrAddr', vrClearRes);
        onInput('#vrMsg', vrClearRes);
        onInput('#vrSig', vrClearRes);
        $('#vrVerify').click(vrVerify);
*/

    });
})(jQuery);
