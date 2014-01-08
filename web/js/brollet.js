(function (exports){
    var Brollet = exports;
    Brollet.MultiSigScript = function (scriptBytes, hash) {
        this.script = new Bitcoin.Script(scriptBytes);
        this.redeemScript = new Brollet.RedeemScript(this.script.chunks[this.script.chunks.length-1]);
        this.pubkeys = this.redeemScript.pubkeys;
        var signatures = [];

        var scriptChunks = this.script.chunks;
        for (var i=1; i<scriptChunks.length-1; i++){
            signatures.push(scriptChunks[i]);
        }
        this.signatures = signatures;
        this.hash = hash;
        this.sortSignatures();
    }

    Brollet.MultiSigScript.prototype.toScript = function () {
        var result = new Bitcoin.Script();
        result.writeOp(Bitcoin.Opcode.map.OP_0);
        var signatures = this.signatures;
        for (var i=0; i<signatures.length; i++){
            result.writeBytes(signatures[i]);
        }
        result.writeBytes(this.redeemScript.script.buffer);
        return result;
    }

    Brollet.MultiSigScript.prototype.isComplete = function () {
        return this.signatures.length >= this.redeemScript.nRequired;
    }

    Brollet.MultiSigScript.prototype.addSignature = function (signature){
        this.signatures.push(signature);
        this.sortSignatures();
    }

    Brollet.MultiSigScript.prototype.sortSignatures = function () {
        var hash = this.hash;

        this.validateSignatures ();
        var pubkeys = this.pubkeys.slice(0);
        var signatures = this.signatures.slice(0);
        var takenSigs = [];
        var result = [];

        for (var i=0; i<pubkeys.length; i++){
            var pubkey = pubkeys[i];
            for (var j=0; j<signatures.length; j++){
                if (takenSigs.indexOf(j) != -1) continue;
                var sig = signatures[j];
                if (Bitcoin.ECDSA.verify(hash, sig, pubkey)){
                    takenSigs.push(j);
                    result.push(sig);
                    break;
                }
            }
        }
        if (result.length != signatures.length){
            throw Error("Signature sorting failed");
        }
        this.signatures = result;
    }
    Brollet.MultiSigScript.prototype.validateSignatures = function () {
        var hash = this.hash;
        var pubkeys = this.pubkeys.slice(0);
        var signatures = this.signatures.slice(0);
        var takenPubkeys = [];
        for(var i=0; i<signatures.length; i++){
            var sig = signatures[i];
            var validSig = false;
            for (var j=0; j<pubkeys.length; j++){
                if (takenPubkeys.indexOf(j) != -1){
                    continue;
                }
                var pubkey = pubkeys[j];
                if (Bitcoin.ECDSA.verify(hash, sig, pubkey)){
                    validSig = true;
                    takenPubkeys.push(j);
                    break;
                }
            }
            if (!validSig){
                throw Error("Signature validation failed for: "+Crypto.util.bytesToHex(sig));
            }
        }

        var unsignedPubkeys = [];
        var signedPubkeys = [];
        for(var i=0; i<pubkeys.length; i++){
            if (takenPubkeys.indexOf(i) != -1){
                signedPubkeys.push(pubkeys[i]);
            }else{
                unsignedPubkeys.push(pubkeys[i]);
            }
        }
        return {unsignedPubkeys: unsignedPubkeys, signedPubkeys: signedPubkeys};

    }
    Brollet.MultiSigScript.prototype.unsignedPubkeys = function () {
        return this.validateSignatures().unsignedPubkeys;
    }
    Brollet.MultiSigScript.prototype.signedPubkeys = function () {
        return this.validateSignatures().signedPubkeys;
    }
    /*
    *  Expects redeem-script bytes
    */
    Brollet.RedeemScript = function (redeemScriptBytes) {
        this.script = new Bitcoin.Script(redeemScriptBytes);
        this.scriptChunks = this.script.chunks;
        this.nRequired = this.scriptChunks[0] - Bitcoin.Opcode.map.OP_1 + 1;
        this.nPubkeys = this.scriptChunks[this.scriptChunks.length-2] - Bitcoin.Opcode.map.OP_1 + 1;

        //Collect public keys from redeem-script.
        var pubkeys = [];
        for (var i=0; i<this.nPubkeys; i++){
            pubkeys.push(this.scriptChunks[i+1]);
        }
        this.pubkeys = pubkeys;
    }

    Brollet.RedeemScript.prototype.getAddress = function () {
        return Bitcoin.Address.fromMultiSigScript(this.script.buffer);
    }

    Brollet.OutputsRequester = function(addresses){
        this.outputs = null;
        this.singleListeners = [];
        var tihs = this;
        function t(i){tihs.processOutputs(i);};
        $.post('cgi-bin/unspent.py', {addresses: addresses.join(",")}, t);
    }

    Brollet.OutputsRequester.prototype.processOutputs = function (outputs){
        this.outputs = outputs;
        var sListeners = this.singleListeners.slice(0);
        this.singleListeners = null;
        for (var i=0; i<sListeners.length; i++){
            sListeners[i](outputs);
        }
    }

    Brollet.OutputsRequester.prototype.addSingleListener = function (listener){
        if(this.outputs != null){
            listener(this.outputs);
        }else{
            this.singleListeners.push(listener);
        }
    }

    Brollet.Key = function (hexKey) {
        this.hexKey = hexKey;
    }

    Brollet.Key.prototype.getECKey = function () {
        var bigIntKey = new BigInteger(this.hexKey, 16)
            .mod(getSECCurveByName("secp256k1").getN());
        return new Bitcoin.ECKey(bigIntKey);
    }

    Brollet.Key.prototype.pubKeyAsHex = function () {
        var eckey = this.getECKey();
        return Crypto.util.bytesToHex(eckey.getPub());
    }

    Brollet.Key.prototype.pubKeyAsBytes = function () {
        return this.getECKey().getPub();
    }

    Brollet.Key.prototype.getBitcoinAddress = function () {
        var eckey = this.getECKey();
        var pub = eckey.getPub();
        var pubKeyHash = Bitcoin.Util.sha256ripe160(pub);
        return new Bitcoin.Address(pubKeyHash);
    }

    Brollet.Key.prototype.base58Address = function () {
        return this.getBitcoinAddress().toString();
    }

})(
'object' === typeof module ? module.exports : (window.Brollet = {})
);

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

function pad(str, len, ch) {
    padding = '';
    for (var i = 0; i < len - str.length; i++) {
        padding += ch;
    }
    return padding + str;
}

function decodeBitcoinQtPrivKey(sec){
    var res = parseBase58Check(sec);
    var version = res[0];
    var payload = res[1];
    var compressed = false;
    if (payload.length > 32) {
        payload.pop();
        compressed = true;
    }
    var eckey = new Bitcoin.ECKey(payload);
    eckey.version = version;
    return eckey;
}

(function($){


    var DEFAULT_BLOCK_PRIORITY_SIZE = 27000;
    var CENT = new BigInteger('1000000',10);
    var COIN = 100000000;
    var MAX_BLOCK_SIZE = 1000000;
    var MAX_BLOCK_SIZE_GEN = MAX_BLOCK_SIZE / 2;
    var MAX_STANDARD_TX_SIZE = MAX_BLOCK_SIZE_GEN / 5;
    var minTxFee = new BigInteger('10000', 10); //nMinTxFee - In the main client it is set as 10000.

    var gen_from = 'pass';
    var gen_compressed = false;
    var gen_eckey = null;
    var gen_pt = null;
    var gen_ps_reset = false;
    var TIMEOUT = 600;
    var timeout = null;

    // added these for the fast generation wallet
    var Seed = {}
    var Keys = {}
    var ImportedKeys = {} //All keys imported into the wallet, for example keys sent via email.
    // Array of [{address: .., value: satoshis, txHash: ..., outputIndex: ..., confirmations: ...}, ....]
    var Unspent = [];
    var Bal = {}
    var TotBal = BigInteger.ZERO;  // this is ReadyBal + PendingBal
    var PendingBal = BigInteger.ZERO;  // this is amount we received but not yet confirmed
    var ReadyBal = BigInteger.ZERO;  // this is the confirmed amount we received and ready to spend
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

    var keysAsBase58 = function(){
        var result = [];
        for(var i in Keys){
            if(i != null) result.push(i);
        }
        return result;
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

// given a hex string return base58 string
function hex2base58(s){ return Bitcoin.Base58.encode(hex2bytes(s))}
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

// given a public key in hex return the base58 bitcoin address
function pubKey2bitAdd(k){
  var b = new Bitcoin.Address(hex2bytes(pubKey2pubKeyHash(k)));
  return b.toString()
}

// given a private key in hex return the base64 bitcoin address
function key2bitAdd(k){ return pubKey2bitAdd(key2pubKey(k)) }

function key2base58addy(privKey){
    var pbKey = key2pubKey (privKey)
    var btcAddr = pubKey2bitAdd(pbKey);
    return btcAddr
}
// given a ScriptPubKey as a string convert it to bytes
function parseScript(script) {
        var newScript = new Bitcoin.Script();
        var s = script.split(" ");
        for (var i=0; i<s.length; i++) {
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
        for(var i = string.length; i > -1; i-=2) {
                out.push(string.substring(i-2,i));
        }
//      console.debug(string);
//      console.debug(out.join(""));
        return out.join("");
}

// given a number (float or int) return the number
// use round instead of floor so that we don't lose small amounts due to floating percision
function num2sathoshi(f){ return Math.round(f*100000000.0) }

function btcToSatoshi(f){ return Math.round(f*100000000.0);}

// given a number (float or int) return the number
function sathoshi2num(f){ return f/100000000.0 }

function satoshiToBtc (f) { return f/100000000.0 }

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

function containsSubCentOutput (sendTx){
    for (var i=0; i<sendTx.outs.length; i++){
        if (sendTx.outs[i].valueAsInt().compareTo(CENT) < 0) return true;
    }
    return false;
}

function lowPriorityOrLargeTransaction (sendTx){
    var txPriority = transactionPriority (sendTx);
    if (txPriority < (COIN * 144 / 250)) return true;
    return (sendTx.serialize().length >= DEFAULT_BLOCK_PRIORITY_SIZE - 17000);
}

function txTooBig (sendTx){
    return (sendTx.serialize().length > MAX_STANDARD_TX_SIZE);
}

function sizeOfTxOut (txOut){
    return serializeTxOut (txOut).length;
}

function serializeTxOut (txOut){
    var buffer = [];
    buffer = buffer.concat(txOut.value);
    var scriptBytes = txOut.script.buffer;
    buffer = buffer.concat(Bitcoin.Util.numToVarInt(scriptBytes.length));
    buffer = buffer.concat(scriptBytes);
    return buffer;
}

function isDust (txOut){
    var nMinRelayTxFee = new BigInteger('10000',10);
    var nValue = txOut.valueAsInt();
    var txOutSize = new BigInteger(''+sizeOfTxOut (txOut), 10);
    //return ((nValue*1000)/(3*(txOutSize+148))) < nMinRelayTxFee;
    var buf = nValue.multiply (new BigInteger(''+1000, 10)) .divide(
        new BigInteger('3', 10).multiply(txOutSize.add(new BigInteger(''+148, 10)))
    );
    return buf.compareTo(nMinRelayTxFee) < 0;
}

//Requires that transaction inputs have main chain depth.
function transactionPriority (sendTx){
    var priority = 0;

    for(var i=0; i<sendTx.ins.length; i++){
        var txIn = sendTx.ins[i];
        var val = num2sathoshi(txIn.value);
        var block = txIn.confirmations; //Could be Bug - double check transaction fee implmentation.
        priority += (val * (block +1));
    }
    var r = sendTx.serialize().length
    var result = priority / r;
    return result;
}

// from - list of zero or more addresses. [ addr1, ..., addrN ]
// to - list of address, amount pairs. [ [addr1, BigInteger(val1)], [addr2, BigInteger(val2)]]
// change - one address to accept transaction change.
// fee - the fee amount to broadcast onto the network. BigInteger()
function makeTxObj(from, to, changeAddress, feeAmt, onlyFromAddrs){
    if (onlyFromAddrs == null) onlyFromAddrs = false;
    var amountTotal = feeAmt;

    for (var i=0; i<to.length; i++){
        amountTotal = amountTotal.add(new BigInteger(''+to[i][1], 10));
    }

    if (amountTotal.compareTo(BigInteger.ZERO) <= 0){
        alert("Amount must be greater than 0.");
        return;
    }

    // get a list of unspent transaction we can send from; make sure the from address isn't also a to address
    var txInputs = collectUnspentOutputs(from, amountTotal, to, onlyFromAddrs);
    if (txInputs == null){ alert('Insufficient funds.'); return }


    sendTx = new Bitcoin.Transaction()
    // create the outputs
    for(var i=0; i<to.length; i++){
        var oPut = to[i];
        toAddr = new Bitcoin.Address(oPut[0]);

        sendTx.addOutput(toAddr, oPut[1]);
        // add the address so it is easy to see on the debug page
        sendTx.outs[sendTx.outs.length-1].address = oPut[0];
        if (isDust(sendTx.outs[sendTx.outs.length-1])){
            alert("Dust transaction to address: "+ oPut[0] + " and amount:"+amt+" BTC(s)")
            return null;
        }
    }

    var changeAmt = txInputs.change;
    if (changeAmt.compareTo(CENT) < 0 &&
            changeAmt.compareTo(BigInteger.ZERO) > 0 &&
            feeAmt.compareTo(minTxFee) < 0){

        var moveToFee = changeAmt.min(minTxFee.subtract(feeAmt));
        changeAmt = changeAmt.subtract(moveToFee);
        feeAmt = feeAmt.add(moveToFee);
    }

    if(changeAddress == ''){
        if(from.length > 0){
            changeAddress = from[0];
        }else{
            changeAddress = txInputs.outputs[0].address;
        }
    }

    if (changeAmt.compareTo(BigInteger.ZERO)>0 ){
        toAddr = new Bitcoin.Address(changeAddress);
        var txOutput = Bitcoin.TransactionOut.create(toAddr, changeAmt);
        if (!isDust(txOutput)){ //change added to fee if dust.
            sendTx.addOutput(toAddr, changeAmt);
            // add the address so it is easy to see on the debug page
            sendTx.outs[sendTx.outs.length-1].address = changeAddress;
        }else{
            feeAmt = feeAmt.add(changeAmt);
        }
    }

    // create the inputs
    //   we have to do this in two loop instead of one loop, otherwise it does not work
    //   all the inputs have to be created before they are signed.
    //   The signing looks at the whole transaction.
    hashType = 1   // SIGHASH_ALL
    for(var i=0; i<txInputs.outputs.length; i++){
        var txInput = txInputs.outputs[i];
        var script = new Bitcoin.Script(Crypto.util.hexToBytes(txInput.script));
        hash = hex2base64(endian(txInput.txHash));
        tx = new Bitcoin.TransactionIn({
            outpoint: {hash: hash, index: txInput.outputIndex},
                                   script: script, sequence: 4294967295})
        sendTx.addInput(tx)
    }

    // now sign the input in the second loop
    //console.log(JSON.stringify(tra, '', '  '))
    for(var i=0; i<txInputs.outputs.length; i++){
        var txInput = txInputs.outputs[i];
        script = sendTx.ins[i].script;
        signHash = sendTx.hashTransactionForSignature(script, i, hashType)
        //console.debug(signHash+'\n')
        key = bigInt2ECKey(hex2bigInt(Keys[txInput.address]))
        //pkh = script.simpleOutPubKeyHash()
        sign = key.sign(signHash)
        sign.push(parseInt(hashType, 10))
        pk = key.getPub()
        sendTx.ins[i].script = Bitcoin.Script.createInputScript(sign, pk)
        // add this just so we can easily see what address was used to send from
        sendTx.ins[i].address = txInput.address
        sendTx.ins[i].value = satoshiToBtc(txInput.value);
        //Add chain depth for calculating transaction priority.
        sendTx.ins[i].block = txInput.block
        sendTx.ins[i].confirmations = txInput.confirmations;
    }
    if (txTooBig (sendTx)){
        alert("Unable to send bitcoins, transaction too big.")
        return null;
    }
    var storageFee = lowPriorityOrLargeTransaction (sendTx) ? minTxFee.multiply(new BigInteger(''+(1+Math.floor(sendTx.serialize().length/1000)), 10)) : BigInteger.ZERO;
    var subCentFee = containsSubCentOutput (sendTx) ? minTxFee : BigInteger.ZERO;
    var minFee = storageFee.max(subCentFee).max(minTxFee);
    if (feeAmt.compareTo(minFee) < 0){
        alert("Fee amount too small, try:"+satoshiToBtc(minFee.intValue())+" BTC");
        return null;
    }
    alert("Fee is "+satoshiToBtc(feeAmt.intValue())+" BTC");
    return sendTx;
}

// given an array of bitcoin addresses and an amount, return a list of
//    transaction references which have a total value greater then or
//    equal to the given amount and which use older transactions first
//    while trying to use the given addresses before other address.
//    Do you get what I mean; probably not. Just read the code :-)
// we are also given a list of the addresses not to use in 'tha'
// formerly bitAddArr2transRefArr
function collectUnspentOutputs(fromAddrs, amount, toAddrs, onlyFromAddrs){
    var eligibleOutputs = confirmedOutputs (Unspent);


    var total = BigInteger.ZERO;
    var secondaryOutputs = [];
    var includedOutputs = [];
    // try to pick from the given bitcoin addresses
    for (var i=0; i<eligibleOutputs.length; i++){
        var output = eligibleOutputs[i];
        if (toAddrs.indexOf(output.address) != -1) continue; //Skip to-addr outputs.

        if (fromAddrs.indexOf(output.address) != -1){ //found in from-addrs
            includedOutputs.push(output);
        }else{
            secondaryOutputs.push(output);
        }
    }

    var result = collectAmt(amount, includedOutputs);
    if (result.isEnough || onlyFromAddrs) return result;
    // now pick from the other addresses, since the given address did not have enough
    includedOutputs = includedOutputs.concat(secondaryOutputs);
    result = collectAmt(amount, includedOutputs);
    if (!(result.isEnough)) return null;

    // now remove any excess that we picked up
    //   for example we needed to send 10, we picked up 1, 2, then 12, so we don't need
    //   the 1 and 2 since 12 has enough. To remove them reverse the order and go through
    //   until we have enough and any left after than can be removed.
    var rOutputs = result.outputs.slice(0);
    rOutputs.reverse()
    var altResult = collectAmt(amount, rOutputs);
    return altResult;
}

function confirmedOutputs (outputs){
    var eligibleOutputs = [];

    // first sort the unspent transactions with the oldest first
    // but skip unconfirmed transactions; where block=0
    for(var i=0; i<Unspent.length; i++){
        var output = Unspent[i];
        if (output.confirmations > 0){
            eligibleOutputs.push(output);
        }
    }
    //Sort by no. confirmations.
    eligibleOutputs.sort(compareBlockDesc);
    return eligibleOutputs;
}
/*
* satoshiAmt - BigInteger, amount is expected to include the fee.
*/
function collectAmt (satoshiAmt, uOutputs) {
    uOutputs.sort (compareBlockDesc);
    var bufAmount = BigInteger.ZERO;
    var bufOutputs = [];
    for (var i=0; i<uOutputs.length; i++){
        var output = uOutputs[i];
        bufOutputs.push (output);
        bufAmount = bufAmount.add(new BigInteger(''+output.value, 10));
        if (bufAmount.compareTo(satoshiAmt) >= 0) break;
    }
    var change = bufAmount.subtract(satoshiAmt);

    var enough = true;
    if (bufAmount.compareTo(satoshiAmt) < 0) {
        enough = false;
        change = BigInteger.ZERO;
    }

    return {total: bufAmount, change: change, outputs: bufOutputs, isEnough: enough};
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
        //if (wn == ''){ alert("Enter wallet name."); return }
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
        var a = confirm('Close the Brollet wallet?')
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
        TotBal = BigInteger.ZERO;
        PendingBal = BigInteger.ZERO;
        ReadyBal = BigInteger.ZERO;
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
        $("#homeSendSendBtn")[0].disabled = false;
    }

    function homeSendByEmailForm(){
        $('#homeSendMessageDiv').show()
        $('#homeSendPasswordDiv').show()
        $('#homeSendToEmailDiv').show()
        $('#homeSendFromEmailDiv').show()
        $('#homeSendFromEmail').html(G.email)
        $('#homeSendToDiv').hide()
        $("#homeSendSendBtn")[0].disabled = true;
        UI.sendBy = 'email'
    }

    function homeSendCodeDone(){
        $('#homeSendCodeForm').hide()
        $('#homeMainForm').show()
    }

    function mozillaScan(videoPass, videoFail, scanCodePass, scanCodeFail){
        var video = document.createElement('video')
        var canvas = document.createElement('canvas')
        var photo = document.createElement('img')
        var width = 600
        var height = 400
        var streaming = false
        var continueScanning = true
        var videoStream

        function startup(){
            navigator.getMedia = ( navigator.getUserMedia ||
                         navigator.webkitGetUserMedia ||
                         navigator.mozGetUserMedia ||
                         navigator.msGetUserMedia);

            navigator.getMedia(
                {
                    video: true,
                    audio: false
                },
                function (stream){
                    videoStream = stream
                    if (navigator.mozGetUserMedia){
                        video.mozSrcObject = stream
                    } else {
                        var vendorURL = window.URL || window.webkitURL;
                        video.src = vendorURL ? vendorURL.createObjectURL(stream) : stream;
                    }
                    video.play();

                    $(video).css('-webkit-transform', 'scale(0.5)')
                    $(video).css('-moz-transform', 'scale(0.5)')
                    $(video).css('-ms-transform', 'scale(0.5)')
                    $(video).css('-o-transform', 'scale(0.5)')
                    $(video).css('transform','scale(0.5)')
                    $(video).css('margin-left', '-150px')
                    $(video).css('margin-top', '-100px')
                    $(video).css('margin-bottom', '-100px')
                },
                function(err){
                    console.log("An error occurred! "+err);
                    console.log(err);
                    continueScanning = false
                    videoFail(err);
                }
            )
            video.addEventListener('canplay', function(ev){
                if(!streaming){
                    height = video.videoHeight / (video.videoWidth/width);
                    video.setAttribute('width', width);
                    video.setAttribute('height', height);
                    video.setAttribute('width', width);
                    video.setAttribute('height', height);
                    streaming = true;
                }
            }, false);
        }

        var imageData = null
        var gCanvas = null
        var gContext = null

        function initCanvas(){
            gCanvas = document.createElement("canvas")
            gCanvas.style.width = width+"px"
            gCanvas.style.height= height+"px"
            gCanvas.width = width
            gCanvas.height = height
            gContext = gCanvas.getContext("2d")
            gContext.clearRect(0,0,width, height)
            imageData = gContext.getImageData(0,0,320,240)
        }

        function takeImage(){
            gContext.drawImage(video, 0,0 )
            imageData = gContext.getImageData(0,0,gCanvas.width, gCanvas.height)
            data= gCanvas.toDataURL('image/png')
            photo.setAttribute('src', data)
            photo.width = 400
            photo.height = 400
            return data
        }

        function qrCodeScan(){
            takeImage()
            qrcode.width = gCanvas.width
            qrcode.height = gCanvas.height
            qrcode.imagedata = imageData
            qrcode.result = qrcode.process (gContext)
            scanCodePass(qrcode.result)
        }

        function stop(){
            continueScanning = false
            if(video != null)video.pause()
            if(videoStream != null) videoStream.stop()
        }

        startup()
        initCanvas()
        videoPass(video, null)

        function scanning(){
            try{
                qrCodeScan()
            } catch (e){
                console.log(e)
                scanCodeFail(e)
            }
            if(continueScanning){
                setTimeout(scanning, 150)
            }
        }
        Miniqr.stop = stop
        setTimeout(scanning, 500)
    }
    function homeScan(){
        mozillaScan(homeScanVideoPass, homeScanVideoFail, homeScanCodePass, homeScanCodeFail)
        if(true) return
        alert('Currently only these browsers support this feature:\n  on PC, Chrome and Opera;\n  on mobile, Opera v12.')
        var opts = {
            fps: 4,
            width: 320,
            height: 240
        }
        $('#qrscanText').html('') //reset
        $('#qrscanImage').html('') //reset
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


    function homeTransactionsShow(){
        getWalletTransactions();
        $("#homeTransactions").show();
        $("#homeMainForm").hide();
    }

    function homeTransactionsHide(){
        $("#homeMainForm").show();
        $("#homeTransactions").hide();
    }

    function multiSigSendShow () {
        $("#homeMultiSigSend").show();
        $("#homeMainForm").hide();

        var addys = Object.keys(Keys);
        var brolletKey = new Brollet.Key(Keys[addys[0]]);
        $("#brolletPubKey").val(brolletKey.pubKeyAsHex());
    }

    function multiSigSendHide(){
        $("#homeMainForm").show();
        $("#homeMultiSigSend").hide();
        $("#homeMultiSigSend input").val("");
        $("#homeMultiSigSend textarea").val("");
    }

    function showComposeMultiSigRedeem(){
        $("#multiSigCompose").show();
        $("#homeMainForm").hide();
    }

    function hideComposeMultiSigRedeem(){
        $("#homeMainForm").show();
        $("#multiSigCompose").hide();
    }

    function showPubkeysMultiSig(){
        displayMultisigPubkeys();
        $("#multiSigPubkeys").show();
        $("#homeMainForm").hide();
    }

    function hidePubkeysMultiSig(){
        $("#homeMainForm").show();
        $("#multiSigPubkeys").hide();
        $("#multiSigPubkeys .pubkey-row").remove();
    }

    function showSignMultiSigRedeem(){
        $("#multiSigRedeemSignHex").show();
        $("#homeMainForm").hide();
    }

    function hideSignMultiSigRedeem(){
        $("#homeMainForm").show();
        $("#multiSigRedeemSignHex").hide();
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

    function clearRedeemForm(){
        $('#homeRedeemCode').val('')
        $('#homeRedeemPassword').val('')
        $('#homeRedeemFee').val('')
        $('#homeRedeemInfo').html('')
        $('#homeRedeemBalance').html('')
    }
    function homeRedeemCancel(){
        $('#homeMainForm').show()
        $('#homeRedeemForm').hide()
        clearRedeemForm()
    }

    function validateFee(amt){
        if(isNaN(parseFloat(amt))){
            alert("Fee must be a number.")
        }
    }
    function homeRedeemNow(){
        alert('about to redeem now')
        if($('#importedTransfer').prop('checked')){
            var fee = $("#homeRedeemFee").val()
            if(fee == '')fee = '0.0'
            validateFee(fee)
            transferFromImportedToBrollet(fee, function(d){
                if (d == null) return;
                homeUpdateBalance()
                $('#homeMainForm').show()
                $('#homeRedeemForm').hide()
                clearRedeemForm();
            });
        }
    }

    function getRecoverPrivateKey(){
        var email = $("#homeRecoverEmail").val()
        var code = $("#homeRecoverCode").val().split("\n").join("")
        var decryptedCode = AESdecrypt(code, email).split("\n")
        var recoverCode = null;
        for(var i=0; i<decryptedCode.length; i++){
            if(decryptedCode[i].indexOf("recover:") > -1){
                recoverCode = decryptedCode[i].split("recover:")[1]
                recoverCode = removeWhiteSpace(recoverCode)
                break;
            }
        }
        var rand = AESdecrypt(recoverCode, seed2key(Seed.main, 0))
        var info = AESdecrypt(code, email).replace(/\nredeem: [\s\S]*/, '\n')

        key = hex2hexKey(hash256(info+rand))
        return key

    }

    function homeSetRecoverInfo(){
        var privKey = null
        try{
            privKey = getRecoverPrivateKey();
            $("#homeRecoverPre").html("<pre>Key recovered.</pre>")

        } catch (e){
            $("#homeRecoverPre").html("<pre>Unable to recover.</pre>")
            throw e
        }
        if (privKey == null)return;
        var btcAddy = key2base58addy(privKey)
        function balanceCallback(data){
            var pending = 0;
            var confirmed = 0;
            for(var k in data){
                if (data[k].address == null)continue;
                if(data[k].block > 0){
                    confirmed += data[k].sathoshi
                }else{
                    pending += data[k].sathoshi
                }
            }
            var total = sathoshi2num (pending + confirmed)
            pending = sathoshi2num(pending)
            confirmed = sathoshi2num(confirmed)
            var buf = bal2html(total, confirmed, pending)
            $("#homeRecoverBalancePre").html(buf)
        }
        getUnspentBalance ([btcAddy], balanceCallback)
    }
    function homeRecoverNow(){
        var privKey = getRecoverPrivateKey()
        addImportedKey (privKey)
        var fee = $("#homeRecoverFee").val()
        if(fee == '')fee = '0.0'
        validateFee(fee)
        function callback(data){
            if (data == null) return;
            $("#homeMainForm").show()
            $("#homeRecoverForm").hide()
            $("#homeRecoverEmail").val('')
            $("#homeRecoverCode").val('')
            $("#homeRecoverFee").val('')
            $("#homeRecoverPre").html('')
            $("#homeRecoverBalancePre").html('')
            homeUpdateBalance()
        }
        transferFromImportedToBrollet(fee, callback)


    }

    function homeRecoverForm(){
        $('#homeRecoverForm').show()
        $('#homeMainForm').hide()
    }

    function clearRecoverForm(){
        $("#homeRecoverPre").html('')
        $("#homeRecoverBalancePre").html('')
        $("#homeRecoverCode").val('')
        $("#homeRecoverFee").val('')
        $("#homeRecoverEmail").val('')
    }

    function homeRecoverCancel(){
        $('#homeMainForm').show()
        $('#homeRecoverForm').hide()
        clearRecoverForm()
    }

    function homeSendCancel(){
        $('#homeMainForm').show()
        $('#homeSendForm').hide()
        $("#homeSendBalanceAfter").html('')
        $("#homeSendAmount").val('')
        $("#homeSendFee").val('')
        $("#homeSendTo").val('')
        $("#homeSendToEmail").val('')
        $("#homeSendMessage").val('')
        $("#homeSendPassword").val('')

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
        $.post('cgi-bin/unspent.py', {addresses: addrArr.join(",")}, homeUpdateBalanceFill)
    }

    function updateAllSpentInfo (callback){
        var addrArr = []
        for(ba in Keys){
            addrArr.push(ba)
        }
        function callbackWrapper (data){
            Unspent = data
            callback(data)
        }
        getUnspentBalance(addrArr, callbackWrapper)
    }
    //Retreives the the unspent balance for the specified addresses.
    //addrArr should be an array of bitcoin address strings as base58.
    function getUnspentBalance(addrArr, callback){
        var addrStr = JSON.stringify(addrArr)
        function callbackWrapper(data){
            var result = parseUnspentDataBase(data, addrArr)
            callback(result);
        }
        $.post('cgi-bin/unspent.py', {addresses: addrArr.join(",")}, callbackWrapper, 'text')
    }

    function parseUnspentDataBase(data, actualKeys){
        var i, res, tr, script, sa, addr;
        var unspentResult = [];
        res = JSON.parse(data, '', '  ')
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
            if(actualKeys.indexOf(tr.address) >= 0){
                unspentResult[i] = res[i]
            }
        }
        return unspentResult

    }
    function parseUnspentData(data){
        Unspent = data; //Should be Brollet.Unspent
        var x = JSON.stringify(data, '', '  ')
        $('#debugUnspent').val(x)
    }

    function homeUpdateBalanceFill(data){
        parseUnspentData(data) // fills the Unspent obj
        setBalance() // gets data from the Unspent obj
        homeBalanceShow()
    }

    function setBalance(){
        TotBal = BigInteger.ZERO;
        PendingBal = BigInteger.ZERO;
        ReadyBal = BigInteger.ZERO;
        Bal = {}
        for(k in Keys){
            Bal[k] = BigInteger.ZERO;
        }
        for (var i=0; i<Unspent.length; i++){
            var uOutput = Unspent[i]
            var value = new BigInteger(''+uOutput.value,10);
            Bal[uOutput.address] = Bal[uOutput.address].add(value);
            if (uOutput.confirmations > 0){
                ReadyBal = ReadyBal.add(value);
            }else{
                PendingBal = PendingBal.add(value);
            }
            TotBal = TotBal.add(value);
        }
    }

    function homeBalanceShow(){
        var i, b, s, c
//        s = '' + TotBal
//        s = '<nobr>'+TotBal+' = <font color=green title="Ready to spend">'+ReadyBal+' + <font color=red title="Pending confirmation">'+PendingBal+'</nobr>'
        s = bal2html(TotBal, ReadyBal, PendingBal)
        $('#homeBalanceLabel').html(s)
        $('#homeReceiveBalance').html(s)
        $('#homeSendBalanceBefore').html(s)
        $("#multiSigSendBalanceBefore").html(s);
        s = ''
        c = 0
        for(i in Keys){
            b = satoshiToBtc(Bal[i]);
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
        var fee = extractFee ($("#homeSendFee"));
        var sendAmt = extractAmount ($("#homeSendAmount"));
        var afterBalance = balanceMinus(fee.add(sendAmt));
        $('#homeSendBalanceAfter').html (satoshiToBtc(afterBalance));
    }

    function homeSetRedeemInfo(privateKeyListener){
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
                if(privateKeyListener != null){
                    privateKeyListener(key)
                }else{
                    addImportedKey(key);
                }
                bita = key2bitAdd(key)
// now check if the bitcoins are still there
                addrArr = []
                addrArr.push(bita)
                addrStr = JSON.stringify(addrArr)
                $('#homeRedeemBalanceDiv').show()
                $('#homeRedeemBalance').html(WaitingIcon)
                $.post('cgi-bin/unspent.py', {addresses: addrArr.join(",")}, homeRedeemBalanceFill, 'text')
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
        var k = Object.keys(bal)[0]
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

    function uOutputsToHtml (uOutputs) {
        var total = BigInteger.ZERO;
        var pending = BigInteger.ZERO;
        var ready = BigInteger.ZERO;
        for (var i=0; i<uOutputs.length; i++){
            var uOutput = uOutputs[i];
            var value = new BigInteger(''+uOutput.value,10);
            if (uOutput.confirmations > 0){
                ready = ready.add(value);
            }else{
                pending = pending.add(value);
            }
            total = total.add(value);
        }
        return bal2html(total, ready, pending);
    }

    function bal2html(total, ready, pending){
        s = '<nobr><pre>' +
            satoshiToBtc(total.intValue()) +
            ' = <font color=green title="Ready to spend">' +
            satoshiToBtc(ready.intValue()) +
            ' + <font color=red title="Pending confirmation">' +
            satoshiToBtc(pending.intValue()) + '</pre></nobr>'
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
        bal['total'] = {'total':0, 'ready':0, 'pending':0}
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
     // method for getting server to send transaction
    // transObj - Bitcoin.Transaction.
    function sendTransaction (transObj, callback){
        //var txJSON = TX.toBBE (transObj)
        var tx = transObj.serialize()
        var txs = {tx: bytes2hex (tx)};
        $.post ('cgi-bin/send.py', {tx: bytes2hex(tx)}, callback, 'text')
    }

    function homeSendTx(){
        var tx, txs, txj
        var emailTx = null
        if (UI.sendBy == 'email'){
          emailTx = homeMakeEmailTx()
          if (! emailTx){
              console.log("invalid homeMakeEmailTx")
              return;
          }
        }
        tx = homeMakeTx()
        if (tx == undefined){ console.log("tx == undefined"); return; }
        txs = {tx: tx}
        txj = JSON.stringify(txs)
        alert(tx)
        $.post('cgi-bin/send.py', {tx: tx}, handleSentTx(emailTx));
    }

    function transactionEmailSent (data){
        var result = JSON.parse(data)
        if(result.status == 'Error'){
            if(result.pythonerror != null){
                $("#sendingInfo").html("<p>Error report.</p><pre>"+result.pythonerror+"</pre>")
            }else{
                $("#sendingInfo").html("<p>Error report.</p><pre>"+result.error+"</pre>")
            }
        }
        if(result.status == 'OK'){
            $("#sendingInfo").html("<p>Email sent!</p>")
            function clearInfo(){
                $("#sendingInfo").html("")
                homeSendCancel();
            }
            setTimeout(clearInfo, 3000)
        }

        if(result.status == 'OK'){

        }else{
            $("#showEmailCodeBtn").removeClass("hide")
            $("#homeSendSendBtn").hide();
            $("#homeSendCancelBtn").hide();
        }
    }
    function hideTestEmailModal(){
        $("#from-email").val('');
        $("#to-email").val('');
        $("#email-msg").val('');
        $("#email-password").val('');
        $("#test-email-sending-info").html('');
        $(".email-modal-wrapper").hide();
    }

    function showTestEmailModal(){
        $(".email-modal-wrapper").show();
    }

    function sendTestEmail(){
        var emailConfig = {
            email_host: $('#smtpHost').val(),
            email_port: $('#smtpPort').val(),
            email_username: $('#smtpUsername').val(),
            email_password: $('#smtpPassword').val(),
        }
        var emailMsg = {
            sender: $("#from-email").val(),
            to: $("#to-email").val(),
            subject: "Brollet test email.",
            message: $("#email-msg").val()
        }
        function callback(i){
            var result = JSON.parse(i);
            if(result.status == 'Error'){
                if(result.pythonerror != null){
                    $("#test-email-sending-info").html("<p>Error report.</p><pre>"+result.pythonerror+"</pre>")
                }else if(result.error != null){
                    $("#test-email-sending-info").html("<p>Error report.</p><pre>"+result.error+"</pre>")
                }else{
                    $("#test-email-sending-info").html("<p>Error report.</p><pre>"+result.message+"</pre>")
                }
            }
            if(result.status == 'OK'){
                $("#test-email-sending-info").html("<p>Email sent!</p>")
            }

        }
        $("#test-email-sending-info").html(WaitingIcon);
        var buf = { emailConfig: emailConfig, emailMsg: emailMsg, password: SettingsPassword.get()};
        $.post('cgi-bin/testemail.py', JSON.stringify(buf),
            callback, 'text' )
    }

    function sendTransactionEmail(emailTx){
        $("#sendingInfo").html(WaitingIcon);
        $("#debugEmailJson").val(JSON.stringify(emailTx));
        emailTx['__'] = Math.floor(Math.random()*10000000000);
        $.post('cgi-bin/emailbitcoins.py', emailTx,
                   transactionEmailSent, 'text')
    }

    function showEmailCode(){
        $("#homeSendCancelBtn").show();
        $("#homeSendSendBtn").show();
        $("#sendingInfo").html("");
        $("#showEmailCodeBtn").addClass("hide")
        $("#homeSendSendBtn").css('visibility','inherit')
        $('#homeSendToEmail').val('')
        $('#homeSendTo').val('')
        $('#homeSendAmount').val('')
        $('#homeSendFee').val('')
        $("#homeSendMessage").val('')
        $("#homeSendPassword").val('')
        $('#homeSendBalanceAfter').html('')
        $('#homeSendCodeForm').show()
        $('#homeSendCode').select()
        $('#homeSendForm').hide()
    }

    function handleSentTx(emailTx){
        return function(data){
            var res = data;
            if (res.status == 'OK'){
                alert('Sent\n'+res.message)
                if (UI.sendBy == 'email'){
                    if (emailTx != null){
                        alert('emailTx:\n'+emailTx.code+'\n'+
                             emailTx.sender+'\n'+
                             emailTx.to);
                        sendTransactionEmail(emailTx)
                    }else{
                        showEmailCode();
                    }
                }
                else{
                    $('#debugSendResult').val(res.message)
                    $('#homeSendTo').val('')
                    $('#homeSendAmount').val('')
                    $('#homeSendFee').val('')
                    $('#homeSendBalanceAfter').html('')
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
    }

    function homeMakeTx(){
        var toAddy = removeWhiteSpace($('#homeSendTo').val())
        if (toAddy == ''){ alert('To Address must be given.'); return }
        try{
            new Bitcoin.Address(toAddy);
        }catch(err){
            alert('To Address is not valid.'); return;
        }
        amount = extractAmount($('#homeSendAmount'));
        if (amount == null){ alert('Amount must be given.'); return }
        fee = extractFee($('#homeSendFee'));
        if (isNaN(fee)){ fee = BigInteger.ZERO; $('#homeSendFee').val('0') }
        if (balanceMinus(amount.add(fee)) < 0){ alert('Insufficient funds.'); return }
        if ((G.pin != undefined) && (G.pin != '')){
          spin = prompt("Enter session pin: ");
          if (spin != G.pin){ return }
        }
        $('#debugTransaction').val('')
        $('#debugHexTransaction').val('')
        var changeAddr = ''
        txo = makeTxObj([], [[toAddy, amount]], changeAddr, fee)
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
the above message will already be known from the Brollet info.

To recover the sender just needs to provide the code and the email of the recipient.
If the sender added a password to redeem, it is not required to be recalled.
The private key needed to decrypt the Recover field of the above message will already
be in the senders Brollet.

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
      if (to == ''){ alert('To Email must be given.'); return null; }
      from = G.email
      amount = parseFloat(removeWhiteSpace($('#homeSendAmount').val()))
      if (isNaN(amount)){ alert('Amount must be given.'); return null;}
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

      return {to:to, sender: from, code: code} //code = transaction code.
    }

     // private bitcoin key in hexadecimal format.
    function addPrivateKey(privKey){
        var pbKey = key2pubKey(privKey)
        var btcAddr = pubKey2bitAdd(pbKey);
        Keys[btcAddr] = privKey
        Bal[btcAddr] = 0.0
    }

    // add hexadecimal private bitcoin key to imported keys.
    function addImportedKey(privKey){
        var pbKey = key2pubKey (privKey)
        var btcAddr = pubKey2bitAdd(pbKey);
        ImportedKeys[btcAddr] = privKey;
        addPrivateKey (privKey)
    }

    // transfers all bitcoins from imported keys into brollet keys
    function transferFromImportedToBrollet(fee, callback){
         var iAddrs = []
        for(var k in ImportedKeys){
            iAddrs.push(k)
        }
        function sTransactionCallback (data){
            if(data != null)advancedSentTx (data);
            if (callback != null){
                callback(data)

            }
        }
        function createTransfer(totalAmt){
             var firstAddy, secondAddy;
            for(var k in Keys){
                if(firstAddy == null){ firstAddy = k; continue;}
                if(secondAddy == null){ secondAddy = k; break;}
            }
            totalAmt -= fee
            if (totalAmt <= 0){
                alert("Not enough confirmed bitcoins.")
                return
            }
            var transObj = makeTxObjBase (iAddrs.join(" "), firstAddy+" "+totalAmt,
                                          secondAddy, fee, true);
            if(transObj == null){
                sTransactionCallback (null)
                return;
            }
            sendTransaction (transObj, sTransactionCallback)
        }

        function unspentCallback(d){
            var totalAmt = 0
            for( var k in d){
                if (d[k].address != null){
                    if(d[k].block > 0){
                        totalAmt += d[k].value
                    }
                }
            }
            createTransfer(totalAmt)
        }
        function getPrivateKeySpentInfo(){
            getUnspentBalance(iAddrs, unspentCallback)
        }
        updateAllSpentInfo(getPrivateKeySpentInfo);
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
          addPrivateKey(k1)
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
             addPrivatekey(k1)
          }
        }
      }
      if (UI.walletType == 'electrum'){
        Wsize = parseInt($('#advancedRange').val())
        if (isNaN(Wsize)){ Wsize = WsizeDefault }
        if (Wsize > WsizeMax){ Wsize = WsizeMax; alert('Keys in wallet limited to '+WsizeMax) }
        var s = $("#advancedSecret").val()
        if (s.split(" ").length > 2) s = mn_decode(s);
        var cnt = 0
        function processKey(r){
            k1 = base582hex(r[1])
            addPrivateKey(k1);
            cnt++
            if(cnt==Wsize){
                $("#advancedWalletWaitingIcon").html('')
                advancedNewKeys(Keys)
            }
        }

        function stretchingUpdate(amt){
            //console.log(amt)
        }
        $("#advancedWalletWaitingIcon").html(WaitingIcon)
        Electrum.init(s, stretchingUpdate,
                     function(){Electrum.gen(Wsize, processKey)})
        return

      }
      if (UI.walletType == 'armory'){
        Wsize = parseInt($('#advancedRange').val())
        if (isNaN(Wsize)){ Wsize = WsizeDefault }
        if (Wsize > WsizeMax){ Wsize = WsizeMax; alert('Keys in wallet limited to '+WsizeMax) }
        var s = $("#advancedSecret").val()
        if (s.split(" ").length < 2){
            var buf = Crypto.util.hexToBytes(s)
            var privKiy = buf.slice(32, 64)
            var chainCode = buf.slice(0,32)
            s = armory_encode_keys(privKiy, chainCode)
        }
        var cnt = 0
        function processKey(r){
            k1 = base582hex(r[1])
            p1 = key2pubKey(k1);
            b1 = pubKey2bitAdd(p1)
            Keys[b1] = k1
            Bal[b1] = 0.0
            cnt++
            if(cnt==Wsize){
                $("#advancedWalletWaitingIcon").html('')
                advancedNewKeys(Keys)
            }
        }
        $("#advancedWalletWaitingIcon").html(WaitingIcon)
        var i = Armory.gen(s, Wsize, processKey)
        if(i==null){
            $("#advancedWalletWaitingIcon").html('')
            alert("Invalid Armory Seed.")
        }
        return
      }
      if (! $.isEmptyObject(Keys)){
        advancedNewKeys (Keys)
      }
      else{
alert('No keys found.')
      }
    }

    function advancedNewKeys(keys){
        $('#advancedOpenForm').hide()
        $('#advancedMainForm').show()
        $('#advancedEmail').val('')
        $('#advancedWalletName').val('')
        $('#advancedWalletPassword').val('')
        $('#advancedSecret').val('')
        $('#advancedSessionPin').val('')
        $('#debugKeys').val(JSON.stringify(keys, '', '  '))
        advancedUpdateBalance()
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
            var kk = bigInt2ECKey(hex2bigInt(Keys[ba]))
            addrArr.push(ba)
        }
        $('#advancedBalanceLabel').html(WaitingIcon)
        $('#advancedReceiveBalance').html(s)
        addrStr = JSON.stringify(addrArr)
        $.post('cgi-bin/unspent.py', {addresses: addrArr.join(",")}, advancedUpdateBalanceFill, 'text')
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
        //Holds list of [{address: .., txHash: ..., outputIndex: ..., value: (satoshis), scriptPubKey: ..., txIndex: ...}, .... ]
        Unspent = [];
        Bal = {}
        TotBal = BigInteger.ZERO;
        PendingBal = BigInteger.ZERO;
        ReadyBal = BigInteger.ZERO;
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
        $.post('cgi-bin/send.py', {tx: tx}, advancedSentTx, 'text')
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

    //Validates public key
    function validPubKey () {
        var pubKey = arguments[0];
        if (typeof (pubKey) == "string"){
            pubKey = Crypto.util.hexToBytes (pubKey);
        }
        var curve = getSECCurveByName("secp256k1").getCurve();
        return ECPointFp.decodeFrom(curve, pubKey).isOnCurve();
    }

    function sortPubKeys (pubKeys) {
        return pubKeys.sort(function(a, b){
            a = Crypto.util.bytesToHex(a);
            b = Crypto.util.bytesToHex(b);
            if (a < b) return -1;
            if (a > b) return 1;
            return 0;
        });
    }

    function createMultiSigRedeemScript (threshold, pubkeys) {
        sortPubKeys(pubkeys);
        var rs = Bitcoin.Script.createMultiSigOutputScript(threshold, pubkeys);
        return rs;
    }

    /**
    *  Creates a multisig address and script.
    */
    function createMultiSig (threshold, pubkeys){
        var rs = createMultiSigRedeemScript (threshold, pubkeys);
        var redeemScript = Crypto.util.bytesToHex(rs.buffer);

        var address = new Bitcoin.Address.fromMultiSigScript(rs.buffer);

        return {'address':address,'redeemScript':redeemScript};
    }

    function multiSigSendBalanceAfter () {
        var amount = extractAmount ($("#multiSigSpendAmt"));
        if (amount == null) return;
        var fee = extractFee ($("#multiSigSpendFee"));
        if (fee == null) return;
        $("#multiSigSendBalanceAfter").html (
            satoshiToBtc(balanceMinus (amount.add(fee))));
    }

    function extractPublicKey (elem) {
        elem.removeClass ("invalid-input");
        var pubKey = elem.val();
        if (pubKey.length == 0) return -1;
        if(!validPubKey (pubKey)) {
            elem.addClass ("invalid-input");
            return null;
        }
        return Crypto.util.hexToBytes(pubKey);
    }

    function extractNumSigsRequired (elem, pubKeysLength) {
        elem.removeClass ("invalid-input");
        var v = elem.val();
        if (v.length == 0) return -1;
        var nSigs = parseInt (v);
        if (isNaN(nSigs) || nSigs < 1 || nSigs > pubKeysLength){
            elem.addClass ("invalid-input");
            return null;
        }
        return nSigs;

    }

    function clearMultiSigSendInfo () {
        $("#multiSigSendRedeemScript").val("");
        $("#multiSigSendAddress").val("");
    }

    function genBrolletRedeemScript () {
        var pubkeys = [];
        var validInputs = true;
        $(".multisigsend-pubkey").each(function (i,e) {
            var pubKey = extractPublicKey ($(e));
            if (pubKey != -1 && pubKey != null)
                pubkeys.push (pubKey);
            else if (pubKey == null)
                validInputs = false;
        });

        if (validInputs == false){
            clearMultiSigSendInfo();
            return;
        }

        var nSigs = extractNumSigsRequired ($("#sendSigsRequired"), pubkeys.length);
        if (nSigs == null || nSigs == -1) validInputs = false;

        if (validInputs == false){
            clearMultiSigSendInfo();
        } else {
            var buf = createMultiSig (nSigs, pubkeys);
            $("#multiSigSendRedeemScript").val(buf.redeemScript);
            $("#multiSigSendAddress").val(buf.address.toString());
        }

    }

    /*
    * Will extract Bitcoin Address from jquery element.
    *
    * If element contains invalid address, then error class will be
    * applied and null returned.
    *
    * allowblanks - if true, will return -1 if address is blank and
    * will not apply error class. default: false
    *
    */
    function extractAddress (elem, allowBlanks) {
        if (allowBlanks == null) allowBlanks = false;
        elem.removeClass ("invalid-input");
        var addy = removeWhiteSpace (elem.val());
        if (addy.length == 0){
            if (allowBlanks){
                return -1;
            }
            elem.addClass ("invalid-input");
            return null;
        }
        try{
            new Bitcoin.Address (addy);
        }catch (error) {
            elem.addClass ("invalid-input");
            return null;
        }
        return addy;
    }

    function extractAmount (elem, applyErrorCls) {
        if (applyErrorCls == null) applyErrorCls = true;
        elem.removeClass ("invalid-input");
        var amount = parseFloat(
            removeWhiteSpace (elem.val())
        );
        if (isNaN (amount)) {
            if (applyErrorCls){
                elem.addClass ("invalid-input");
            }
            return null;
        }
        amount = btcToSatoshi (amount);
        return new BigInteger(''+amount, 10);
    }

    /*
    * Extracts the fee in btc from the element,
    * and converting to BigInteger and satoshis.
    */
    function extractFee (elem) {
        elem.removeClass ("invalid-input");
        var fee = removeWhiteSpace (elem.val());
        if (fee.length == 0){
            elem.val(0.0);
            return BigInteger.ZERO;
        }
        fee = parseFloat (fee);
        if (isNaN(fee)){
            elem.addClass ("invalid-input");
            return null;
        }
        fee = btcToSatoshi (fee);
        return new BigInteger(''+fee, 10);
    }

    function validSessionPin () {
        if ((undefined != G.pin) && (G.pin != '')) {
            var gPin = prompt ("Enter session pin: ");
            if (gPin != G.pin) return false;
            return true;
        }
        return true;
    }

    /*
    * amt - in satoshis.
    * returns remaining balance in satoshis.
    */
    function balanceMinus (amt){
        return ReadyBal.subtract(amt);
    }

    function multiSigResponse (data){
        var response = JSON.parse (data, '', ' ');

        if (response.status == 'OK'){
            $("#debugSendResult").val (response.message);
            alert ("Sent\n"+response.message);
            multiSigSendHide();
            homeUpdateBalance();
        }else{
            $("#debugSendResult").val (response.error);
            alert ("Error: "+response.error);
        }
    }

    function multiSigSendTx () {
        var address = extractAddress ($("#multiSigSendAddress"));
        if (address == null) return;
        var amount = extractAmount ($("#multiSigSpendAmt"));
        if (amount == null) return;
        var fee = extractFee ($("#multiSigSpendFee"));
        if (fee == null) return;

        if (balanceMinus (amount.add(fee)) < 0){
            alert ("Not enough Bitcoins!");
            return;
        }

        if (!validSessionPin()) return;

        var tx = makeTxObj ([], [[address, amount]], "", fee);
        if (tx == null || tx == undefined){
            alert("Unable to create transaction.");
            return;
        }
        var txSerial = tx.serialize();
        if (txSerial == null || txSerial == undefined){
            alert ("Unable to serialize transaction.");
            return;
        }
        var txHex = Crypto.util.bytesToHex (txSerial);
        $("#debugTransaction").val (TX.toBBE (tx));
        $("#debugHexTransaction").val (Crypto.util.bytesToHex (tx.serialize()));
        alert (JSON.stringify ({tx: txHex}));
        $.post ("cgi-bin/send.py", {tx: txHex}, multiSigResponse,'text');
    }

    var multiSigAddyToScriptPubKey = function (addy) {
        var s = new Bitcoin.Script();
        var a = new Bitcoin.Address(addy);
        s.writeOp (169); //OP_HASH160
        s.writeBytes (a.fingerPrint);
        s.writeOp (135); //OP_EQUAL
        return Crypto.util.bytesToHex (s.buffer);
    }


    /*
    * Assume that all tx inputs come from same
    * multisig address.
    *
    * Establish a convention that the during the
    * initial raw transaction creation, that each
    * input has OP_0 redeemScript.
    */
    function signMultiSigTransaction (tx, ecKey) {

        var redeemScriptBytes = tx.ins[0].script.chunks[tx.ins[0].script.chunks.length-1];

        //Need to work with a 3 out of 3 multisig address.
        var redeemScript = new Brollet.RedeemScript(redeemScriptBytes);
        var hashType = 1   // SIGHASH_ALL

        //Collect public keys from redeem-script.
        var pubkeys = redeemScript.pubkeys;

        //For each input validate signatures.
        var sendTx = tx.clone();
        var txInputs = tx.ins;

        for (var i=0; i<txInputs.length; i++){
            var sighash = sendTx.hashTransactionForSignature(redeemScript.script, i, hashType);

            //Validates signatures.
            new Brollet.MultiSigScript(txInputs[i].script.buffer, sighash);
        }

        sendTx = tx.clone();
        txInputs = sendTx.ins;
        var complete = true;
        for (var i=0; i<txInputs.length; i++){
            var currentScript = txInputs[i].script;
            var sighash = sendTx.hashTransactionForSignature(redeemScript.script, i, hashType);
            var signature = ecKey.sign(sighash);
            signature.push(parseInt(1, 10));
            var txScript = addSignatureToScript (sighash, signature, currentScript);
            txInputs[i].script = txScript;
            if (!signingComplete (sighash, txScript)) {
                complete = false;
            }
        }

        return {complete: complete, tx: sendTx};
    }

    function addSignatureToScript (hash, signature, script){
        var multiSigScript = new Brollet.MultiSigScript(script.buffer, hash);
        multiSigScript.addSignature(signature);
        return multiSigScript.toScript();
    }

    function signingComplete (hash, script) {
        var multiSigScript = new Brollet.MultiSigScript (script.buffer, hash);
        return multiSigScript.isComplete();
    }

    function multiSigScriptFromFirstInput (tx){
        var redeemScript = new Bitcoin.Script(tx.ins[0].script.chunks[tx.ins[0].script.chunks.length-1]);
        var hashType = 1;
        var txBuf = tx.clone();
        var sighash = txBuf.hashTransactionForSignature(redeemScript, 0, hashType);
        return new Brollet.MultiSigScript(txBuf.ins[0].script.buffer, sighash);
    }

    function signMultiSigRedeemSignTx(){
        var tx = Bitcoin.Transaction.deserialize($("#multiSigRedeemSignTxHex").val());
        var multiSigScript = multiSigScriptFromFirstInput (tx);
        var brolletKey = keyToSign (multiSigScript.unsignedPubkeys());
        var result = signMultiSigTransaction (tx, brolletKey.getECKey());
        var txHex = Crypto.util.bytesToHex(result.tx.serialize());
        $("#multiSigRedeemSignEncodedTx").val(txHex);
        if (result.complete){
            enableBroadcast($("#multiSigRedeemSignBroadcastBtn"), $("#multiSigRedeemSignBroadcastSpan"), txHex);
        }
    }

    function signMultiSigRedeemTx(){
        var txParams = extractMultiSigRedeemInputs();
        if (txParams == null) return;

        var s = Crypto.util.hexToBytes($("#multiSigRedeemRscript").val());
        var script = new Bitcoin.Script(s);
        var redeemScript = new Brollet.RedeemScript(script.buffer);
        var brolletKey = keyToSign (redeemScript.pubkeys);
        var eckey = brolletKey.getECKey();

        $("#multiSigRedeemRscript").data("outputsRequester")
        .addSingleListener(function (unspentOutputs){
            if (!enoughBitcoins (txParams.outputs, txParams.feeAmt, unspentOutputs)){
                $("#multiSigRedeemEncodedTx").val("Not enough bitcoins for transaction.");
                return;
            }
            var tx = createMultiSigRedeemTx (txParams.rscript, txParams.outputs, txParams.changeAddress, txParams.feeAmt, unspentOutputs);
            var result = signMultiSigTransaction (tx, eckey);
            $("#multiSigRedeemEncodedTx").val(Crypto.util.bytesToHex(result.tx.serialize()));
        })
    }

    function composeMultiSigRedeemTx(){
        var txParams = extractMultiSigRedeemInputs();
        if (txParams == null) return;
        $("#multiSigRedeemRscript")
        .data("outputsRequester").addSingleListener(function (unspentOutputs){
            if (!enoughBitcoins (txParams.outputs, txParams.feeAmt, unspentOutputs)){
                $("#multiSigRedeemEncodedTx").val("Not enough bitcoins for transaction.");
                return;
            }
            var result = createMultiSigRedeemTx (txParams.rscript, txParams.outputs, txParams.changeAddress, txParams.feeAmt, unspentOutputs);
            $("#multiSigRedeemEncodedTx").val(Crypto.util.bytesToHex(result.serialize()));
        });
    }

    function extractMultiSigRedeemInputs(){
        var script = new Bitcoin.Script(Crypto.util.hexToBytes($("#multiSigRedeemRscript").val()));
        var rscript = new Brollet.RedeemScript(script.buffer);
        var outputs = [];
        var validOutputs = true;
        $("#multiSigRedeemOutputs .control-group.seen").each(function (i,e){
            e = $(e);
            var addr = extractAddress(e.find(".btc-address"));
            var amt = extractAmount(e.find(".btc-amount"));
            if (addr == null || amt == null){
                validOutputs = false;
            }
            outputs.push([addr, amt]);
        });
        if (validOutputs == false){
            console.debug("Invalid outputs");
            return null;
        }

        var changeAddress = extractAddress($("#multiSigRedeemChangeAddress"), true);
        if (changeAddress == -1) changeAddress = rscript.getAddress().toString();
        if (changeAddress == null){
            console.debug("Invalid changeAddress");
            return null;
        }
        var feeAmt = extractFee($("#multiSigRedeemFeeAmt"));
        if(feeAmt == null){
            console.debug("Invalid fee amount");
            return null;
        }
        return {outputs: outputs, feeAmt: feeAmt, rscript: rscript, changeAddress: changeAddress};

    }

    function enoughBitcoins (txOutputs, fee, unspentOutputs){
        var totalAmt = fee;
        for (var i=0; i<txOutputs.length; i++){
            totalAmt = totalAmt.add(txOutputs[i][1]);
        }
        var uOutputs = collectAmt (totalAmt, unspentOutputs);
        return uOutputs.isEnough;
    }

    // redeemScript
    // txOutputs - list of address, amount pairs. [ [addr1, BigInteger(val1)], [addr2, BigInteger(val2)]]
    // changeAddress - one address to accept transaction change, if null use multisig address from redeemscript.
    // fee - the fee amount to broadcast onto the network. BigInteger()
    function createMultiSigRedeemTx (redeemScript, txOutputs, changeAddress, feeAmt, unspentOutputs) {
        var redeemAddress = redeemScript.getAddress().toString();
        if (!enoughBitcoins (txOutputs, feeAmt, unspentOutputs)) return null;

        var totalAmt = feeAmt;
        for (var i=0; i<txOutputs.length; i++){
            totalAmt = totalAmt.add(txOutputs[i][1]);
        }
        var uOutputs = collectAmt (totalAmt, unspentOutputs);

        var sendTx = new Bitcoin.Transaction();
        hashType = 1 //SIGHASH_ALL
        var inputs = uOutputs.outputs;
        for (var i=0; i<inputs.length; i++){
            var tx = {'hash': Crypto.util.bytesToBase64(Crypto.util.hexToBytes(endian(inputs[i].txHash)))};
            sendTx.addInput(tx, inputs[i].outputIndex);
        }

        for (var i=0; i<txOutputs.length; i++){
            var sendToAddy = new Bitcoin.Address(txOutputs[i][0]);
            sendTx.addOutput (sendToAddy, txOutputs[i][1]);
        }

        var changeAmt = uOutputs.change;
        if (changeAmt.compareTo(CENT) < 0 &&
            changeAmt.compareTo(BigInteger.ZERO) > 0 &&
            feeAmt.compareTo(minTxFee) < 0){

            var moveToFee = changeAmt.min(minTxFee.subtract(feeAmt));
            changeAmt = changeAmt.subtract(moveToFee);
            feeAmt = feeAmt.add(moveToFee);
        }

        if (changeAmt.compareTo(BigInteger.ZERO)>0 ){
            toAddr = new Bitcoin.Address(changeAddress);
            var txOutput = Bitcoin.TransactionOut.create(toAddr, changeAmt);
            if (!isDust(txOutput)){ //change added to fee if dust.
                sendTx.addOutput(toAddr, changeAmt);
                // add the address so it is easy to see on the debug page
                sendTx.outs[sendTx.outs.length-1].address = changeAddress;
            }else{
                feeAmt = feeAmt.add(changeAmt);
            }
        }

        var inputScript = new Bitcoin.Script();
        inputScript.writeOp(Bitcoin.Opcode.map.OP_0);
        inputScript.writeBytes(redeemScript.script.buffer);

        var txInputs = sendTx.ins;
        for (var i=0; i<txInputs.length; i++){
            txInputs[i].script = inputScript;
        }

        return sendTx;
    };

    function correspondingKey(pubkey){
        pubkey = Crypto.util.bytesToHex(pubkey);
        var btcAddys = Object.keys(Keys);
        for(var i=0; i<btcAddys.length; i++){
            var brolletKey = new Brollet.Key(Keys[btcAddys[i]]);
            if (brolletKey.pubKeyAsHex() == pubkey){
                return brolletKey;
            }
        }
        return null;
    }

    function keyToSign (pubkeys) {
        for (var i=0; i<pubkeys.length; i++){
            var pubkey = pubkeys[i];
            var b = correspondingKey (pubkey);
            if (b != null){
                return b;
            }
        }
        return null;
    }
    function hideGrandparent(elem){
        var elem = $(elem.target);
        elem.parent().parent().remove();
    }

    function addRedeemTxOutput() {
        var elem = $(".output-row-base").clone();
        elem = elem.removeClass("hide").removeClass("output-row-base").addClass("seen");
        $("#multiSigRedeemOutputs").append(elem);
        $(".hide-grandparent").click(hideGrandparent);
        $(".hide-grandparent").click(composeMultiSigRedeemTx);
        onInput($(".process-multisig-redeem-input"), composeMultiSigRedeemTx);
    }

    function disableBroadcast (btn, status){
        $(btn[0]).data("txHex","");
        btn[0].disabled = true;
        status.html("");
    }
    function enableBroadcast (btn, status, txHex){
        $(btn[0]).data("txHex", txHex);
        btn[0].disabled = false;
        status.html("Signing is complete, transaction can be sent onto network.");
    }
    function enableSigning (btn, status) {
        btn[0].disabled = false;
        status.html("You have a Private Key");
    }

    function disableSigning (btn, status){
        btn[0].disabled = true;
        status.html("");
    }

    function setSignaturesStatus (elem, nSignings, nNeeded){
        var buf = "";
        if(nSignings == 1){
            buf = "Signed once, ";
        }else{
            buf = "Signed "+nSignings+" times, ";
        }
        var required = nNeeded - nSignings;
        buf += "requires "+required+" more.";
        elem.html(buf);
    }

    function inputsWithSameScript (tx, scriptBytes){
        var matchHex = Crypto.util.bytesToHex(scriptBytes);
        for (var i=0; i<tx.ins.length; i++){
            var sBytes = tx.ins[i].script.chunks[tx.ins[i].script.chunks.length-1];
            var hex = Crypto.util.bytesToHex(sBytes);
            if(hex != matchHex) return false;
        }
        return true;
    }

    function arraysEqual(a, b){
        if (a === b) return true;
        if (a == null || b == null) return false;
        if (a.length != b.length) return false;

        for (var i = 0; i < a.length; ++i) {
            if (a[i] !== b[i]) return false;
        }
        return true;
    }

    function pubkeyArraysEqual (a, b){
        if (a.length != b.length) return false;

        for(var i=0; i<a.length; i++){
            var c = a[i];
            var d = b[i];
            if(!arraysEqual(c,d)) return false;
        }
        return true;
    }

    function inputsWithSameSignatures (tx, redeemScript){
        var hashType = 1;
        var txBuf = tx.clone();
        var txInputs = txBuf.ins;
        var current = null;

        for (var i=0; i<txInputs.length; i++){
            var sighash = txBuf.hashTransactionForSignature(redeemScript.script, i, hashType);
            var multiSigScript = new Brollet.MultiSigScript(txInputs[i].script.buffer, sighash);
            var arr = multiSigScript.signedPubkeys();
            if (current == null) current = arr;
            if (!pubkeyArraysEqual(current, arr)){
                return false;
            }
        }
        return true;
    }

    function broadcastMultisigRedeemTx () {
        var txHex = $("#multiSigRedeemSignBroadcastBtn").data("txHex");
        $.post ('cgi-bin/send.py', {tx: txHex}, function (data){
            $("#multiSigRedeemSignBroadcastSpan").html("<span style='color: rgb(26, 26, 182)'>"+data.status+" "+data.message+"</span>");
        });
    }

    function processMultisigRedeemTx() {
        disableSigning ($("#multiSigRedeemTxSignBtn"), $("#multiSigRedeemTxPrivkey"));
        disableBroadcast ($("#multiSigRedeemSignBroadcastBtn"), $("#multiSigRedeemSignBroadcastSpan"));
        $("#multiSigRedeemSignEncodedTx").val("");

        var txHex = $("#multiSigRedeemSignTxHex").val();
        var tx = Bitcoin.Transaction.deserialize(txHex);
        var redeemScriptBytes = tx.ins[0].script.chunks[tx.ins[0].script.chunks.length-1];
        var redeemScript = new Brollet.RedeemScript(redeemScriptBytes);

        if (!inputsWithSameScript(tx, redeemScriptBytes)){
            $("#multiSigRedeemSignEncodedTx").val("Transaction contains inputs that originate from different scriptPubKeys.");
            return;
        }

        if (!inputsWithSameSignatures(tx, redeemScript)){
            $("#multiSigRedeemSignEncodedTx").val("Transaction contains inputs that have inconsistent signatures.");
            return;
        }
        var address = redeemScript.getAddress().toString();
        $("#multiSigRedeemSignAddress").val(address);
        $("#multiSigRedeemSignTitle").html(redeemScript.nRequired+" out of "+redeemScript.nPubkeys+" Script");

        var multiSigScript = multiSigScriptFromFirstInput (tx);
        if (multiSigScript.isComplete()){
            enableBroadcast ($("#multiSigRedeemSignBroadcastBtn"), $("#multiSigRedeemSignBroadcastSpan"), txHex);
        }
        setSignaturesStatus($("#multiSigRedeemSignNsigs"), multiSigScript.signatures.length, redeemScript.nRequired);
        var brolletKey = keyToSign (multiSigScript.unsignedPubkeys());
        if (brolletKey != null){
            enableSigning ($("#multiSigRedeemTxSignBtn"), $("#multiSigRedeemTxPrivkey"));
        }
        $("#multiSigRedeemSignTxHex")
        .data("outputsRequester", new Brollet.OutputsRequester([address]))
        .data("outputsRequester")
        .addSingleListener(function (outputs){
            var txInputs = tx.ins;
            var total = BigInteger.ZERO;
            for (var i=0; i<txInputs.length; i++){
                var outpoint = txInputs[i].outpoint;
                var h = endian(Crypto.util.bytesToHex(Crypto.util.base64ToBytes(outpoint.hash)));
                for (var j=0; j<outputs.length; j++){
                    if (outputs[j].txHash == h && outputs[j].outputIndex == outpoint.index){
                        total = total.add(new BigInteger(''+outputs[j].value, 10));
                        break;
                    }
                }
            }
            $("#multiSigRedeemSignBalBefore").html(uOutputsToHtml(outputs));

            var totalSent = BigInteger.ZERO;
            var txOutputs = tx.outs;
            var nOutputs = txOutputs.length;
            $("#multiSigRedeemSignOutputs .control-group:nth-child(n+3)").remove();

            for (var i=0; i<txOutputs.length; i++){
                var addy = []
                txOutputs[i].script.extractAddresses(addy);
                var v = BigInteger.fromByteArrayUnsigned(txOutputs[i].value.slice(0).reverse());
                totalSent = totalSent.add(v);
                if (i==0){
                    var elem = $("#multiSigRedeemSignOutputs .control-group:first-child");
                    elem.find(".btc-amount").val(satoshiToBtc(v.intValue()));
                    elem.find(".btc-address").val(addy);
                }else{
                    var elem = $(".sign-output-row-base").clone();
                    elem.removeClass("sign-output-row-base hide");
                    elem.find(".btc-amount").val(satoshiToBtc(v.intValue()));
                    elem.find(".btc-address").val(addy);
                    $("#multiSigRedeemSignOutputs").append(elem);
                }
            }

            var feeAmt = total.subtract(totalSent);
            $("#multiSigRedeemSignFee").val(satoshiToBtc(feeAmt.intValue()));
            $("#multiSigRedeemSignTotal").val(satoshiToBtc(total.intValue()));
        });

    }
    /**
    * This will update redeem-multisig UI elements
    * when the redeem-script is entered.
    */
    function processComposeRedeemScript() {
        var s = Crypto.util.hexToBytes($("#multiSigRedeemRscript").val());
        var script = new Bitcoin.Script(s);
        var address = new Bitcoin.Address.fromMultiSigScript(script.buffer);
        $("#multiSigRedeemAddress").val(address.toString());

        var redeemScript = new Brollet.RedeemScript(script.buffer);
        $("#multiSigRedeemTitle").html(redeemScript.nRequired+" out of "+redeemScript.nPubkeys+" Script");
        var brolletKey = keyToSign (redeemScript.pubkeys);
        if (brolletKey != null){
            enableSigning ($("#multiSigRedeemSignBtn"), $("#multiSigRedeemPrivkey"));
        }
        $("#multiSigRedeemRscript")
        .data("outputsRequester", new Brollet.OutputsRequester([address]))
        .data("outputsRequester")
        .addSingleListener(function (outputs){
            var buf = uOutputsToHtml(outputs);
            $("#multiSigRedeemBalance").html(buf);
        });
    }

    function cleanNumber(buf){
        buf = buf.split("").reverse().join("");
        var result = "";
        var cleaning = true;
        for (var i=0; i<buf.length; i++){
            if(cleaning == false){
                result += buf[i];
                continue;
            }
            if(buf[i] == '0'){

            }else if(/^[1-9]$/.test(buf[i])){
                cleaning = false;
                result += buf[i];
            }else{ //buf[i] == '.'
                cleaning = false;
            }
        }
        return result.split("").reverse().join("");
    }

    function displayMultisigPubkeys(){
        var addys = Object.keys(Keys);
        for(var i=0; i<addys.length; i++){
            var btcAddy = addys[i]
            var brolletKey = new Brollet.Key(Keys[btcAddy]);
            var elem = "<tr class='pubkey-row'>"
            elem += "<td>"+(i+1)+"</td>";
            elem += "<td>"+brolletKey.pubKeyAsHex()+"</td>";
            elem += "</tr>";
            $("#pubkeys-table-body").append($(elem));
        }
    }
    function placeTxnsInTable(data){
        var ds = {
            cols: {
                time: {index:1, type: "date", friendly: 'Time'},
                addrs: { index: 2, type: 'string', friendly: 'Bitcoin Address' },
                txid: {index: 3, type: 'string', friendly: 'Transaction'},
                fee: {index: 4, type: 'number', friendly: 'Fee (BTC)', decimals: 12},
                amt: {index: 5, type: 'number', friendly: 'Amount (BTC)', decimals: 12},

            },
            rows: data
        }
        function formatTable(){
            $("#transactions-table tbody td:nth-child(4)").each(function(i,e){
                var temp = cleanNumber($(e).html());
                if(temp == "0")temp = "";
                $(e).html(temp);
            });
            $("#transactions-table tbody td:nth-child(5)").each(function(i,e){
                var t = cleanNumber($(e).html());
                var cls = 'negative';
                if(t[0] != '-'){
                    t = "&nbsp;"+t;
                    cls = 'positive';
                }
                $(e).html("<span class='"+cls+"'>"+t+"</span>");
            })
        }
        $("#transactions-table").html("");
        var table = $("#transactions-table").WATable({
            tableCreated: formatTable,
            rowClicked: formatTable,
            columnClicked: formatTable,
            pageChanged: formatTable,
            pageSizeChanged: formatTable,
        }).data('WATable');
        table.setData(ds);
    }
    function getWalletTransactions(){
        var addresses = keysAsBase58();
        function sendingTrans(txn){
            var inputs = txn.inputs;
            var inputAddresses = [];
            var totalInputs = 0;
            for(var j=0; j<inputs.length; j++){
                totalInputs += inputs[j].prev_out.value;
                inputAddresses.push(inputs[j].prev_out.addr);
            }
            var outputs = txn.out;
            var totalOutputs = 0;
            var sentOutput = 0;
            for(var j=0; j<outputs.length; j++){
                totalOutputs += outputs[j].value;
                if(addresses.indexOf(outputs[j].addr) == -1){
                    sentOutput += outputs[j].value;
                }
            }
            var fee = totalInputs - totalOutputs;
            return {
                time: new Date(txn.time*1000),
                addrs: inputAddresses.join("<br />"),
                amt: sathoshi2num(-1*sentOutput),
                fee: sathoshi2num(fee),
                txid: "<a target=_blank href='https://blockchain.info/tx/"+txn.hash+"'>"+txn.hash.substring(0,8)+"...</a>"
            };
        }
        function receivingTrans(txn){
            var outputs = txn.out;
            var outputAddresses = [];
            var totalOutputs = 0;
            for(var j=0; j<outputs.length; j++){
                if(addresses.indexOf(outputs[j].addr) != -1){
                    outputAddresses.push(outputs[j].addr);
                    totalOutputs += outputs[j].value;
                }
            }
            return {
                time: new Date(txn.time*1000),
                addrs: outputAddresses.join("<br />"),
                amt: sathoshi2num(totalOutputs),
                fee: null,
                txid: "<a target=_blank href='https://blockchain.info/tx/"+txn.hash+"'>"+txn.hash.substring(0,8)+"...</a>"
            };
        }

        function cback(i){
            var txns = i.txs;
            var results = [];
            for(var i=0; i<txns.length; i++){
                if(txns[i].result>0) results.push(receivingTrans(txns[i]));
                else results.push(sendingTrans(txns[i]));
            }
            placeTxnsInTable(results);
        }
        var param = '';
        for(var i=1; i<addresses.length; i++){
            var address = addresses[i];
            param += addresses[i] + '|';

        }
        param += addresses[0];
        var baseUrl = 'cgi-bin/transactions.py?addresses='+param;

        $.get(baseUrl, {}, function (data){
            cback(data);
        });
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
        $.post('cgi-bin/send.py', {tx: tx}, homeSentTx, 'text')
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
        var jo, jos;
        jo = {}
        jo.action = 'get'
        jos = JSON.stringify(jo)
        $.post('cgi-bin/settings.py', jos, settingsGetShow, 'text')
    }

    var SettingsPassword = function(){
        var val = null;
        return {
            set: function(v){val = v;},
            get: function(){ return val;},
            clear: function(){ val = null;}
        }
    }();

    function settingsLogin(){
        var pword = $("#login-password").val();
        var jo = {action: 'get', password: pword};
        var jos = JSON.stringify(jo);
        function testCallback(arg){
            var result = JSON.parse(arg);
            if(result.status == 'Error'){
                alert(result.message);
            }else{
                SettingsPassword.set(pword);
                settingsGetShow(arg);
                $("#login-password").val('');
                $("#settings-actual-li").show();
                $("#settings-li").hide();
                $("#settingsActual").click();
            }
            //settingsGetShow(arg)
        }
        $.post('cgi-bin/settings.py', jos, testCallback, 'text');
    }

    function hideSettingsActual(){
        SettingsPassword.clear();
        $("#settings-actual-li").hide();
        $("#settings-li").show();
        $("#settingsSend .btn").removeClass('active');
        $("#settingsUnspent .btn").removeClass('active');
        $("#smtpHost").val('');
        $("#smtpPort").val('');
        $("#smtpUsername").val('');
        $("#smtpPassword").val('');
        $("#settings-password-change").val('');
    }

    function smtpSettingsSet(e){
        var p = $("#smtpPort").val()
        if (p != '' && isNaN(parseInt(p))){
            alert("Port must be a number.")
            return;
        }
        e.data = {}
        e.data.v = {
            send: $("#settingsSend .active").attr('data-val'),
            unspent: $("#settingsUnspent .active").attr('data-val'),
            email: {
                host: $("#smtpHost").val(),
                port: $("#smtpPort").val(),
                username: $("#smtpUsername").val(),
                password: $("#smtpPassword").val()
            }
        }
        settingsSet(e)
    }


    function settingsSetCallback(data){
        var res = JSON.parse(data, '', '  ');
        if(res.status == 'Error'){
            alert(res.message);
        }else{
            alert("Settings updated.");
        }
    }
    function settingsSet(e){
//      alert(e.data.f + ' ' +e.data.v)
        var jo, jos, ba, s
        jo = {}
        jo.action = 'set'
        jo.value = e.data.v
        jo.password = SettingsPassword.get();
        jos = JSON.stringify(jo)
        $.post('cgi-bin/settings.py', jos, settingsSetCallback, 'text')
    }

    function settingsGetShow(data){
        res = JSON.parse(data, '', '  ')
        var isError = false;
        if (res.status == 'Error'){
          isError = true;
          alert(res.message)
        }
        $('#settingsSendBtn_'+res.send).button('toggle')
        $('#settingsUnspentBtn_'+res.unspent).button('toggle')
        $("#smtpHost").val(res.smtphost)
        $("#smtpPort").val(res.smtpport)
        $("#smtpUsername").val(res.smtpusername)
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
        $('.homeSendCancelBtn').click(homeSendCancel);
        $('#homeSendSendBtn').click(homeSendTx);
        $("#showEmailCodeBtn").click(showEmailCode);
        $('#homeScanBtn').click(homeScan);
        $('#homeScanCloseBtn').click(homeScanClose);
        $("#homeTransactionsBtn").click(homeTransactionsShow);
        $(".homeTransactionsBackBtn").click(homeTransactionsHide);
        $("#multiSigSendBtn").click(multiSigSendShow);
        $(".multiSigCancelBtn").click(multiSigSendHide);
        $("#multiSigSpendBtn").click(multiSigSendTx);
        onInput($(".multisigsend-pubkey"), genBrolletRedeemScript);
        onInput($("#sendSigsRequired"), genBrolletRedeemScript);
        onInput($("#multiSigSpendAmt"), multiSigSendBalanceAfter);
        onInput($("#multiSigSpendFee"), multiSigSendBalanceAfter);
        onInput($("#multiSigRedeemRscript"), processComposeRedeemScript);
        onInput($(".process-multisig-redeem-input"), composeMultiSigRedeemTx);

        $("#multiSigRedeemComposeBtn").click(showComposeMultiSigRedeem);
        $(".cancelMultiSigSpendBtn").click(hideComposeMultiSigRedeem);
        $("#multiSigRedeemSignHexBtn").click(showSignMultiSigRedeem);
        $(".cancelMultiSigSignBtn").click(hideSignMultiSigRedeem);

        $("#multiSigRedeemAddOutput").click(addRedeemTxOutput);
        $(".hide-grandparent").click(hideGrandparent);
        $("#multiSigRedeemSignBtn").click(signMultiSigRedeemTx);
        onInput($("#multiSigRedeemSignTxHex"), processMultisigRedeemTx);
        $("#multiSigRedeemTxSignBtn").click(signMultiSigRedeemSignTx);
        $("#multiSigRedeemSignBroadcastBtn").click(broadcastMultisigRedeemTx);

        $("#multiSigPubkeysBtn").click(showPubkeysMultiSig);
        $(".multiSigPubkeysHideBtn").click(hidePubkeysMultiSig);
        $('#homeReceiveBtn').click(homeReceiveForm);
        $('.homeReceiveBackBtn').click(homeReceiveBack);
        $('#homeRedeemBtn').click(homeRedeemForm);
        $('.homeRedeemCancelBtn').click(homeRedeemCancel);
        $('#homeRedeemNowBtn').click(homeRedeemNow);
        $('#homeRecoverBtn').click(homeRecoverForm);
        $('#homeRecoverNowBtn').click (homeRecoverNow)
        $('.homeRecoverCancelBtn').click(homeRecoverCancel);
        $('#homeReloadBalBtn').click(homeUpdateBalance);
//        $('#homeSendShowBtn').click(homeSendShowTx);
        onInput($('#homeSendAmount'), homeSetBalanceAfterSend);
        onInput($('#homeSendFee'), homeSetBalanceAfterSend);
        onInput($('#homeRedeemCode'), homeSetRedeemInfo);
        onInput($('#homeRedeemPassword'), homeSetRedeemInfo);
        onInput($('#homeRecoverCode'), homeSetRecoverInfo);
        onInput($("#homeRecoverEmail"), homeSetRecoverInfo);


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

        $("#settings-login-btn").click(settingsLogin);
        $('#smtpSettingsBtn').click(smtpSettingsSet);
        $("#settingsCloseBtn").click(function(){$("#tab-home").click();});
        $("#send-test-email-btn").click(sendTestEmail);
        $("#cancel-test-email-btn").click(hideTestEmailModal);
        $("#smtpTestBtn").click(showTestEmailModal);
        hideTestEmailModal();
        $(".email-modal-wrapper").css("visibility","visible");
        $("a[data-toggle='tab']").on('shown', function(e){
            if($(e.relatedTarget).attr('id') == 'settingsActual'){
                hideSettingsActual();
            }
        });
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
