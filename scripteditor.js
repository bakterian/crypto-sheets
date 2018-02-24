/**
 * @OnlyCurrentDoc
 */

/*
     ==============================================
   Don't change if using USD
    Possible values:
      "aud", "brl", "cad", "chf", "clp", "cny", "czk", "dkk", "eur", "gbp", "hkd", "huf",
      "idr", "ils", "inr", "jpy", "krw", "mxn", "myr", "nok", "nzd", "php", "pkr", "pln",
      "rub", "sek", "sgd", "thb", "try", "twd", "usd", "zar"
     ============================================== 
*/

/*
CryptoJS v3.1.2
code.google.com/p/crypto-js
(c) 2009-2013 by Jeff Mott. All rights reserved.
code.google.com/p/crypto-js/wiki/License
*/
var CryptoJS=CryptoJS||function(h,s){var f={},g=f.lib={},q=function(){},m=g.Base={extend:function(a){q.prototype=this;var c=new q;a&&c.mixIn(a);c.hasOwnProperty("init")||(c.init=function(){c.$super.init.apply(this,arguments)});c.init.prototype=c;c.$super=this;return c},create:function(){var a=this.extend();a.init.apply(a,arguments);return a},init:function(){},mixIn:function(a){for(var c in a)a.hasOwnProperty(c)&&(this[c]=a[c]);a.hasOwnProperty("toString")&&(this.toString=a.toString)},clone:function(){return this.init.prototype.extend(this)}},
r=g.WordArray=m.extend({init:function(a,c){a=this.words=a||[];this.sigBytes=c!=s?c:4*a.length},toString:function(a){return(a||k).stringify(this)},concat:function(a){var c=this.words,d=a.words,b=this.sigBytes;a=a.sigBytes;this.clamp();if(b%4)for(var e=0;e<a;e++)c[b+e>>>2]|=(d[e>>>2]>>>24-8*(e%4)&255)<<24-8*((b+e)%4);else if(65535<d.length)for(e=0;e<a;e+=4)c[b+e>>>2]=d[e>>>2];else c.push.apply(c,d);this.sigBytes+=a;return this},clamp:function(){var a=this.words,c=this.sigBytes;a[c>>>2]&=4294967295<<
32-8*(c%4);a.length=h.ceil(c/4)},clone:function(){var a=m.clone.call(this);a.words=this.words.slice(0);return a},random:function(a){for(var c=[],d=0;d<a;d+=4)c.push(4294967296*h.random()|0);return new r.init(c,a)}}),l=f.enc={},k=l.Hex={stringify:function(a){var c=a.words;a=a.sigBytes;for(var d=[],b=0;b<a;b++){var e=c[b>>>2]>>>24-8*(b%4)&255;d.push((e>>>4).toString(16));d.push((e&15).toString(16))}return d.join("")},parse:function(a){for(var c=a.length,d=[],b=0;b<c;b+=2)d[b>>>3]|=parseInt(a.substr(b,
2),16)<<24-4*(b%8);return new r.init(d,c/2)}},n=l.Latin1={stringify:function(a){var c=a.words;a=a.sigBytes;for(var d=[],b=0;b<a;b++)d.push(String.fromCharCode(c[b>>>2]>>>24-8*(b%4)&255));return d.join("")},parse:function(a){for(var c=a.length,d=[],b=0;b<c;b++)d[b>>>2]|=(a.charCodeAt(b)&255)<<24-8*(b%4);return new r.init(d,c)}},j=l.Utf8={stringify:function(a){try{return decodeURIComponent(escape(n.stringify(a)))}catch(c){throw Error("Malformed UTF-8 data");}},parse:function(a){return n.parse(unescape(encodeURIComponent(a)))}},
u=g.BufferedBlockAlgorithm=m.extend({reset:function(){this._data=new r.init;this._nDataBytes=0},_append:function(a){"string"==typeof a&&(a=j.parse(a));this._data.concat(a);this._nDataBytes+=a.sigBytes},_process:function(a){var c=this._data,d=c.words,b=c.sigBytes,e=this.blockSize,f=b/(4*e),f=a?h.ceil(f):h.max((f|0)-this._minBufferSize,0);a=f*e;b=h.min(4*a,b);if(a){for(var g=0;g<a;g+=e)this._doProcessBlock(d,g);g=d.splice(0,a);c.sigBytes-=b}return new r.init(g,b)},clone:function(){var a=m.clone.call(this);
a._data=this._data.clone();return a},_minBufferSize:0});g.Hasher=u.extend({cfg:m.extend(),init:function(a){this.cfg=this.cfg.extend(a);this.reset()},reset:function(){u.reset.call(this);this._doReset()},update:function(a){this._append(a);this._process();return this},finalize:function(a){a&&this._append(a);return this._doFinalize()},blockSize:16,_createHelper:function(a){return function(c,d){return(new a.init(d)).finalize(c)}},_createHmacHelper:function(a){return function(c,d){return(new t.HMAC.init(a,
d)).finalize(c)}}});var t=f.algo={};return f}(Math);
(function(h){for(var s=CryptoJS,f=s.lib,g=f.WordArray,q=f.Hasher,f=s.algo,m=[],r=[],l=function(a){return 4294967296*(a-(a|0))|0},k=2,n=0;64>n;){var j;a:{j=k;for(var u=h.sqrt(j),t=2;t<=u;t++)if(!(j%t)){j=!1;break a}j=!0}j&&(8>n&&(m[n]=l(h.pow(k,0.5))),r[n]=l(h.pow(k,1/3)),n++);k++}var a=[],f=f.SHA256=q.extend({_doReset:function(){this._hash=new g.init(m.slice(0))},_doProcessBlock:function(c,d){for(var b=this._hash.words,e=b[0],f=b[1],g=b[2],j=b[3],h=b[4],m=b[5],n=b[6],q=b[7],p=0;64>p;p++){if(16>p)a[p]=
c[d+p]|0;else{var k=a[p-15],l=a[p-2];a[p]=((k<<25|k>>>7)^(k<<14|k>>>18)^k>>>3)+a[p-7]+((l<<15|l>>>17)^(l<<13|l>>>19)^l>>>10)+a[p-16]}k=q+((h<<26|h>>>6)^(h<<21|h>>>11)^(h<<7|h>>>25))+(h&m^~h&n)+r[p]+a[p];l=((e<<30|e>>>2)^(e<<19|e>>>13)^(e<<10|e>>>22))+(e&f^e&g^f&g);q=n;n=m;m=h;h=j+k|0;j=g;g=f;f=e;e=k+l|0}b[0]=b[0]+e|0;b[1]=b[1]+f|0;b[2]=b[2]+g|0;b[3]=b[3]+j|0;b[4]=b[4]+h|0;b[5]=b[5]+m|0;b[6]=b[6]+n|0;b[7]=b[7]+q|0},_doFinalize:function(){var a=this._data,d=a.words,b=8*this._nDataBytes,e=8*a.sigBytes;
d[e>>>5]|=128<<24-e%32;d[(e+64>>>9<<4)+14]=h.floor(b/4294967296);d[(e+64>>>9<<4)+15]=b;a.sigBytes=4*d.length;this._process();return this._hash},clone:function(){var a=q.clone.call(this);a._hash=this._hash.clone();return a}});s.SHA256=q._createHelper(f);s.HmacSHA256=q._createHmacHelper(f)})(Math);
(function(){var h=CryptoJS,s=h.enc.Utf8;h.algo.HMAC=h.lib.Base.extend({init:function(f,g){f=this._hasher=new f.init;"string"==typeof g&&(g=s.parse(g));var h=f.blockSize,m=4*h;g.sigBytes>m&&(g=f.finalize(g));g.clamp();for(var r=this._oKey=g.clone(),l=this._iKey=g.clone(),k=r.words,n=l.words,j=0;j<h;j++)k[j]^=1549556828,n[j]^=909522486;r.sigBytes=l.sigBytes=m;this.reset()},reset:function(){var f=this._hasher;f.reset();f.update(this._iKey)},update:function(f){this._hasher.update(f);return this},finalize:function(f){var g=
this._hasher;f=g.finalize(f);g.reset();return g.finalize(this._oKey.clone().concat(f))}})})();

/*
CryptoJS v3.1.2
code.google.com/p/crypto-js
(c) 2009-2013 by Jeff Mott. All rights reserved.
code.google.com/p/crypto-js/wiki/License
*/
(function(){var h=CryptoJS,j=h.lib.WordArray;h.enc.Base64={stringify:function(b){var e=b.words,f=b.sigBytes,c=this._map;b.clamp();b=[];for(var a=0;a<f;a+=3)for(var d=(e[a>>>2]>>>24-8*(a%4)&255)<<16|(e[a+1>>>2]>>>24-8*((a+1)%4)&255)<<8|e[a+2>>>2]>>>24-8*((a+2)%4)&255,g=0;4>g&&a+0.75*g<f;g++)b.push(c.charAt(d>>>6*(3-g)&63));if(e=c.charAt(64))for(;b.length%4;)b.push(e);return b.join("")},parse:function(b){var e=b.length,f=this._map,c=f.charAt(64);c&&(c=b.indexOf(c),-1!=c&&(e=c));for(var c=[],a=0,d=0;d<
e;d++)if(d%4){var g=f.indexOf(b.charAt(d-1))<<2*(d%4),h=f.indexOf(b.charAt(d))>>>6-2*(d%4);c[a>>>2]|=(g|h)<<24-8*(a%4);a++}return j.create(c,a)},_map:"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/="}})();


var targetCurrency = 'eur'

//   ============== DON'T TOUCH ===================
var queryString = Math.random();
if (typeof targetCurrency == 'undefined' || targetCurrency == '') {targetCurrency = 'usd'};
var coins = getCoins();
var ss = SpreadsheetApp.getActiveSpreadsheet();
//   ==============================================

// ================ GDAX RELATED DATA =============
var passPhraseGdax = "passphraseGoesHere";
var apiKeyGdax = "keyGoesHere";
var apiSecretGdax = "gdaxSecretGoesHere";
var GdaxWalletInfo = getGdaxBalance(apiKeyGdax, apiSecretGdax, passPhraseGdax);
// ================================================




/**
* Include hmac-sha256 and base64 library, due to bug in Google Script
* @see https://issuetracker.google.com/issues/36757327
* @see https://stackoverflow.com/questions/46105421/google-apps-script-equivalent-of-phps-hash-hmac-with-raw-binary-output  
*/


function onOpen() {
  createMenu();
  getData();
  getGlobal();
}

function createMenu() {
  
/*
     ==============================================
           Creates menu button for refreshing
     ============================================== 
*/ 

    var ui = SpreadsheetApp.getUi();
    ui.createMenu('crypto-sheets')
      .addItem('Refresh Rates', 'getData')
      .addItem('Refresh Global', 'getGlobal')
      .addSeparator()
      .addItem('About', 'about')
      .addToUi();
}

function getData() {
/*
     ==============================================
   Enter the coins you want tracked, one per line, in single quotes, followed by a comma
   Use the value in the 'id' field here: https://api.coinmarketcap.com/v1/ticker/?limit=0
   If you're getting errors, you may be using the wrong 'id'.  Double-check the values.
     ============================================== 
*/ 

  var myCoins = [
    'bitcoin-cash',
    'bitcoin',
    'ethereum',
    'litecoin'
  ]

// Setting up and formatting the Rates sheet
  var ssRates = ss.getSheetByName('Rates');
  if (ssRates === null) {
  ssRates = ss.insertSheet('Rates');
  }
  var ratesDateFormat = ssRates.getRange("O2:O");
  ratesDateFormat.setNumberFormat("mmm dd h:mm A/P\".M.\"");
  
/*   ========== DONT TOUCH UNLESS WIZARD ==========

    Creates column headers.  Don't change unless you know what you're doing.
    If there is data you don't want, just hide the column in your spreadsheet
    ...or simply don't reference it

         \/     \/    \/    \/    \/    \/    \/   
*/
  ssRates.getRange('A1').setValue("ID");
  ssRates.getRange('B1').setValue("Name");
  ssRates.getRange('C1').setValue("Symbol");
  ssRates.getRange('D1').setValue("Rank");
  ssRates.getRange('E1').setValue("Price USD");
  ssRates.getRange('F1').setValue("Price BTC");
  ssRates.getRange('G1').setValue("24H Volume USD");
  ssRates.getRange('H1').setValue("Market Cap USD");
  ssRates.getRange('I1').setValue("Available Supply");
  ssRates.getRange('J1').setValue("Total Supply");
  ssRates.getRange('K1').setValue("Max Supply");
  ssRates.getRange('L1').setValue("Percent Change 1H");
  ssRates.getRange('M1').setValue("Percent Change 24H ");
  ssRates.getRange('N1').setValue("Percent Change 7D");
  ssRates.getRange('O1').setValue("Last Updated");
  // Adds in extra column headers if non-USD currency was chosen
  if (targetCurrency !== 'usd') {
    ssRates.getRange('P1').setValue("Price " + targetCurrency.toUpperCase());
    ssRates.getRange('Q1').setValue("24H Volume " + targetCurrency.toUpperCase());
    ssRates.getRange('R1').setValue("Market Cap " + targetCurrency.toUpperCase());
  };
  
/*
           /\      /\      /\      /\      /\
     ==============================================
     ========== DONT TOUCH UNLESS WIZARD ==========
    Creating new Object with our coins for later use.
          Each Object's key is the coin's ID

           \/      \/      \/      \/      \/
*/
  
  var myCoinsObj = {};
  var myCoinsCount = myCoins.length;
  for (var i = 0; i < myCoinsCount; i++) {
    var c = i+2;
    var r = c.toString();
    var n = 0;
    while (coins[n]['id'] !== myCoins[i]) {
      n++;
    }
    
    myCoinsObj[coins[n]['id']] = coins[n];
    
    ssRates.getRange('A' + r).setValue(myCoinsObj[myCoins[i]]['id']);
    ssRates.getRange('B' + r).setValue(myCoinsObj[myCoins[i]]['name']);
    ssRates.getRange('C' + r).setValue(myCoinsObj[myCoins[i]]['symbol']);
    ssRates.getRange('D' + r).setValue(myCoinsObj[myCoins[i]]['rank']);
    ssRates.getRange('E' + r).setValue(myCoinsObj[myCoins[i]]['price_usd']);
    ssRates.getRange('F' + r).setValue(myCoinsObj[myCoins[i]]['price_btc']);
    ssRates.getRange('G' + r).setValue(myCoinsObj[myCoins[i]]['24h_volume_usd']);
    ssRates.getRange('H' + r).setValue(myCoinsObj[myCoins[i]]['market_cap_usd']);
    ssRates.getRange('I' + r).setValue(myCoinsObj[myCoins[i]]['available_supply']);
    ssRates.getRange('J' + r).setValue(myCoinsObj[myCoins[i]]['total_supply']);
    ssRates.getRange('K' + r).setValue(myCoinsObj[myCoins[i]]['max_supply']);
    ssRates.getRange('L' + r).setValue(myCoinsObj[myCoins[i]]['percent_change_1h']+'%');
    ssRates.getRange('M' + r).setValue(myCoinsObj[myCoins[i]]['percent_change_24h']+'%');
    ssRates.getRange('N' + r).setValue(myCoinsObj[myCoins[i]]['percent_change_7d']+'%');
    ssRates.getRange('O' + r).setValue(new Date((myCoinsObj[myCoins[i]]['last_updated'])*1000));
    if (targetCurrency !== 'usd') {
      ssRates.getRange('P' + r).setValue(myCoinsObj[myCoins[i]]['price_' + targetCurrency]);
      ssRates.getRange('Q' + r).setValue(myCoinsObj[myCoins[i]]['24h_volume_' + targetCurrency]);
      ssRates.getRange('R' + r).setValue(myCoinsObj[myCoins[i]]['market_cap_' + targetCurrency]);
    };
  };

/*
          /\      /\      /\      /\       /\
     ==============================================
     ==============================================

             COIN WALLET BALANCE CONFIGURATION

     ============================================== 
*/  

  var ssWallets = ss.getSheetByName('CoinWallets');
  if (ssWallets === null) {ssWallets = ss.insertSheet('CoinWallets');}

  ssWallets.getRange('A1').setValue("Id");
  ssWallets.getRange('B1').setValue("Wallet");
  ssWallets.getRange('C1').setValue("Avialable");
  ssWallets.getRange('D1').setValue("Blocked");
  
/*
   ===== BTC Wallet Balances =========================================
   =================================================================== 
*/

  var gdaxBtcAvialbleAmmount =  getGdaxCurrencyAmount(GdaxWalletInfo,'BTC','available');
  var gdaxBtcBlockedAmmount =  getGdaxCurrencyAmount(GdaxWalletInfo,'BTC','hold');
  ssWallets.getRange('A2').setValue("BTC");
  ssWallets.getRange('B2').setValue("GDAX Wallet");
  ssWallets.getRange('C2').setValue(gdaxBtcAvialbleAmmount);  
  ssWallets.getRange('D2').setValue(gdaxBtcBlockedAmmount);  
  
  var gdaxEthAvialbleAmmount =  getGdaxCurrencyAmount(GdaxWalletInfo,'ETH','available');
  var gdaxEthBlockedAmmount =  getGdaxCurrencyAmount(GdaxWalletInfo,'ETH','hold');
  ssWallets.getRange('A3').setValue("ETH");
  ssWallets.getRange('B3').setValue("GDAX Wallet");
  ssWallets.getRange('C3').setValue(gdaxEthAvialbleAmmount);  
  ssWallets.getRange('D3').setValue(gdaxEthBlockedAmmount);  
  
  var gdaxBchAvialbleAmmount =  getGdaxCurrencyAmount(GdaxWalletInfo,'BCH','available');
  var gdaxBchBlockedAmmount =  getGdaxCurrencyAmount(GdaxWalletInfo,'BCH','hold');
  ssWallets.getRange('A4').setValue("BCH");
  ssWallets.getRange('B4').setValue("GDAX Wallet");
  ssWallets.getRange('C4').setValue(gdaxBchAvialbleAmmount);  
  ssWallets.getRange('D4').setValue(gdaxBchBlockedAmmount);  
  
  var gdaxLtcAvialbleAmmount =  getGdaxCurrencyAmount(GdaxWalletInfo,'LTC','available');
  var gdaxLtcBlockedAmmount =  getGdaxCurrencyAmount(GdaxWalletInfo,'LTC','hold');
  ssWallets.getRange('A5').setValue("LTC");
  ssWallets.getRange('B5').setValue("GDAX Wallet");
  ssWallets.getRange('C5').setValue(gdaxLtcAvialbleAmmount);  
  ssWallets.getRange('D5').setValue(gdaxLtcBlockedAmmount);  
  
  var btcWalletBittrex = -1;
  ssWallets.getRange('A6').setValue("BTC");
  ssWallets.getRange('B6').setValue("BTC on Bittrex");
  //ssWallets.getRange('C6').setValue(btcWalletBittrex);  
  //ssWallets.getRange('D6').setValue(btcWalletBittrex);
  
  var btcWalletBinance = -1;
  ssWallets.getRange('A7').setValue("BTC");
  ssWallets.getRange('B7').setValue("BTC on Binace");
  //ssWallets.getRange('C7').setValue(btcWalletBinance);  
  //ssWallets.getRange('D7').setValue(btcWalletBinance);  
  
  var btcWalletExmo  = -1;
  ssWallets.getRange('A8').setValue("BTC");
  ssWallets.getRange('B8').setValue("BTC on Exmo");
  //ssWallets.getRange('C8').setValue(btcWalletExmo); 
  //ssWallets.getRange('D8').setValue(btcWalletBinance);  
  
/* 
   ===== Nano Wallet Balances =========================================
     Uncomment the lines of code below
     Set the variable by pasting your Address inside of the ("") 
     Change getRange('A1') and getRange('B1') to match the row you want
   =================================================================== 
*/

  //var nanoWallet = getNanoBalance("Your Nano Address");
  //ssWallets.getRange('A1').setValue("Nano Wallet");
  //ssWallets.getRange('B1').setValue(nanoWallet);

/*
   ===== Ethereum Wallet Balances ====================================
     Create an account on Etherscan.io
     Create an API key at https://etherscan.io/myapikey
     Uncomment the lines of code below
     Set the API key variable by pasting your API key inside of the ("") 
     Set the address variable by pasting your Address inside of the ("") 
     Change getRange('A2') and getRange('B2') to match the row you want
   =================================================================== 
*/

  //var ethApiKey = "Your Etherscan API Key";
  //var ethWallet = getEthBalance(ethApiKey,"Your ETH Address");
  //ssWallets.getRange('A2').setValue("ETH Wallet");
  //ssWallets.getRange('B2').setValue(ethWallet);

/* 
   ===== BCH Wallet Balances =========================================
     Uncomment the lines of code below
     Set the variable by pasting your Address inside of the ("") 
     Change getRange('A3') and getRange('B3') to match the row you want
   =================================================================== 
*/

  //var bchWallet = getBchBalance("Your BCH Address");
  //ssWallets.getRange('A3').setValue("BCH Wallet");
  //ssWallets.getRange('B3').setValue(bchWallet);

/* 


/* 
   ===== DGB wallet balances =========================================
     Uncomment the lines of code below
     Set the variable by pasting your Address inside of the ("") 
     Change getRange('A5') and getRange('B5') to match the row you want
   =================================================================== 
*/

  //var dgbWallet = getDgbBalance("Your DGB Address");
  //ssWallets.getRange('A5').setValue("DGB Wallet");
  //ssWallets.getRange('B5').setValue(dgbWallet);

/* 
   ===== LTC wallet balances =========================================
     Uncomment the lines of code below
     Set the variable by pasting your Address inside of the ("") 
     Change getRange('A6') and getRange('B6') to match the row you want
   =================================================================== 
*/

  //var ltcWallet = getLtcBalance("Your LTC Address");
  //ssWallets.getRange('A6').setValue("LTC Wallet");
  //ssWallets.getRange('B6').setValue(ltcWallet);

/* 
   ===== VTC wallet balances =========================================
     Uncomment the lines of code below
     Set the variable by pasting your Address inside of the ("") 
     Change getRange('A7') and getRange('B7') to match the row you want
   =================================================================== 
*/

  //var vtcWallet = getVtcBalance("Your VTC Address");
  //ssWallets.getRange('A7').setValue("VTC Wallet");
  //ssWallets.getRange('B7').setValue(vtcWallet);
  
  
  /*
          /\      /\      /\      /\       /\
     ==============================================
     ==============================================

             FIAT WALLET BALANCE CONFIGURATION

     ============================================== 
*/  

  var fiatWallets = ss.getSheetByName('FiatWallets');
  if (fiatWallets === null) {fiatWallets = ss.insertSheet('FiatWallets');}

  fiatWallets.getRange('A1').setValue("Id");
  fiatWallets.getRange('B1').setValue("Location");
  fiatWallets.getRange('C1').setValue("Avialable");
  fiatWallets.getRange('D1').setValue("Blocked");
  
/*
   ===== BTC Wallet Balances =========================================
   =================================================================== 
*/
  var gdaxEurAvialbleAmmount =  getGdaxCurrencyAmount(GdaxWalletInfo,'EUR','available');
  var gdaxEurBlockedAmmount =  getGdaxCurrencyAmount(GdaxWalletInfo,'EUR','hold');
  fiatWallets.getRange('A2').setValue("EUR");
  fiatWallets.getRange('B2').setValue("GDAX Wallet");
  fiatWallets.getRange('C2').setValue(gdaxEurAvialbleAmmount);  
  fiatWallets.getRange('D2').setValue(gdaxEurBlockedAmmount);  
  
  
}

/*
   ========== DONT TOUCH UNLESS WIZARD ==========

        DON'T TOUCH ANYTHING BELOW UNLESS WIZARD
               IT MAKES THE MAGIC HAPPEN
 
       \/     \/    \/    \/    \/    \/    \/      
*/

function getCoins() {

  var url = 'https://api.coinmarketcap.com/v1/ticker/?limit=0&convert='+targetCurrency;
  var response = UrlFetchApp.fetch(url, {'muteHttpExceptions': true});
  var json = response.getContentText();
  var data = JSON.parse(json);
 
  return data;
}

function getGlobal() {
  //Setting up and formatting Global sheet
  var ssGlobal = ss.getSheetByName('Global');
  if (ssGlobal === null) {
    ssGlobal = ss.insertSheet('Global');
  } 
  var globalDateFormat = ssGlobal.getRange("B7");
  globalDateFormat.setNumberFormat("mmm dd h:mm A/P\".M.\"");
  //Pause to not trigger API limit
  Utilities.sleep(300);
  var timeNow = new Date();
  var url = 'https://api.coinmarketcap.com/v1/global/'
  var response = UrlFetchApp.fetch(url, {'muteHttpExceptions': true});
  var json = response.getContentText();
  var globaldata = JSON.parse(json);
  var tmcusd = globaldata['total_market_cap_usd'];
  var t24hvu = globaldata['total_24h_volume_usd'];
  var bpmc = globaldata['bitcoin_percentage_of_market_cap'];
  var ac = globaldata['active_currencies'];
  var aa = globaldata['active_assets'];
  var am = globaldata['active_markets'];
  var lu = new Date((globaldata['last_updated']) * 1000);
  ssGlobal.getRange('A1').setValue('total_market_cap_usd');
  ssGlobal.getRange('A2').setValue('total_24h_volume_usd');
  ssGlobal.getRange('A3').setValue('bitcoin_percentage_of_market_cap');
  ssGlobal.getRange('A4').setValue('active_currencies');
  ssGlobal.getRange('A5').setValue('active_assets');
  ssGlobal.getRange('A6').setValue('active_markets'); 
  ssGlobal.getRange('A7').setValue('last_updated');
  ssGlobal.getRange('B1').setValue(tmcusd);
  ssGlobal.getRange('B2').setValue(t24hvu);
  ssGlobal.getRange('B3').setValue(bpmc+'%');
  ssGlobal.getRange('B4').setValue(ac);
  ssGlobal.getRange('B5').setValue(aa);
  ssGlobal.getRange('B6').setValue(am); 
  ssGlobal.getRange('B7').setValue(lu); 
}


function getGdaxBalance(apiKey, apiSeceret, passPhrase)
{
  var restEndpointApiUrl =  'https://api.gdax.com';
  var date = new Date();
  var timestamp = Math.floor((date.getTime()/1000)).toString();
  
  var requestPath = '/accounts';
  
  var body =''; // the body is omitted as this is a get request
  
  var method = 'GET';
  
  // create the prehash string by concatenating required parts
  var singaturePlainText = timestamp + method + requestPath + body;
  
  // decode the base64 secret
  var apiSeceretDecoded = CryptoJS.enc.Base64.parse(apiSeceret);
  
  // create a sha256 hmac with the secret
  var msgSignatureHash = CryptoJS.HmacSHA256(singaturePlainText, apiSeceretDecoded);
  
  // sign the require message with the hmac
  // and finally base64 encode the result
  var encodedMsgSingature = msgSignatureHash.toString(CryptoJS.enc.Base64); 
  
  var requestUrl = restEndpointApiUrl + requestPath;

   var params = 
       {
         'method': method,
         'headers': 
         {
           'CB-ACCESS-KEY': apiKey, //The api key as a string
           'CB-ACCESS-SIGN': encodedMsgSingature, //Message signature
           'CB-ACCESS-TIMESTAMP': timestamp, //A timestamp for your request
           'CB-ACCESS-PASSPHRASE': passPhrase //The passphrase you specified when creating the API key
         }
       };
 
  var response = UrlFetchApp.fetch(requestUrl,params);
  var data = JSON.parse(response);
  return data
}

function getGdaxCurrencyAmount(gdaxInfo, currencyId,currStatus)
{
   var ammount = -1;
   for (var i = 0; i < Object.keys(gdaxInfo).length; i++) 
   {		
     var currencyInfo = gdaxInfo[i];
     if(currencyInfo['currency'] == currencyId)
     {
     	ammount =  currencyInfo[currStatus];
     }
   }
  return ammount;
}

function getNanoBalance(nanoAddress) {
  var url = 'https://api.nano.club/accounts/'+nanoAddress+'/balances/total';
  var response = UrlFetchApp.fetch(url, {'muteHttpExceptions': true});
  var balance = response.getContentText();
  //Pause to not trigger API limit for multiple wallets
  Utilities.sleep(300);
 
  return balance * Math.pow(10,-30);
}


function getEthBalance(ethApiKey,ethAddress) {
  var url = 'https://api.etherscan.io/api?module=account&action=balance&address='+ethAddress+'&tag=latest&apikey='+ethApiKey;
  var response = UrlFetchApp.fetch(url, {'muteHttpExceptions': true});
  var json = response.getContentText();
  var obj = JSON.parse(json);
  var balance = obj.result;
  //Pause to not trigger API limit for multiple wallets
  Utilities.sleep(300);
 
  return balance * Math.pow(10,-18);
}


function getBchBalance(bchAddress) {
  var url = 'https://bitcoincash.blockexplorer.com/api/addr/'+bchAddress+'/balance';
  var response = UrlFetchApp.fetch(url, {'muteHttpExceptions': true});
  var balance = response.getContentText();
  //Pause to not trigger API limit for multiple wallets
  Utilities.sleep(300);
 
  return balance * Math.pow(10,-8);
}


function getBtcBalance(btcAddress) {
  var url = 'https://blockexplorer.com/api/addr/'+btcAddress+'/balance';
  var response = UrlFetchApp.fetch(url, {'muteHttpExceptions': true});
  var balance = response.getContentText();
  //Pause to not trigger API limit for multiple wallets
  Utilities.sleep(300);
 
  return balance * Math.pow(10,-8);
}


function getDgbBalance(dgbAddress) {

  var url = 'https://chainz.cryptoid.info/dgb/api.dws?q=getbalance&a='+dgbAddress;
  var response = UrlFetchApp.fetch(url, {'muteHttpExceptions': true});
  var balance = response.getContentText();
  //Pause to not trigger API limit for multiple wallets
  Utilities.sleep(300);

  return balance;
}


function getLtcBalance(ltcAddress) {
  var url = 'https://chainz.cryptoid.info/ltc/api.dws?q=getbalance&a='+ltcAddress;
  var response = UrlFetchApp.fetch(url, {'muteHttpExceptions': true});
  var balance = response.getContentText();
  //Pause to not trigger API limit for multiple wallets
  Utilities.sleep(300);

  return balance;
}


function getVtcBalance(vtcAddress) {
  var url = 'http://explorer.vertcoin.info/ext/getbalance/'+vtcAddress;
  var response = UrlFetchApp.fetch(url, {'muteHttpExceptions': true});
  var balance = response.getContentText();
  //Pause to not trigger API limit for multiple wallets
  Utilities.sleep(300);
 
  return balance;
}


function about() {
  SpreadsheetApp.getUi()
     .alert('Visit https://github.com/saitei/crypto-sheets to get the latest dev build, report issues, or request new features!');
}