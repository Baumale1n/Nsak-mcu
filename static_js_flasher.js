/* ============================================================
   flasher.js — BLE OTA flasher for kasai's cfw builder
   Pairing/session stack aligned with working neinbot.html.
   OTA profiles (mcu/vcu/ble/bms) from N-SAK go.* table.
   ============================================================ */
(function(global){
'use strict';

var X={HOST:62,VCU:22,MCU:2,BLE:4,BMS:7};
var SERVICE_UUID='6e400001-b5a3-f393-e0a9-e50e24dcca9e';
var RX_UUID='6e400002-b5a3-f393-e0a9-e50e24dcca9e';
var TX_UUID='6e400003-b5a3-f393-e0a9-e50e24dcca9e';

function Ia(f){if(f.data.length>255)throw RangeError('frame too long');var t=new Uint8Array(7+f.data.length);t[0]=0x5A;t[1]=0xA5;t[2]=f.data.length;t[3]=f.src;t[4]=f.dst;t[5]=f.cmd;t[6]=f.arg;t.set(f.data,7);return t}
function La(e){if(e.length<7||e[0]!==0x5A||e[1]!==0xA5)return null;var t=e[2];if(e.length<7+t)return null;return{src:e[3],dst:e[4],cmd:e[5],arg:e[6],data:e.slice(7,7+t)}}
var sleep=function(ms){return new Promise(function(r){setTimeout(r,ms)})};

/* ---- Nbc pairing/session crypto (matches working neinbot.html) ---- */
var Bo=Uint8Array.of(151,207,184,2,132,65,67,222,86,0,43,59,52,120,10,93);
async function Uo(e,t){var n=new Uint8Array(32);n.set(e,0);n.set(t,16);return new Uint8Array(await crypto.subtle.digest('SHA-1',n)).slice(0,16)}
async function Vo(e,t){var n=await crypto.subtle.importKey('raw',e,{name:'AES-CBC'},false,['encrypt']);return new Uint8Array(await crypto.subtle.encrypt({name:'AES-CBC',iv:new Uint8Array(16)},n,t)).slice(0,16)}
function xorBuf(a,b){var d=new Uint8Array(16);for(var i=0;i<16;i++)d[i]=a[i]^b[i];return d}

class Nbc{
  constructor(name){
    var enc=new TextEncoder();
    var d=typeof name==='string'?enc.encode(name):name;
    this.nameData=new Uint8Array(16);
    this.nameData.set(d.subarray(0,Math.min(16,d.length)));
    this.bleData=new Uint8Array(16);
    this.appData=new Uint8Array(16);
    this.sha1=null;
    this.msgIt=0;
    this.peerAddr=0;
    this.initialKeyTail=new Uint8Array(14);
    this.initialKeyReceived=false;
    this.recalcReceived=false;
    this.pairedReceived=false;
  }
  async init(){this.sha1=await Uo(this.nameData,Bo)}
  setAppData(d){if(d.length!==16)throw Error('app_data must be 16 bytes');this.appData=d.slice()}
  async cryptoFirst(e){
    var t=await Vo(this.sha1,Bo);
    var n=new Uint8Array(e.length);
    for(var r=0;r<e.length;r+=16){
      var i=Math.min(16,e.length-r);
      for(var a=0;a<i;a++)n[r+a]=e[r+a]^t[a];
    }
    return n;
  }
  async cryptoNext(e,t){
    var n=new Uint8Array(16);
    n[0]=1;n[1]=(t>>>24)&255;n[2]=(t>>>16)&255;n[3]=(t>>>8)&255;n[4]=t&255;
    n.set(this.bleData.subarray(0,8),5);
    var r=new Uint8Array(e.length),i=0;
    for(var a=0;a<e.length;a+=16){
      i+=1;n[15]=i&255;
      var o=await Vo(this.sha1,n);
      var s=Math.min(16,e.length-a);
      for(var c=0;c<s;c++)r[a+c]=e[a+c]^o[c];
    }
    return r;
  }
  async computeMac(e,t){
    var n=e.length-3,r=new Uint8Array(16);
    r[0]=89;r[1]=(t>>>24)&255;r[2]=(t>>>16)&255;r[3]=(t>>>8)&255;r[4]=t&255;
    r.set(this.bleData.subarray(0,8),5);r[15]=n&255;
    var i=await Vo(this.sha1,r);
    var a=new Uint8Array(16);a.set(e.subarray(0,3),0);
    i=await Vo(this.sha1,xorBuf(a,i));
    for(var o=0;o<n;o+=16){
      var s=new Uint8Array(16);
      var l=Math.min(16,n-o);
      s.set(e.subarray(3+o,3+o+l),0);
      i=await Vo(this.sha1,xorBuf(s,i));
    }
    var u=new Uint8Array(16);
    u[0]=1;u[1]=(t>>>24)&255;u[2]=(t>>>16)&255;u[3]=(t>>>8)&255;u[4]=t&255;
    u.set(this.bleData.subarray(0,8),5);
    var p=await Vo(this.sha1,u);
    return Uint8Array.of(p[0]^i[0],p[1]^i[1],p[2]^i[2],p[3]^i[3]);
  }
  async decrypt(e){
    if(e.length<9||e[0]!==0x5A||e[1]!==0xA5)return null;
    var t=this.msgIt,n=(e[e.length-2]<<8|e[e.length-1])&0xFFFF;
    if((t&0x8000)&&!(e[e.length-2]>>7))t+=0x10000;
    var r=(t&0xFFFF0000)|n;
    var i=e.length-9,a=e.slice(3,3+i),o=e.slice(0,3);
    var s=new Uint8Array(3+i);s.set(o,0);
    if(r===0){
      var c=await this.cryptoFirst(a);s.set(c,3);
      if(s.length>=23&&s[2]>=22&&s[4]===62&&s[5]===91&&s[6]===1){
        this.bleData=s.slice(7,23);
        this.peerAddr=s[3];
        if(s.length>=37)this.initialKeyTail=s.slice(23,37);
        this.sha1=this.appData.some(function(v){return v!==0})?await Uo(this.appData,this.bleData):await Uo(this.nameData,this.bleData);
        this.initialKeyReceived=true;
      }
      return s;
    }
    var l=await this.cryptoNext(a,r);s.set(l,3);
    if(s.length>=23&&s[2]===16&&s[3]===62&&s[5]===92&&s[6]===0)this.appData=s.slice(7,23);
    if(s.length>=7&&s[2]===0&&s[4]===62&&s[5]===92&&s[6]===1){this.sha1=await Uo(this.appData,this.bleData);this.recalcReceived=true}
    if(s.length>=7&&s[2]===0&&s[4]===62&&s[5]===93&&s[6]===1)this.pairedReceived=true;
    this.msgIt=r;
    return s;
  }
  async encrypt(e){
    if(e[0]!==0x5A||e[1]!==0xA5)throw Error('frame must start with 5A A5');
    var t=e.slice(0,3),n=e.slice(3);
    if(this.msgIt===0){
      var r=0;for(var o of n)r=(r+o)&0xFFFF;
      var i=((r^0xFFFF)&0xFFFF);
      var a=await this.cryptoFirst(n);
      var s=new Uint8Array(3+a.length+6);
      s.set(t,0);s.set(a,3);
      s[3+a.length+2]=i&255;s[3+a.length+3]=(i>>>8)&255;
      return s;
    }
    this.msgIt+=1;
    var c=await this.computeMac(e,this.msgIt);
    var l=await this.cryptoNext(n,this.msgIt);
    var u=new Uint8Array(3+l.length+6);
    u.set(t,0);u.set(l,3);u.set(c,3+l.length);
    u[3+l.length+4]=(this.msgIt>>>8)&255;u[3+l.length+5]=this.msgIt&255;
    return u;
  }
}

function createFrameAssembler(ble){
  var listeners=new Set(),buf=new Uint8Array(0);
  ble.onTx(function(chunk){
    var merged=new Uint8Array(buf.length+chunk.length);
    merged.set(buf,0);merged.set(chunk,buf.length);buf=merged;
    while(buf.length>=3){
      var start=-1;
      for(var i=0;i<=buf.length-2;i++){if(buf[i]===0x5A&&buf[i+1]===0xA5){start=i;break}}
      if(start<0){buf=buf.subarray(buf.length-1);break}
      if(start>0)buf=buf.subarray(start);
      if(buf.length<3)break;
      var frameLen=3+buf[2]+10;
      if(buf.length<frameLen)break;
      var frame=buf.subarray(0,frameLen).slice();
      buf=buf.subarray(frameLen);
      listeners.forEach(function(cb){cb(frame)});
    }
  });
  return{onFrame:function(cb){listeners.add(cb);return function(){listeners.delete(cb)}}};
}

class BleDevice{
  constructor(device){
    this.device=device;
    this.id=device.id;
    this.name=device.name||'Scooter';
    this._txChar=null;this._rxChar=null;
    this._listeners=[];
    this._writeChain=Promise.resolve();
  }
  async connect(){
    var server=await this.device.gatt.connect();
    var svc=await server.getPrimaryService(SERVICE_UUID);
    this._rxChar=await svc.getCharacteristic(RX_UUID);
    this._txChar=await svc.getCharacteristic(TX_UUID);
    await this._txChar.startNotifications();
    this._txChar.addEventListener('characteristicvaluechanged',this._onValue.bind(this));
  }
  _onValue(ev){
    var val=ev.target.value;
    if(val){
      var data=new Uint8Array(val.buffer,val.byteOffset,val.byteLength).slice();
      for(var cb of this._listeners)cb(data);
    }
  }
  onTx(cb){this._listeners.push(cb)}
  write(data,withResponse){
    var buf=new Uint8Array(data).buffer;
    var self=this;
    var run=this._writeChain.then(async function(){
      if(withResponse&&self._rxChar.writeValueWithResponse){
        try{await self._rxChar.writeValueWithResponse(buf);return}catch(e){}
      }
      if(self._rxChar.writeValueWithoutResponse)await self._rxChar.writeValueWithoutResponse(buf);
      else await self._rxChar.writeValue(buf);
    });
    this._writeChain=run.then(function(){},function(){});
    return run;
  }
  async disconnect(){
    try{await this._txChar.stopNotifications()}catch(e){}
    if(this.device.gatt&&this.device.gatt.connected)this.device.gatt.disconnect();
  }
}

var KeyStore={
  load:async function(id){
    try{var raw=localStorage.getItem('nbc_'+id);return raw?new Uint8Array(JSON.parse(raw)):null}catch(e){return null}
  },
  save:async function(id,data){
    try{localStorage.setItem('nbc_'+id,JSON.stringify(Array.from(data)))}catch(e){}
  },
  delete:async function(id){
    try{localStorage.removeItem('nbc_'+id)}catch(e){}
  }
};

class NbcSession{
  constructor(ble,bleName,store){
    this.ble=ble;
    this.bleName=bleName;
    this.store=store||KeyStore;
    this.pending=[];
    this.dstTails=new Map();
    this.nbc=null;
    this.assembler=createFrameAssembler(this.ble);
    this.assembler.onFrame(this._handleIncoming.bind(this));
  }
  async start(onPowerHint){
    this.nbc=new Nbc(this.bleName);
    await this.nbc.init();
    var cached=await this.store.load(this.ble.id);
    if(cached&&cached.length===16){
      this.nbc.setAppData(cached);
      try{
        await this._requestInitialKeyWithFallback();
        await this._waitForConfirmReady(8000);
        return;
      }catch(e){
        await this.store.delete(this.ble.id);
        this.nbc=new Nbc(this.bleName);
        await this.nbc.init();
      }
    }
    await this._requestInitialKeyWithFallback();
    if(onPowerHint)onPowerHint(true);
    for(var i=0;i<4;i++)await this._sendSaveAppKey();
    await this._waitForRecalcKey();
    if(onPowerHint)onPowerHint(false);
    await this._waitForConfirmReady();
    try{await this.store.save(this.ble.id,this.nbc.appData)}catch(e){}
  }
  async _requestInitialKeyWithFallback(){
    await this._sendRequestInitialKey(X.BLE);
    try{await this._waitForInitialKey(4000);return}catch(e){}
    await this._sendRequestInitialKey(33);
    await this._waitForInitialKey(6000);
  }
  async _sendRequestInitialKey(dst){
    var f=Uint8Array.of(0x5A,0xA5,0,62,dst,91,0);
    await this.ble.write(await this.nbc.encrypt(f),true);
  }
  async _waitForInitialKey(timeout){
    var t=Date.now();
    while(!this.nbc.initialKeyReceived){
      if(Date.now()-t>timeout)throw new Error('INITIAL_KEY not received (Auth-Key falsch oder Scooter antwortet nicht)');
      await sleep(100);
    }
  }
  async _sendSaveAppKey(){
    var app=crypto.getRandomValues(new Uint8Array(16));
    this.nbc.setAppData(app);
    var dst=this.nbc.peerAddr||X.BLE;
    var f=new Uint8Array(23);
    f.set([0x5A,0xA5,16,62,dst,92,0],0);
    f.set(app,7);
    await this.ble.write(await this.nbc.encrypt(f),true);
  }
  async _waitForRecalcKey(timeout){
    timeout=timeout||60000;
    var t=Date.now(),last=Date.now();
    while(!this.nbc.recalcReceived){
      if(Date.now()-t>timeout)throw new Error('RECALC_KEY not received - Power-Taste am Roller nicht gedrueckt?');
      if(Date.now()-last>500){await this._sendSaveAppKey();last=Date.now()}
      await sleep(50);
    }
  }
  async _sendConfirmReady(){
    var dst=this.nbc.peerAddr||X.BLE;
    var f=new Uint8Array(21);
    f.set([0x5A,0xA5,14,62,dst,93,0],0);
    f.set(this.nbc.initialKeyTail,7);
    await this.ble.write(await this.nbc.encrypt(f),true);
  }
  async _waitForConfirmReady(timeout){
    timeout=timeout||10000;
    var t=Date.now(),last=0;
    while(!this.nbc.pairedReceived){
      if(Date.now()-t>timeout)throw new Error('D0 confirm not acked');
      if(Date.now()-last>500){await this._sendConfirmReady();last=Date.now()}
      await sleep(50);
    }
  }
  async _handleIncoming(raw){
    if(!this.nbc)return;
    var dec;try{dec=await this.nbc.decrypt(raw)}catch(e){return}
    if(!dec)return;
    var frame=La(dec);if(!frame)return;
    if(frame.src===this.nbc.peerAddr&&(frame.cmd===91||frame.cmd===92||frame.cmd===93))return;
    var idx=this.pending.findIndex(function(e){
      return e.target===frame.src&&(!e.expectedCmd||e.expectedCmd.has(frame.cmd));
    });
    if(idx>=0){
      var entry=this.pending.splice(idx,1)[0];
      clearTimeout(entry.timer);
      entry.resolve(frame);
    }
  }
  async request(frame,timeout,opts){
    var dst=frame.dst;
    var prev=this.dstTails.get(dst)||Promise.resolve();
    var self=this;
    var run=prev.then(function(){return self._doRequest(frame,timeout,opts)},function(){return self._doRequest(frame,timeout,opts)});
    var tailGuard=run.then(function(){},function(){});
    this.dstTails.set(dst,tailGuard);
    return run;
  }
  async _doRequest(frame,timeout,opts){
    var self=this;
    return new Promise(function(resolve,reject){
      var data=Ia(frame);
      var expected=(opts&&opts.expectedCmd)?new Set(Array.isArray(opts.expectedCmd)?opts.expectedCmd:[opts.expectedCmd]):null;
      var entry={target:frame.dst,expectedCmd:expected,resolve:resolve,reject:reject};
      var timer=setTimeout(function(){
        var idx=self.pending.indexOf(entry);
        if(idx>=0)self.pending.splice(idx,1);
        reject(new Error('timeout dst=0x'+frame.dst.toString(16)+' cmd=0x'+frame.cmd.toString(16)+' arg=0x'+frame.arg.toString(16)));
      },timeout||10000);
      entry.timer=timer;
      self.pending.push(entry);
      self.nbc.encrypt(data).then(function(enc){return self.ble.write(enc,true)}).catch(function(err){
        clearTimeout(timer);
        var idx=self.pending.indexOf(entry);
        if(idx>=0)self.pending.splice(idx,1);
        reject(err);
      });
    });
  }
  async sendNoReply(frame){
    var data=Ia(frame);
    var enc=await this.nbc.encrypt(data);
    await this.ble.write(enc,false);
  }
  async readRegister(dst,reg,len,timeout){
    var f={src:X.HOST,dst:dst,cmd:1,arg:reg,data:Uint8Array.of(len&255,(len>>8)&255)};
    var resp=await this.request(f,timeout||1500,{expectedCmd:4});
    if(resp.arg!==reg)throw new Error('readRegister arg mismatch');
    if(resp.data.length!==len)throw new Error('readRegister length mismatch');
    return resp.data;
  }
  async writeRegister(dst,reg,data,timeout){
    var f={src:X.HOST,dst:dst,cmd:2,arg:reg,data:data};
    var resp=await this.request(f,timeout||1500,{expectedCmd:5});
    if(resp.cmd!==5||resp.arg!==reg)throw new Error('writeRegister unexpected ack');
    if(resp.data.length>=2&&(resp.data[0]|(resp.data[1]<<8)))throw new Error('writeRegister rejected 0x'+(resp.data[0]|(resp.data[1]<<8)).toString(16));
  }
  async calibRead(dst,offset,len,timeout){
    var f={src:X.HOST,dst:dst,cmd:174,arg:offset,data:Uint8Array.of(len&255,(len>>8)&255)};
    var resp=await this.request(f,timeout||900,{expectedCmd:174});
    if(resp.arg!==offset)throw new Error('calib read arg mismatch off=0x'+offset.toString(16));
    return resp.data;
  }
  async calibWrite(dst,offset,data,timeout){
    if(offset<0||data.length<1||offset+data.length>256)throw new Error('calib write out of range');
    var f={src:X.HOST,dst:dst,cmd:173,arg:offset,data:data};
    var resp=await this.request(f,timeout||1800,{expectedCmd:173});
    if(resp.arg!==offset)throw new Error('calib write ack arg mismatch');
  }
  /* N-SAK Flash-Slots: cmd 241=f-read→244, cmd 242=f-write→245 */
  async flashReadSlot(slot,len,timeout){
    var f={src:X.HOST,dst:X.VCU,cmd:241,arg:slot,data:new Uint8Array(0)};
    var resp=await this.request(f,timeout||5000,{expectedCmd:244});
    if(resp.arg!==slot)throw new Error('f-read slot 0x'+slot.toString(16)+' rejected');
    if(resp.data.length!==len)throw new Error('f-read length mismatch expected '+len+' got '+resp.data.length);
    return resp.data;
  }
  async flashWriteSlot(slot,data,timeout){
    var f={src:X.HOST,dst:X.VCU,cmd:242,arg:slot,data:data};
    var resp=await this.request(f,timeout||5000,{expectedCmd:245});
    if(resp.arg!==slot)throw new Error('f-write slot 0x'+slot.toString(16)+' rejected');
  }
  async close(){
    this.pending.forEach(function(e){clearTimeout(e.timer);e.reject(new Error('session closed'))});
    this.pending=[];
    await this.ble.disconnect();
  }
}

/* ---- OTA profiles (N-SAK go.*) ---- */
var PROFILES={
  ble:{dst:X.BLE,pageSize:128,hd:true, postWaitMs:8000,pageTimeoutMs:5000,startTimeoutMs:5000,interPageDelayMs:0, startExpected:[7,11],pageExpected:[8,11],csExpected:[9,11]},
  vcu:{dst:X.VCU,pageSize:128,hd:false,postWaitMs:8000,pageTimeoutMs:2000,startTimeoutMs:5000,interPageDelayMs:0, startExpected:[7,11],pageExpected:[8,11],csExpected:[9,11]},
  mcu:{dst:X.MCU,pageSize:128,hd:false,postWaitMs:8000,pageTimeoutMs:6000,startTimeoutMs:9000,interPageDelayMs:15,startExpected:[7,11],pageExpected:[8,11],csExpected:[9,11]},
  bms:{dst:X.BMS,pageSize:128,hd:false,postWaitMs:8000,pageTimeoutMs:6000,startTimeoutMs:9000,interPageDelayMs:15,startExpected:[7,11],pageExpected:[8,11],csExpected:[9,11]}
};
var RETRY_DELAYS=[0,150,400,900];

function frame(dst,cmd,arg,data){return{src:X.HOST,dst:dst,cmd:cmd,arg:arg,data:data}}
function startPayload(len,md5,hd){
  var b=new Uint8Array(hd?20:4);
  b[0]=len&255;b[1]=(len>>>8)&255;b[2]=(len>>>16)&255;b[3]=(len>>>24)&255;
  if(hd&&md5)b.set(md5,4);
  return b;
}
function pageSlice(fw,idx,pageSize){
  var off=idx*pageSize,b=new Uint8Array(pageSize),n=Math.min(pageSize,fw.length-off);
  if(n>0)b.set(fw.subarray(off,off+n),0);
  return b;
}
function checkAck(label,ack){
  if(ack===0)return;
  if(ack===7)throw new Error(label+' abgelehnt (ACK=7) - Roller nimmt diese Firmware nicht an, evtl. noch gesperrt.');
  if(ack===255)throw new Error(label+' vom Roller abgebrochen (ACK=255)');
  throw new Error(label+' fehlgeschlagen (ACK=0x'+ack.toString(16)+')');
}
async function requestWithRetry(session,f,timeout,expectedCmd,delays){
  var lastErr;
  for(var i=0;i<delays.length;i++){
    if(i>0&&delays[i]>0)await sleep(delays[i]);
    try{return await session.request(f,timeout,{expectedCmd:expectedCmd})}catch(e){lastErr=e}
  }
  throw lastErr;
}

function md5js(bytes){
  function cmn(q,a,b,x,s,t){a=a+(q+x+t)|0;return(((a<<s)|(a>>> (32-s)))+b)|0}
  function ff(a,b,c,d,x,s,t){return cmn((b&c)|((~b)&d),a,b,x,s,t)}
  function gg(a,b,c,d,x,s,t){return cmn((b&d)|(c&(~d)),a,b,x,s,t)}
  function hh(a,b,c,d,x,s,t){return cmn(b^c^d,a,b,x,s,t)}
  function ii(a,b,c,d,x,s,t){return cmn(c^(b|(~d)),a,b,x,s,t)}
  var n=bytes.length, state=new Int32Array([1732584193,-271733879,-1732584194,271733878]);
  function md5blk(x){
    var a=state[0],b=state[1],c=state[2],d=state[3];
    a=ff(a,b,c,d,x[0],7,-680876936);d=ff(d,a,b,c,x[1],12,-389564586);c=ff(c,d,a,b,x[2],17,606105819);b=ff(b,c,d,a,x[3],22,-1044525330);
    a=ff(a,b,c,d,x[4],7,-176418897);d=ff(d,a,b,c,x[5],12,1200080426);c=ff(c,d,a,b,x[6],17,-1473231341);b=ff(b,c,d,a,x[7],22,-45705983);
    a=ff(a,b,c,d,x[8],7,1770035416);d=ff(d,a,b,c,x[9],12,-1958414417);c=ff(c,d,a,b,x[10],17,-42063);b=ff(b,c,d,a,x[11],22,-1990404162);
    a=ff(a,b,c,d,x[12],7,1804603682);d=ff(d,a,b,c,x[13],12,-40341101);c=ff(c,d,a,b,x[14],17,-1502002290);b=ff(b,c,d,a,x[15],22,1236535329);
    a=gg(a,b,c,d,x[1],5,-165796510);d=gg(d,a,b,c,x[6],9,-1069501632);c=gg(c,d,a,b,x[11],14,643717713);b=gg(b,c,d,a,x[0],20,-373897302);
    a=gg(a,b,c,d,x[5],5,-701558691);d=gg(d,a,b,c,x[10],9,38016083);c=gg(c,d,a,b,x[15],14,-660478335);b=gg(b,c,d,a,x[4],20,-405537848);
    a=gg(a,b,c,d,x[9],5,568446438);d=gg(d,a,b,c,x[14],9,-1019803690);c=gg(c,d,a,b,x[3],14,-187363961);b=gg(b,c,d,a,x[8],20,1163531501);
    a=gg(a,b,c,d,x[13],5,-1444681467);d=gg(d,a,b,c,x[2],9,-51403784);c=gg(c,d,a,b,x[7],14,1735328473);b=gg(b,c,d,a,x[12],20,-1926607734);
    a=hh(a,b,c,d,x[5],4,-378558);d=hh(d,a,b,c,x[8],11,-2022574463);c=hh(c,d,a,b,x[11],16,1839030562);b=hh(b,c,d,a,x[14],23,-35309556);
    a=hh(a,b,c,d,x[1],4,-1530992060);d=hh(d,a,b,c,x[4],11,1272893353);c=hh(c,d,a,b,x[7],16,-155497632);b=hh(b,c,d,a,x[10],23,-1094730640);
    a=hh(a,b,c,d,x[13],4,681279174);d=hh(d,a,b,c,x[0],11,-358537222);c=hh(c,d,a,b,x[3],16,-722521979);b=hh(b,c,d,a,x[6],23,76029189);
    a=hh(a,b,c,d,x[9],4,-640364487);d=hh(d,a,b,c,x[12],11,-421815835);c=hh(c,d,a,b,x[15],16,530742520);b=hh(b,c,d,a,x[2],23,-995338651);
    a=ii(a,b,c,d,x[0],6,-198630844);d=ii(d,a,b,c,x[7],10,1126891415);c=ii(c,d,a,b,x[14],15,-1416354905);b=ii(b,c,d,a,x[5],21,-57434055);
    a=ii(a,b,c,d,x[12],6,1700485571);d=ii(d,a,b,c,x[3],10,-1894986606);c=ii(c,d,a,b,x[10],15,-1051523);b=ii(b,c,d,a,x[1],21,-2054922799);
    a=ii(a,b,c,d,x[8],6,1873313359);d=ii(d,a,b,c,x[15],10,-30611744);c=ii(c,d,a,b,x[6],15,-1560198380);b=ii(b,c,d,a,x[13],21,1309151649);
    a=ii(a,b,c,d,x[4],6,-145523070);d=ii(d,a,b,c,x[11],10,-1120210379);c=ii(c,d,a,b,x[2],15,718787259);b=ii(b,c,d,a,x[9],21,-343485551);
    state[0]=(state[0]+a)|0;state[1]=(state[1]+b)|0;state[2]=(state[2]+c)|0;state[3]=(state[3]+d)|0;
  }
  var i=0, block=new Int32Array(16);
  for(;i+64<=n;i+=64){
    for(var j=0;j<16;j++)block[j]=bytes[i+j*4]|(bytes[i+j*4+1]<<8)|(bytes[i+j*4+2]<<16)|(bytes[i+j*4+3]<<24);
    md5blk(block);
  }
  var tail=new Uint8Array(64);tail.set(bytes.subarray(i));
  tail[n-i]=0x80;
  if(n-i>=56){
    for(var j=0;j<16;j++)block[j]=tail[j*4]|(tail[j*4+1]<<8)|(tail[j*4+2]<<16)|(tail[j*4+3]<<24);
    md5blk(block);tail=new Uint8Array(64);
  }
  var bitLen=n*8;
  tail[56]=bitLen&255;tail[57]=(bitLen>>>8)&255;tail[58]=(bitLen>>>16)&255;tail[59]=(bitLen>>>24)&255;
  for(var j=0;j<16;j++)block[j]=tail[j*4]|(tail[j*4+1]<<8)|(tail[j*4+2]<<16)|(tail[j*4+3]<<24);
  md5blk(block);
  var out=new Uint8Array(16);
  for(var e=0;e<4;e++){var r=state[e];out[e*4]=r&255;out[e*4+1]=(r>>>8)&255;out[e*4+2]=(r>>>16)&255;out[e*4+3]=(r>>>24)&255}
  return out;
}

async function flashPartition(session,partition,firmware,onPhase,onProgress){
  var p=PROFILES[partition];
  if(!p)throw new Error('Unbekannte Partition: '+partition);
  var totalPages=Math.ceil(firmware.length/p.pageSize);
  var md5=p.hd?md5js(firmware):null;
  onPhase&&onPhase('starting');
  var startAck=await requestWithRetry(
    session,
    frame(p.dst,7,0,startPayload(firmware.length,md5,p.hd)),
    p.startTimeoutMs,p.startExpected,[0,300,800]
  );
  checkAck('start_update',startAck.arg);
  onPhase&&onPhase('flashing');
  for(var idx=0;idx<totalPages;idx++){
    var pageAck=await requestWithRetry(
      session,
      frame(p.dst,8,idx&255,pageSlice(firmware,idx,p.pageSize)),
      p.pageTimeoutMs,p.pageExpected,RETRY_DELAYS
    );
    checkAck('update_page',pageAck.arg);
    onProgress&&onProgress(idx+1,totalPages);
    if(p.interPageDelayMs>0)await sleep(p.interPageDelayMs);
  }
  onPhase&&onPhase('finalizing');
  var sum=0;for(var i=0;i<firmware.length;i++)sum=(sum+firmware[i])|0;
  var crc=(~sum)>>>0;
  var csAck=await requestWithRetry(
    session,
    frame(p.dst,9,0,Uint8Array.of(crc&255,(crc>>>8)&255,(crc>>>16)&255,(crc>>>24)&255)),
    10000,p.csExpected,[0,500]
  );
  checkAck('update_checksum',csAck.arg);
  onPhase&&onPhase('resetting');
  for(var r=0;r<4;r++){await session.sendNoReply(frame(p.dst,10,0,new Uint8Array(0)));await sleep(100)}
  onPhase&&onPhase('post-wait');
  await sleep(p.postWaitMs);
  onPhase&&onPhase('done');
}

async function pickAndConnect(onStatus){
  if(!navigator.bluetooth)throw new Error('Web Bluetooth wird von diesem Browser nicht unterstuetzt (Chrome/Edge Desktop/Android).');
  onStatus&&onStatus('Waehle deinen Scooter...');
  var device=await navigator.bluetooth.requestDevice({
    filters:[
      {namePrefix:'1CG'},
      {namePrefix:'1K1'},
      {namePrefix:'NB'},
      {namePrefix:'Segway'}
    ],
    optionalServices:[SERVICE_UUID]
  });
  var bleName=device.name||'Scooter';
  onStatus&&onStatus('Verbinde mit '+bleName+'...');
  var ble=new BleDevice(device);
  await ble.connect();
  /* CRITICAL: crypto key is derived from the BLE advertisement name */
  var session=new NbcSession(ble,bleName);
  onStatus&&onStatus('Pairing (ggf. Power-Taste am Roller druecken)...');
  await session.start(function(waiting){
    if(waiting)onStatus&&onStatus('Bitte kurz die Power-Taste am Roller druecken...');
  });
  return session;
}

async function flash(partition,firmwareBytes,callbacks){
  callbacks=callbacks||{};
  var onStatus=callbacks.onStatus||function(){};
  var onPhase=callbacks.onPhase||function(){};
  var onProgress=callbacks.onProgress||function(){};
  partition=(partition||'mcu').toLowerCase();
  if(!PROFILES[partition])throw new Error('Partition nicht unterstuetzt: '+partition);
  var session=await pickAndConnect(onStatus);
  try{
    onStatus('Verbunden, starte '+partition.toUpperCase()+'-Flash ('+firmwareBytes.length+' Bytes)...');
    await flashPartition(session,partition,firmwareBytes,onPhase,onProgress);
    onStatus('Fertig! Roller startet neu.');
  }finally{
    try{await session.close()}catch(e){}
  }
}

async function flashMcu(firmwareBytes,callbacks){return flash('mcu',firmwareBytes,callbacks)}

global.CfwFlasher={
  flash:flash,
  flashMcu:flashMcu,
  flashVcu:function(b,c){return flash('vcu',b,c)},
  flashBle:function(b,c){return flash('ble',b,c)},
  flashBms:function(b,c){return flash('bms',b,c)},
  connect:pickAndConnect,
  X:X,
  PROFILES:PROFILES
};
})(window);
