const crypto=require("crypto");

const response=(data,status=200)=>new Response(
JSON.stringify(data),
{
status,
headers:{
"content-type":"application/json;charset=utf-8",
"access-control-allow-origin":"*",
"access-control-allow-methods":"POST,OPTIONS",
"access-control-allow-headers":"content-type,x-api-key"
}
}
);

const xorData=(data,key)=>{

let out="";

for(let i=0;i<data.length;i++){

out+=String.fromCharCode(
data.charCodeAt(i)^
key.charCodeAt(i%key.length)
);

}

return out;
};

const shuffle=(data,seed)=>{

const a=data.split("");
let x=seed>>>0;

for(let i=a.length-1;i>0;i--){

x=(Math.imul(x,1664525)+1013904223)>>>0;

const j=x%(i+1);

const t=a[i];

a[i]=a[j];
a[j]=t;

}

return a.join("");

};

const makeLua=(source,options)=>{

const key=crypto.randomBytes(18).toString("hex");

const seed=crypto.randomBytes(4).readUInt32BE(0);

let payload=source;

if(options.xor!==false)
payload=xorData(payload,key);

let bytes=Buffer.from(payload,"latin1");

if(options.numeric!==false){

const arr=Array.from(bytes);

let x=seed>>>0;

for(let i=arr.length-1;i>0;i--){

x=(Math.imul(x,1664525)+1013904223)>>>0;

const j=x%(i+1);

const t=arr[i];

arr[i]=arr[j];
arr[j]=t;

}

bytes=Buffer.from(arr);

}

const encoded=
options.base64!==false
?bytes.toString("base64")
:bytes.toString("latin1");

if(options.loader===false)
return encoded;

return `local p=${JSON.stringify(encoded)}
local k=${JSON.stringify(key)}
local s=${seed}

local b="ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"

local function bx(a,c)
local r=0
local q=1

while a>0 or c>0 do

local x=a%2
local y=c%2

if x~=y then
r=r+q
end

a=math.floor(a/2)
c=math.floor(c/2)
q=q*2

end

return r
end

local function dec(x)

x=x:gsub("[^"..b.."=]","")

local o={}
local n=0
local v=0

for i=1,#x do

local c=x:sub(i,i)

if c~="=" then

local z=b:find(c,1,true)-1

v=v*64+z
n=n+1

if n==4 then

o[#o+1]=string.char(
math.floor(v/65536)%256,
math.floor(v/256)%256,
v%256
)

v=0
n=0

end
end
end

local out=table.concat(o)

local pad=0

if x:sub(-1)=="=" then
pad=1
end

if x:sub(-2,-2)=="=" then
pad=2
end

if pad>0 then
out=out:sub(1,-pad-1)
end

return out

end

local function unshuffle(a,seed)

local n=#a
local jlist={}
local x=seed

for i=n-1,1,-1 do

x=(x*1664525+1013904223)%4294967296

jlist[i]=x%(i+1)+1

end

for i=1,n-1 do

local ri=n-i
local j=jlist[ri]

local t=a[ri+1]

a[ri+1]=a[j]
a[j]=t

end

return a

end

local d=dec(p)

local a={}

for i=1,#d do
a[i]=d:byte(i)
end

a=unshuffle(a,s)

local q={}

for i=1,#a do
q[i]=string.char(a[i])
end

local z=table.concat(q)

local out={}

for i=1,#z do

out[i]=string.char(
bx(
z:byte(i),
k:byte((i-1)%#k+1)
)
)

end

local src=table.concat(out)

local f=loadstring or load

local fn,err=f(src)

if not fn then
error(err)
end

return fn()
`;
};

exports.handler=async(event)=>{

if(event.httpMethod==="OPTIONS")
return response({ok:true});

if(event.httpMethod!=="POST")
return response(
{ok:false,error:"POST فقط"},
405
);

const expected=process.env.LUA_SHIELD_API_KEY;

const supplied=
event.headers?.["x-api-key"]||
event.headers?.["X-Api-Key"]||
"";

if(expected&&supplied!==expected){

return response(
{ok:false,error:"مفتاح API غير صحيح"},
401
);

}

try{

const body=JSON.parse(event.body||"{}");

const source=
typeof body.code==="string"
?body.code
:"";

if(!source.trim())
return response(
{ok:false,error:"الكود فارغ"},
400
);

if(Buffer.byteLength(source,"utf8")>4500000)
return response(
{ok:false,error:"حجم الملف أكبر من الحد المسموح"},
413
);

const output=makeLua(
source,
body.options||{}
);

return response({
ok:true,
code:output,
filename:"protected.lua"
});

}catch(e){

return response(
{ok:false,error:"تعذر معالجة الطلب"},
500
);

}

};
