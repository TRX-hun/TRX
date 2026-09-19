const crypto=require("crypto");

const send=(data,status=200)=>{

return new Response(
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

};

const xorData=(data,key)=>{

let output="";

for(
let i=0;
i<data.length;
i++
){

output+=String.fromCharCode(
data.charCodeAt(i)^
key.charCodeAt(
i%key.length
)
);

}

return output;

};

const makeSeed=()=>{

return crypto
.randomBytes(4)
.readUInt32BE(0);

};

const shuffleBytes=(bytes,seed)=>{

const array=Array.from(bytes);

let x=seed>>>0;

for(
let i=array.length-1;
i>0;
i--
){

x=(
Math.imul(
x,
1664525
)+
1013904223
)>>>0;

const j=x%(i+1);

const temp=array[i];

array[i]=array[j];

array[j]=temp;

}

return Buffer.from(array);

};

const createLoader=(encoded,key,seed)=>{

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

local out={}
local n=0
local v=0

for i=1,#x do

local c=x:sub(i,i)

if c~="=" then

local pos=b:find(c,1,true)

if pos then

local z=pos-1

v=v*64+z

n=n+1

if n==4 then

out[#out+1]=string.char(
math.floor(v/16777216)%256,
math.floor(v/65536)%256,
math.floor(v/256)%256,
v%256
)

v=0
n=0

end

end

end

end

local result=table.concat(out)

local padding=0

if x:sub(-1)=="=" then
padding=1
end

if x:sub(-2,-2)=="=" then
padding=2
end

if padding>0 then

result=result:sub(
1,
#result-padding
)

end

return result

end

local function unshuffle(a,seed)

local n=#a
local swaps={}
local x=seed

for i=n-1,1,-1 do

x=(
x*1664525+
1013904223
)%4294967296

swaps[i]=x%(i+1)+1

end

for i=1,n-1 do

local index=n-i
local j=swaps[index]

local temp=a[index+1]

a[index+1]=a[j]
a[j]=temp

end

return a

end

local data=dec(p)

local bytes={}

for i=1,#data do

bytes[i]=data:byte(i)

end

bytes=unshuffle(bytes,s)

local chars={}

for i=1,#bytes do

chars[i]=string.char(bytes[i])

end

local encrypted=table.concat(chars)

local plain={}

for i=1,#encrypted do

plain[i]=string.char(
bx(
encrypted:byte(i),
k:byte(
(i-1)%#k+1
)
)

end

local source=table.concat(plain)

local loader=loadstring or load

local fn,errorMessage=loader(source)

if not fn then

error(errorMessage)

end

return fn()
`;

};

const obfuscate=(source,options)=>{

const key=crypto
.randomBytes(18)
.toString("hex");

const seed=makeSeed();

let payload=source;

if(options.xor!==false){

payload=xorData(
payload,
key
);

}

let bytes=Buffer.from(
payload,
"latin1"
);

if(options.numeric!==false){

bytes=shuffleBytes(
bytes,
seed
);

}

let encoded;

if(options.base64!==false){

encoded=bytes.toString(
"base64"
);

}else{

encoded=bytes.toString(
"latin1"
);

}

if(options.loader===false){

return encoded;

}

return createLoader(
encoded,
key,
seed
);

};

exports.handler=async(event)=>{

if(
event.httpMethod===
"OPTIONS"
){

return send({
ok:true
});

}

if(
event.httpMethod!==
"POST"
){

return send(
{
ok:false,
error:"يسمح بطلب POST فقط"
},
405
);

}

const configuredKey=
process.env.LUA_SHIELD_API_KEY;

const suppliedKey=
event.headers?.["x-api-key"]||
event.headers?.["X-Api-Key"]||
"";

if(
configuredKey&&
suppliedKey!==configuredKey
){

return send(
{
ok:false,
error:"مفتاح API غير صحيح"
},
401
);

}

try{

const body=
JSON.parse(
event.body||"{}"
);

const source=
typeof body.code===
"string"
?
body.code
:
"";

if(!source.trim()){

return send(
{
ok:false,
error:"الكود فارغ"
},
400
);

}

if(
Buffer.byteLength(
source,
"utf8"
)>4500000
){

return send(
{
ok:false,
error:"حجم الملف أكبر من الحد المسموح"
},
413
);

}

const options=
body.options||
{};

const output=
obfuscate(
source,
options
);

return send({
ok:true,
code:output,
filename:"protected.lua"
});

}catch(error){

return send(
{
ok:false,
error:
"حدث خطأ داخل الخادم: "+
(
error.message||
"Unknown error"
)
},
500
);

}

};
