const http=require('http'),fs=require('fs'),path=require('path'),crypto=require('crypto');
const sessions=new Map();
const PORT=process.env.PORT||3000, ROOT=path.join(__dirname,'public'), DATA=path.join(__dirname,'data','orders.json');
const products=[{"id": 1, "stars": 50, "name": "بسته پایه", "price": 198603}, {"id": 2, "stars": 100, "name": "بسته کوچک", "price": 397205}, {"id": 3, "stars": 150, "name": "بسته ۱۵۰", "price": 609047}, {"id": 4, "stars": 250, "name": "بسته ۲۵۰", "price": 993012}, {"id": 5, "stars": 350, "name": "بسته ۳۵۰", "price": 1403457}, {"id": 6, "stars": 500, "name": "پیشنهاد ویژه", "price": 1986024}, {"id": 7, "stars": 1000, "name": "بسته حرفه‌ای", "price": 3972047}, {"id": 8, "stars": 2500, "name": "بسته طلایی", "price": 9930117}, {"id": 9, "stars": 5000, "name": "بسته بزرگ", "price": 19860234}, {"id": 10, "stars": 10000, "name": "بسته ویژه", "price": 39720466}, {"id": 11, "stars": 50000, "name": "بسته ۵۰ هزار", "price": 198602333}, {"id": 12, "stars": 25000, "name": "بسته ۲۵ هزار", "price": 99301167}];
if(!fs.existsSync(path.dirname(DATA)))fs.mkdirSync(path.dirname(DATA),{recursive:true});
if(!fs.existsSync(DATA))fs.writeFileSync(DATA,'[]','utf8');
function readOrders(){try{return JSON.parse(fs.readFileSync(DATA,'utf8'))}catch{return []}}
function writeOrders(x){fs.writeFileSync(DATA,JSON.stringify(x,null,2),'utf8')}
function json(res,code,obj){const s=JSON.stringify(obj);res.writeHead(code,{'Content-Type':'application/json; charset=utf-8','Access-Control-Allow-Origin':'*'});res.end(s)}
function body(req){return new Promise((resolve,reject)=>{let s='';req.on('data',c=>s+=c);req.on('end',()=>{try{resolve(JSON.parse(s||'{}'))}catch(e){reject(e)}})})}

function normPhone(v){return String(v||'').replace(/\D/g,'')}
function session(req){let m=(req.headers.cookie||'').match(/bs=([^;]+)/);return m?sessions.get(m[1]):null}
function setSession(res,phone){let t=crypto.randomBytes(16).toString('hex');sessions.set(t,phone);res.setHeader('Set-Cookie','bs='+t+'; Path=/; HttpOnly; Max-Age=2592000')}

function code(){return 'BS-'+Date.now().toString(36).toUpperCase()+'-'+crypto.randomBytes(2).toString('hex').toUpperCase()}
const server=http.createServer(async(req,res)=>{
 if(req.method==='OPTIONS'){res.writeHead(204,{'Access-Control-Allow-Origin':'*','Access-Control-Allow-Headers':'Content-Type'});return res.end()}
 const u=new URL(req.url,'http://localhost');

 if(u.pathname==='/api/login'&&req.method==='POST'){
  const b=await body(req); let phone=normPhone(b.phone);
  if(!phone||String(b.code)!=='123456')return json(res,400,{error:'کد ورود اشتباه است'});
  setSession(res,phone); return json(res,200,{ok:true});
 }
 if(u.pathname==='/api/me'&&req.method==='GET'){
  let phone=session(req); if(!phone)return json(res,401,{loggedIn:false});
  return json(res,200,{loggedIn:true,phone,orders:readOrders().filter(o=>normPhone(o.phone)===phone)});
 }

 if(u.pathname==='/api/products')return json(res,200,products);
 if(u.pathname==='/api/orders'&&req.method==='POST'){
  try{
   const b=await body(req),p=products.find(x=>x.id===Number(b.productId));
   if(!p)return json(res,404,{error:'بسته پیدا نشد'});
   if(!String(b.telegram||'').trim()||!String(b.phone||'').trim())return json(res,400,{error:'اطلاعات سفارش کامل نیست'});
   const o={code:code(),productId:p.id,stars:p.stars,telegram:String(b.telegram).replace(/^@/,''),phone:normPhone(b.phone),amount:p.price,status:'pending',createdAt:new Date().toISOString()};
   const all=readOrders();all.push(o);writeOrders(all);
   // Payment adapter: if PAYMENT_URL is configured, redirect to the real gateway endpoint.
   const paymentUrl=process.env.PAYMENT_URL ? process.env.PAYMENT_URL+'?order='+encodeURIComponent(o.code)+'&amount='+o.amount : '/payment.html?code='+encodeURIComponent(o.code);
   return json(res,200,{ok:true,code:o.code,paymentUrl});
  }catch(e){return json(res,400,{error:'درخواست نامعتبر'})}
 }
 if(u.pathname==='/api/orders'&&req.method==='GET'){
  const c=u.searchParams.get('code'),o=readOrders().find(x=>x.code===c);
  return o?json(res,200,o):json(res,404,{error:'سفارش پیدا نشد'});
 }

 if(u.pathname==='/api/pay'&&req.method==='POST'){
  try{
   const b=await body(req), orders=readOrders(), o=orders.find(x=>x.code===String(b.code||''));
   if(!o)return json(res,404,{error:'سفارش پیدا نشد'});
   if(o.status==='paid')return json(res,200,{ok:true,code:o.code,redirect:'/order.html?code='+encodeURIComponent(o.code)});
   o.status='paid';o.paidAt=new Date().toISOString();writeOrders(orders);
   return json(res,200,{ok:true,code:o.code,redirect:'/order.html?code='+encodeURIComponent(o.code)});
  }catch(e){return json(res,400,{error:'پرداخت نامعتبر است'})}
 }
 let file=u.pathname==='/'?'/index.html':u.pathname;
 if(file==='/order.html'){
  file='/order.html';
 }
 const fp=path.join(ROOT,path.normalize(file));
 if(!fp.startsWith(ROOT)||!fs.existsSync(fp))return json(res,404,{error:'Not found'});
 const ext=path.extname(fp),types={'.html':'text/html; charset=utf-8','.css':'text/css; charset=utf-8','.js':'application/javascript; charset=utf-8','.json':'application/json; charset=utf-8'};
 res.writeHead(200,{'Content-Type':types[ext]||'application/octet-stream'});fs.createReadStream(fp).pipe(res);
});
server.listen(PORT,()=>console.log(`Bright Star running: http://localhost:${PORT}`));
