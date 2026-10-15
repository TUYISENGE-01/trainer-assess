import http from 'node:http';
import {DatabaseSync} from 'node:sqlite';
import {randomBytes,randomUUID,createHash,scrypt,timingSafeEqual} from 'node:crypto';
import {promisify} from 'node:util';
import {mkdirSync,readFileSync} from 'node:fs';
import {dirname,resolve} from 'node:path';
import {fileURLToPath} from 'node:url';
const derive=promisify(scrypt),root=dirname(fileURLToPath(import.meta.url));
const digest=s=>createHash('sha256').update(s).digest('hex');
const escape=s=>String(s??'').replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
const emailOK=e=>typeof e==='string'&&e.length<=254&&/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(e);
const empty=()=>({classes:[],questions:[],records:[],released:{}});
export function openStore(filename){
 mkdirSync(dirname(resolve(filename)),{recursive:true});
 const db=new DatabaseSync(filename,{timeout:5000});
 db.exec(`PRAGMA journal_mode=WAL;
 CREATE TABLE IF NOT EXISTS users(id TEXT PRIMARY KEY,email TEXT UNIQUE NOT NULL,role TEXT NOT NULL,password TEXT);
 CREATE TABLE IF NOT EXISTS sessions(token TEXT PRIMARY KEY,user_id TEXT NOT NULL,expires INTEGER NOT NULL);
 CREATE TABLE IF NOT EXISTS setup_tokens(token TEXT PRIMARY KEY,user_id TEXT NOT NULL,expires INTEGER NOT NULL);
 CREATE TABLE IF NOT EXISTS attempts(key TEXT PRIMARY KEY,count INTEGER NOT NULL,until INTEGER NOT NULL);
 CREATE TABLE IF NOT EXISTS workspaces(owner TEXT PRIMARY KEY,data TEXT NOT NULL,revision INTEGER NOT NULL);
 CREATE TABLE IF NOT EXISTS audit(id INTEGER PRIMARY KEY,time INTEGER NOT NULL,actor TEXT NOT NULL,action TEXT NOT NULL,target TEXT NOT NULL);
 PRAGMA user_version=1;`);
 return db;
}
async function hashPassword(p){const salt=randomBytes(16).toString('hex');return salt+':'+(await derive(p,salt,64,{N:32768,maxmem:64*1024*1024})).toString('hex')}
async function verifyPassword(p,stored){const [salt,key]=stored.split(':');const result=await derive(p,salt,64,{N:32768,maxmem:64*1024*1024});return timingSafeEqual(result,Buffer.from(key,'hex'))}
const norm=s=>String(s??'').normalize('NFKC').trim().replace(/\s+/g,' ').toLowerCase();
export function grade(q,a){if(['mcq','tf'].includes(q.type))return String(a)===String(q.correct)?q.max:0;if(q.type==='short')return q.accepted.some(v=>norm(v)===norm(a))?q.max:0;return null}
function validate(d){
 if(!d||!Array.isArray(d.classes)||!Array.isArray(d.questions)||!Array.isArray(d.records)||typeof d.released!=='object'||!d.released)throw Error('Invalid workspace');
 const unique=a=>new Set(a).size===a.length;
 if(!unique(d.classes.map(c=>c.id))||!unique(d.questions.map(q=>q.id)))throw Error('Duplicate IDs');
 for(const c of d.classes){
  if(typeof c.id!=='string'||c.owner!=='t1'||!c.name?.trim()||!Array.isArray(c.students)||!c.students.every(s=>typeof s==='string'&&s.trim())||!unique(c.students))throw Error('Invalid class');
  const en=c.enrollments||[];
  if(!Array.isArray(en)||!unique(en.map(x=>x.email))||!unique(en.map(x=>x.name))||en.some(x=>!emailOK(x.email)||!c.students.includes(x.name)))throw Error('Invalid student email links');
 }
 for(const q of d.questions){
  if(!d.classes.some(c=>c.id===q.classId)||typeof q.id!=='string'||!q.text?.trim()||!Number.isFinite(q.max)||q.max<=0||q.max>10000)throw Error('Invalid question');
  if(q.type==='mcq'&&(!Array.isArray(q.options)||q.options.length!==4||!q.options.every(x=>typeof x==='string'&&x.trim())||!['0','1','2','3'].includes(String(q.correct))))throw Error('Invalid multiple choice key');
  if(q.type==='tf'&&!['True','False'].includes(q.correct))throw Error('Invalid true/false key');
  if(q.type==='short'&&(!Array.isArray(q.accepted)||!q.accepted.length||!q.accepted.every(x=>typeof x==='string'&&x.trim())))throw Error('Invalid accepted answers');
  if(q.type&&!['mcq','tf','short','manual'].includes(q.type))throw Error('Unknown question type');
 }
 const keys=[];
 for(const r of d.records){let c=d.classes.find(c=>c.id===r.classId),q=d.questions.find(q=>q.id===r.qid&&q.classId===r.classId);if(!c||!q||!c.students.includes(r.student)||typeof r.answer!=='string'||(r.score!=null&&(!Number.isFinite(r.score)||r.score<0||r.score>q.max)))throw Error('Invalid response or score');keys.push(JSON.stringify([r.classId,r.qid,r.student]))}
 if(!unique(keys))throw Error('Duplicate responses');
}
function authPage(title,content){return `<!doctype html><html lang="en"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>${title} — TrainerAssess</title><style>body{margin:0;background:#122e3e;font:16px system-ui;color:#182d3b;display:grid;min-height:100vh;place-items:center}main{background:white;padding:36px;border-radius:15px;width:min(380px,80vw)}h1{font-size:28px}label{display:block;margin:18px 0 6px}input,button{box-sizing:border-box;width:100%;padding:12px;font:inherit;border:1px solid #b9cbd4;border-radius:7px}button{margin-top:24px;background:#087e8b;color:white;cursor:pointer}p{line-height:1.6}a{color:#087e8b}</style><main><h1>Trainer<span style="color:#087e8b">Assess</span></h1>${content}</main></html>`}
export function makeServer({db,origin,secure=true}){
 if(!origin||new URL(origin).origin!==origin)throw Error('Set APP_ORIGIN to the website origin, without a trailing slash');
 if(secure&&!origin.startsWith('https://'))throw Error('Production requires an HTTPS APP_ORIGIN');
 const query=(sql,...args)=>db.prepare(sql).get(...args),run=(sql,...args)=>db.prepare(sql).run(...args);
 const audit=(u,action,target)=>run('INSERT INTO audit(time,actor,action,target) VALUES(?,?,?,?)',Date.now(),u,action,target);
 const cookie=(name,value,age)=>`${name}=${value}; Path=/; HttpOnly; SameSite=Lax; Max-Age=${age}${secure?'; Secure':''}`;
 const issue=(id)=>{let token=randomBytes(32).toString('hex');run('DELETE FROM setup_tokens WHERE user_id=?',id);run('INSERT INTO setup_tokens VALUES(?,?,?)',digest(token),id,Date.now()+3600000);return origin+'/set-password?token='+token};
 const limited=(key,max)=>{let r=query('SELECT * FROM attempts WHERE key=?',key);if(r&&r.until>Date.now()&&r.count>=max)return true;run('INSERT INTO attempts VALUES(?,?,?) ON CONFLICT(key) DO UPDATE SET count=?,until=?',key,r&&r.until>Date.now()?r.count+1:1,r&&r.until>Date.now()?r.until:Date.now()+900000,r&&r.until>Date.now()?r.count+1:1,r&&r.until>Date.now()?r.until:Date.now()+900000);return false};
 const readWorkspace=id=>{let r=query('SELECT * FROM workspaces WHERE owner=?',id);return r?{data:JSON.parse(r.data),revision:r.revision}:{data:empty(),revision:0}};
 const writeWorkspace=(id,d,revision)=>{run('INSERT OR IGNORE INTO workspaces VALUES(?,?,0)',id,JSON.stringify(empty()));let r=run('UPDATE workspaces SET data=?,revision=revision+1 WHERE owner=? AND revision=?',JSON.stringify(d),id,revision);if(!r.changes)throw Object.assign(Error('Workspace changed on another device. Reload before editing.'),{status:409})};
 const server=http.createServer(async(req,res)=>{
  const send=(status,body,type='text/plain; charset=utf-8')=>{res.writeHead(status,{'Content-Type':type});res.end(body)};
  const json=(body,status=200)=>send(status,JSON.stringify(body),'application/json; charset=utf-8');
  const redirect=path=>{res.writeHead(303,{Location:path});res.end()};
  const page=(title,body)=>send(200,authPage(title,body),'text/html; charset=utf-8');
  try{
   res.setHeader('Cache-Control','no-store');res.setHeader('X-Content-Type-Options','nosniff');res.setHeader('X-Frame-Options','DENY');res.setHeader('Referrer-Policy','same-origin');
   if(secure)res.setHeader('Strict-Transport-Security','max-age=31536000');
   const url=new URL(req.url,origin),path=url.pathname,method=req.method;
   if(!['GET','POST','PUT'].includes(method))return send(405,'Method not allowed');
   if(['POST','PUT'].includes(method)&&req.headers.origin!==origin)return send(403,'Request origin rejected');
   const cookies=Object.fromEntries((req.headers.cookie||'').split(';').map(s=>s.trim().split('=')));
   let ses=cookies.ta_session?query('SELECT u.* FROM users u JOIN sessions s ON s.user_id=u.id WHERE s.token=? AND s.expires>?',digest(cookies.ta_session),Date.now()):null;
   const body=async()=>{let chunks=[],size=0;for await(const part of req){size+=part.length;if(size>1600000)throw Object.assign(Error('Request too large'),{status:413});chunks.push(part)}let s=Buffer.concat(chunks).toString();return req.headers['content-type']?.includes('application/json')?JSON.parse(s):Object.fromEntries(new URLSearchParams(s))};
   if(path==='/health')return json({ok:true});
   if(path==='/login'){
    if(method==='GET')return page('Sign in','<h2>School account sign-in</h2><form method="post"><label>Email</label><input name="email" type="email" autocomplete="username" required><label>Password</label><input name="password" type="password" autocomplete="current-password" required><button>Sign in</button></form><p>Need an account or forgot your password? Ask your school administrator for a one-time setup link.</p>');
    const b=await body(),email=String(b.email||'').trim().toLowerCase();
    if(limited('login:'+digest(email),10)||limited('ip:'+req.socket.remoteAddress,100))return send(429,'Too many attempts. Try again in 15 minutes.');
    let u=query('SELECT * FROM users WHERE email=?',email);
    // Perform scrypt even for unknown accounts to reduce account enumeration.
    const fake='00000000000000000000000000000000:'+('00'.repeat(64));
    const ok=typeof b.password==='string'&&b.password.length<=1024&&await verifyPassword(b.password,u?.password||fake);
    if(!u?.password||!ok)return send(401,'Email or password is incorrect. Return to sign in and try again.');
    const token=randomBytes(32).toString('hex');run('DELETE FROM sessions WHERE expires<?',Date.now());run('INSERT INTO sessions VALUES(?,?,?)',digest(token),u.id,Date.now()+8*3600000);res.setHeader('Set-Cookie',cookie('ta_session',token,8*3600));audit(u.id,'login',u.id);return redirect('/workspace');
   }
   if(path==='/set-password'){
    const token=url.searchParams.get('token')||'';
    const t=query('SELECT * FROM setup_tokens WHERE token=? AND expires>?',digest(token),Date.now());
    if(!t)return send(400,'This setup link is invalid or expired. Ask your administrator for a new link.');
    if(method==='GET')return page('Set password','<h2>Set your password</h2><form method="post"><label>New password (at least 12 characters)</label><input name="password" type="password" minlength="12" maxlength="1024" autocomplete="new-password" required><button>Save password</button></form>');
    const b=await body();if(typeof b.password!=='string'||b.password.length<12||b.password.length>1024)return send(400,'Use a password of 12–1024 characters.');
    const hash=await hashPassword(b.password);
    db.exec('BEGIN IMMEDIATE');try{
     if(!run('DELETE FROM setup_tokens WHERE token=? AND expires>?',digest(token),Date.now()).changes)throw Error('Link already used');
     run('UPDATE users SET password=? WHERE id=?',hash,t.user_id);run('DELETE FROM sessions WHERE user_id=?',t.user_id);db.exec('COMMIT');
    }catch(e){db.exec('ROLLBACK');throw e}
    audit(t.user_id,'password_changed',t.user_id);return redirect('/login');
   }
   if(!ses)return path.startsWith('/api/')?json({error:'Sign in required'},401):redirect('/login');
   if(path==='/logout'&&method==='POST'){run('DELETE FROM sessions WHERE token=?',digest(cookies.ta_session));res.setHeader('Set-Cookie',cookie('ta_session','',0));return json({ok:true})}
   if((path==='/'||path==='/workspace')&&method==='GET')return send(200,readFileSync(resolve(root,'public/workspace.html'),'utf8'),'text/html; charset=utf-8');
   const trainer=['admin','trainer'].includes(ses.role);
   if(path==='/api/account'&&method==='GET')return json({userId:ses.id,email:ses.email,displayName:ses.email,role:ses.role});
   if(path==='/api/account'&&method==='POST'){
    if(ses.role!=='admin')return send(403,'Administrator required');
    const b=await body(),email=String(b.email||'').trim().toLowerCase();
    if(!emailOK(email)||!['trainer','student'].includes(b.role))return send(400,'Valid email and role required');
    let u=query('SELECT * FROM users WHERE email=?',email);
    if(u?.role==='admin')return send(400,'Administrator accounts cannot be changed here');
    if(u){run('UPDATE users SET role=? WHERE id=?',b.role,u.id);run('DELETE FROM sessions WHERE user_id=?',u.id)}else{u={id:randomUUID()};run('INSERT INTO users(id,email,role) VALUES(?,?,?)',u.id,email,b.role)}
    audit(ses.id,'account_setup_link',u.id);return json({setupUrl:issue(u.id)});
   }
   if(path==='/api/workspace'){
    if(!trainer)return send(403,'Trainer required');
    if(method==='GET')return json(readWorkspace(ses.id));
    if(method==='PUT'){const b=await body();validate(b.data);if(!Number.isInteger(b.revision)||b.revision<0)return send(400,'Invalid revision');writeWorkspace(ses.id,b.data,b.revision);audit(ses.id,'workspace_saved',ses.id);return json({revision:b.revision+1})}
   }
   if(path==='/api/student'&&method==='GET'){
    const result=[];
    for(const row of db.prepare('SELECT * FROM workspaces').all()){
     const d=JSON.parse(row.data);
     for(const c of d.classes){const member=c.enrollments?.find(x=>x.email===ses.email);if(!member)continue;
      result.push({owner:row.owner,id:c.id,name:c.name,module:c.module,released:!!d.released[c.id],
       questions:d.questions.filter(q=>q.classId===c.id).map(q=>({id:q.id,text:q.text,type:q.type,max:q.max,options:q.options})),
       records:d.records.filter(r=>r.classId===c.id&&r.student===member.name).map(r=>({qid:r.qid,answer:r.answer,...(d.released[c.id]?{score:r.score,feedback:r.feedback}:{})}))});
     }
    }return json(result);
   }
   if(path==='/api/student'&&method==='POST'){
    const b=await body(),{data:d,revision}=readWorkspace(b.owner);
    const c=d.classes.find(c=>c.id===b.classId),member=c?.enrollments?.find(x=>x.email===ses.email);
    if(!member)return send(403,'You are not enrolled in this class');
    const qq=d.questions.filter(q=>q.classId===c.id);
    if(!qq.length||qq.some(q=>typeof b.answers?.[q.id]!=='string'||!b.answers[q.id].trim()||b.answers[q.id].length>20000))return send(400,'Answer all questions');
    if(d.records.some(r=>r.classId===c.id&&r.student===member.name))return send(409,'Already submitted. Contact your trainer.');
    const scores=qq.map(q=>{
     const a=b.answers[q.id];
     if(q.type==='mcq'&&!['0','1','2','3'].includes(a)||q.type==='tf'&&!['True','False'].includes(a))throw Error('Invalid choice');
     const score=grade(q,a);
     d.records.push({classId:c.id,student:member.name,qid:q.id,answer:a,mode:'Written',score,feedback:score==null?'Awaiting trainer review.':score===q.max?'Correct. Automatically marked.':'Automatically marked. Ask your trainer for review if needed.',marking:score==null?'Manual':'Automatic'});
     return {qid:q.id,score,max:q.max};
    });
    d.released[c.id]=false;writeWorkspace(b.owner,d,revision);audit(ses.id,'assessment_submitted',c.id);return json({scores});
   }
   send(404,'Page not found');
  }catch(e){console.error('Request failed:',e.message);if(!res.headersSent)send(e.status||400,e.status?e.message:'Unable to process request. Check the information and try again.');else res.end()}
 });
 return {server,issue};
}
if(process.argv[1]&&resolve(process.argv[1])===fileURLToPath(import.meta.url)){
 const db=openStore(process.env.DATA_FILE||resolve(root,'data/school.sqlite'));
 const origin=process.env.APP_ORIGIN||'http://localhost:3000',secure=process.env.NODE_ENV==='production';
 const {server,issue}=makeServer({db,origin,secure});
 if(process.argv[2]==='create-admin'){
  const email=process.argv[3]?.trim().toLowerCase();if(!emailOK(email))throw Error('Usage: node server.mjs create-admin your-email@example.com');
  if(db.prepare("SELECT id FROM users WHERE role='admin'").get())throw Error('An administrator already exists. Use reset-password instead.');
  const id=randomUUID();db.prepare('INSERT INTO users(id,email,role) VALUES(?,?,?)').run(id,email,'admin');console.log('Administrator setup link (private, expires in one hour):\n'+issue(id));db.close();
 }else if(process.argv[2]==='reset-password'){
  const u=db.prepare('SELECT id FROM users WHERE email=?').get((process.argv[3]||'').toLowerCase());if(!u)throw Error('Account not found');console.log('Private one-hour reset link:\n'+issue(u.id));db.close();
 }else if(process.argv[2]==='backup'){
  const target=process.argv[3];if(!target)throw Error('Provide a new absolute backup path');db.prepare('VACUUM INTO ?').run(resolve(target));console.log('Backup created');db.close();
 }else server.listen(Number(process.env.PORT)||3000,process.env.HOST||'127.0.0.1',()=>console.log('TrainerAssess listening at '+origin));
}
