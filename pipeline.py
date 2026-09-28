#!/usr/bin/env python3
"""Validated DNS blocklist publisher. GPL-3.0. Upstream data is never executed."""
import argparse, concurrent.futures, datetime as dt, gzip, hashlib, html, ipaddress, json, os, re, shutil, sys, tempfile, time, unittest, urllib.error, urllib.parse, urllib.request
from pathlib import Path
ROOT = Path(__file__).resolve().parent
CATS = ['gambling','anti-bypass','new-domains','dynamic-dns','abused-tlds','shorteners','suspicious-domains']
LABEL = re.compile(r'[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\Z')
RULE = re.compile(r'\|\|([a-z0-9.-]+)\^\Z')
VERSION = '1.0.0'
def utc(): return dt.datetime.now(dt.timezone.utc).isoformat().replace('+00:00','Z')
def sha(b): return hashlib.sha256(b).hexdigest()
def dump(p,obj): p.parent.mkdir(parents=True,exist_ok=True); p.write_text(json.dumps(obj,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
def fetch(url,limit=190_000_000):
    if urllib.parse.urlsplit(url).scheme!='https': raise ValueError('HTTPS required')
    last=None
    for attempt in range(3):
        try:
            req=urllib.request.Request(url,headers={'User-Agent':'DNS-Blocklists/1.0 (+https://github.com/Leonne9/dns-blocklists)','Accept':'text/plain,application/json,application/octet-stream'})
            with urllib.request.urlopen(req,timeout=90) as r:
                if r.status!=200 or not r.url.startswith('https://'): raise ValueError('Invalid HTTP response')
                if int(r.headers.get('Content-Length',0))>limit: raise ValueError('Response too large')
                b=r.read(limit+1)
                if len(b)>limit or not b: raise ValueError('Empty or oversized response')
                return b,dict(r.headers.items())
        except (OSError,ValueError) as e:
            last=e
            if attempt<2: time.sleep(2**attempt)
    raise RuntimeError(str(last))
def domain(value,allow_tld=False):
    value=value.strip().lower().rstrip('.')
    if not value or any(c in value for c in ' /\\:@#$?^|*<>"\t\r\n'): raise ValueError('Invalid characters')
    try: value=value.encode('idna').decode('ascii') if not value.isascii() else value
    except UnicodeError: raise ValueError('Invalid IDN')
    labels=value.split('.')
    if len(value)>253 or (len(labels)<2 and not allow_tld) or not all(LABEL.fullmatch(x) for x in labels): raise ValueError('Invalid domain')
    if labels[-1].isdigit() or value=='localhost' or value.endswith(('.localhost','.local','.invalid','.test')): raise ValueError('Not public DNS')
    for x in labels:
        if x.startswith('xn--'):
            try:
                if x.encode().decode('idna').encode('idna').decode()!=x: raise ValueError('IDN roundtrip')
            except UnicodeError: raise ValueError('Invalid punycode')
    return value

def parse_line(line,fmt='auto',allow_tld=False):
    line=line.strip().lstrip('\ufeff')
    if not line or line.startswith(('#','!',';')) or line in ('[Adblock Plus]','[Adblock Plus 2.0]'): return []
    line=line.split('#',1)[0].strip()
    if not line: return []
    if line.startswith('||'):
        if not line.endswith('^') or any(x in line for x in '$@*'): raise ValueError('Unsupported AdGuard rule')
        return [domain(line[2:-1],allow_tld)]
    if line.startswith(('address=/','server=/')):
        parts=line.split('/')
        if len(parts)!=3 or parts[-1] not in ('','0.0.0.0','127.0.0.1','::'): raise ValueError('Unsupported DNS rule')
        return [domain(parts[1],allow_tld)]
    fields=line.split()
    if fields[0] in ('0.0.0.0','127.0.0.1','::','::1'):
        if len(fields)<2: raise ValueError('Empty hosts record')
        return [domain(x,allow_tld) for x in fields[1:]]
    if len(fields)!=1: raise ValueError('Unexpected whitespace')
    if fmt in ('domains','auto') and line.startswith(('http://','https://')):
        u=urllib.parse.urlsplit(line)
        if u.username or u.password or not u.hostname: raise ValueError('Invalid URL')
        line=u.hostname
    elif fmt in ('domains','auto') and '/' in line: line=line.split('/',1)[0]
    return [domain(line,allow_tld)]

def parse(data,source):
    text=data.decode('utf-8-sig',errors='strict')
    if '\x00' in text or re.search(r'<\s*(?:!doctype|html|script|body|head)\b',text[:20000],re.I): raise ValueError('HTML or binary instead of list')
    values=set(); raw=valid=invalid=ignored=0
    for line in text.splitlines():
        try:
            ds=parse_line(line,source.get('format','auto'),source.get('allow_tld',False))
            if not ds: ignored+=1; continue
            raw+=len(ds); valid+=len(ds); values.update(ds)
        except ValueError: raw+=1; invalid+=1
    if not values or invalid>max(20,raw*.01): raise ValueError('Empty or corrupt source')
    stats={'raw_entries':raw,'valid_entries':valid,'invalid_entries':invalid,'ignored_lines':ignored,'unique_entries':len(values),'duplicates':valid-len(values)}
    dates=re.findall(r'(?im)^[!#]\s*(?:Last modified|Last updated|Date)\s*:\s*(.+)$',text[:20000])
    stats['last_update_known']=dates[0] if dates else None
    return values,stats

def safety(ds,cfg):
    protected=cfg.get('protected_domains',[]); sub=cfg.get('protected_subtrees',[])
    # Exclude a rule that would block the publisher, AdGuard, or broad critical roots.
    bad={d for d in ds if any(p==d or p.endswith('.'+d) for p in protected) or any(d.endswith('.'+p) for p in sub)}
    return ds-bad,len(bad)

def reduce_parents(ds):
    keep=set()
    for d in ds:
        labels=d.split('.')
        if not any('.'.join(labels[i:]) in ds for i in range(1,len(labels))): keep.add(d)
    return keep

def check_anomaly(count,source,previous=None):
    if not source['min_entries']<=count<=source['max_entries']: raise ValueError('Source absolute count anomaly')
    if previous and (count<previous*.60 or count>previous*3): raise ValueError('Source relative count anomaly')

def source_load(source,cfg,old):
    cid=source['id']; cached=ROOT/'.cache'/f'{cid}.gz'; meta=cached.with_suffix('.json'); cached.parent.mkdir(exist_ok=True)
    prior=next((x for x in old.get('sources',[]) if x['id']==cid and x.get('cache')),None)
    if not cached.exists() and prior:
        try:
            b,_=fetch(cfg['site_url']+'/'+prior['cache']['path'],70_000_000)
            if sha(b)!=prior['cache']['sha256']: raise ValueError('Cache integrity')
            cached.write_bytes(b);dump(meta,prior)
        except Exception: pass
    prev=json.loads(meta.read_text()) if cached.exists() and meta.exists() else None
    try:
        b,headers=fetch(source['url'],source['max_bytes'])
        if 'html' in headers.get('Content-Type','').lower(): raise ValueError('HTML Content-Type')
        ds,stats=parse(b,source)
        check_anomaly(len(ds),source,prev.get('unique_entries') if prev else None)
        report={**source,**stats,'status':'ok','fetched_at':utc(),'upstream_last_modified':headers.get('Last-Modified'),'upstream_sha256':sha(b),'upstream_bytes':len(b),'error':None}
        payload=gzip.compress(('\n'.join(sorted(ds))+'\n').encode(),mtime=0)
        temp=cached.with_suffix('.tmp');temp.write_bytes(payload);temp.replace(cached);dump(meta,report)
    except Exception as e:
        if not prev or not cached.exists(): return None,{**source,'status':'unavailable','error':str(e),'unique_entries':0}
        with gzip.open(cached,'rt',encoding='utf-8') as f: ds={domain(x,source.get('allow_tld',False)) for x in f}
        if len(ds)!=prev['unique_entries']: raise ValueError('Cached count mismatch')
        report={**prev,**source,'status':'stale','error':str(e),'last_attempt_at':utc()}
    print(cid,report['status'],len(ds),flush=True)
    return ds,report

def split_rules(rules,limit,header):
    prefix=header.encode(); current=bytearray(prefix); count=0
    if len(prefix)>=limit: raise ValueError('Header too large')
    for rule in rules:
        b=(rule+'\n').encode()
        if len(prefix)+len(b)>limit: raise ValueError('Rule exceeds part size')
        if len(current)+len(b)>limit:
            yield bytes(current),count
            current=bytearray(prefix);count=0
        current.extend(b);count+=1
    if count: yield bytes(current),count

def metadata(p,base,category,count,master=False):
    b=p.read_bytes();return {'path':'lists/'+p.name,'url':base+'/lists/'+p.name,'category':category,'rules':count,'bytes':len(b),'sha256':sha(b),'master':master}

def validate(out,manifest,cfg):
    for cat in CATS:
        files=[x for x in manifest['files'] if x['category']==cat and not x['master']]
        if not files: raise ValueError('Missing category '+cat)
        seen=set()
        for m in files:
            p=out/m['path'];b=p.read_bytes()
            if not b or len(b)>=cfg['hard_limit_bytes'] or len(b)>cfg['max_part_bytes'] or sha(b)!=m['sha256'] or len(b)!=m['bytes']: raise ValueError('Size/hash violation '+p.name)
            rules=[line for line in b.decode('utf-8').splitlines() if line and not line.startswith('!')]
            if len(rules)!=m['rules']: raise ValueError('Rule count mismatch')
            for line in rules:
                match=RULE.fullmatch(line)
                if not match or domain(match[1],cat=='abused-tlds')!=match[1] or line in seen: raise ValueError('Invalid/duplicate rule')
                seen.add(line)
        if len(seen)!=manifest['categories'][cat]['rules']: raise ValueError('Incomplete category')
        if cat=='gambling':
            b=(out/'lists/gambling-master.txt').read_bytes()
            master={x for x in b.decode().splitlines() if x and not x.startswith('!')}
            if master!=seen: raise ValueError('Master mismatch')
    if sum(p.stat().st_size for p in out.rglob('*') if p.is_file())>900_000_000: raise ValueError('Pages size safety limit')

def build():
    cfg=json.loads((ROOT/'sources.json').read_text());base=cfg['site_url'].rstrip('/')
    old={}
    try: old=json.loads(fetch(base+'/lists/manifest.json',3_000_000)[0])
    except Exception: pass
    if old: dump(ROOT/'.cache/previous-manifest.json',old)
    out=ROOT/'.staging';shutil.rmtree(out,ignore_errors=True);(out/'lists').mkdir(parents=True);(out/'cache').mkdir()
    stamp=utc();build_id=stamp.replace(':','').replace('-','')
    buckets={c:set() for c in CATS};reports=[]
    for s in cfg['sources']:
        if not s['enabled']: continue
        ds,r=source_load(s,cfg,old)
        if ds is not None:
            clean,excluded=safety(ds,cfg);r['safety_excluded']=excluded;buckets[s['category']].update(clean)
            cp=ROOT/'.cache'/f"{s['id']}.gz";shutil.copy2(cp,out/'cache'/cp.name)
            r['cache']={'path':'cache/'+cp.name,'sha256':sha(cp.read_bytes()),'bytes':cp.stat().st_size}
        reports.append(r)
    if len([s for s in reports if s['category']=='gambling' and s['status']!='unavailable'])<2: raise ValueError('Fewer than two gambling sources')
    for c in CATS:
        if not buckets[c]: raise ValueError('Missing initial category '+c)
    manifest={'version':VERSION,'build_id':build_id,'timestamp_utc':stamp,'next_update_expected':(dt.datetime.now(dt.timezone.utc)+dt.timedelta(hours=cfg['interval_hours'])).isoformat(),'frequency_hours':cfg['interval_hours'],'status':'degraded' if any(s['status']!='ok' for s in reports) else 'ok','sources':reports,'unavailable_sources':[s['id'] for s in reports if s['status']!='ok'],'categories':{},'files':[],'source_url':'https://github.com/Leonne9/dns-blocklists','licenses':['LICENSE','LICENSE-BLP.txt','LICENSE-StevenBlack.txt','LICENSE-hostsVN.txt']}
    global_unique=set().union(*buckets.values())
    total_valid=sum(s.get('valid_entries',0) for s in reports);raw=sum(s.get('raw_entries',0) for s in reports);excluded=sum(s.get('safety_excluded',0) for s in reports)
    manifest.update(raw_entries=raw,valid_entries=total_valid,invalid_entries=sum(s.get('invalid_entries',0) for s in reports),unique_entries=len(global_unique),duplicates_removed=total_valid-excluded-len(global_unique),safety_excluded=excluded)
    del global_unique
    for cat,ds in buckets.items():
        reduced=reduce_parents(ds);header=f'! DNS Blocklists | {cat}\n! Build: {build_id}\n! Updated: {stamp}\n! Expires: 6 hours\n! License: GPL-3.0; see sources.json and LICENSE files\n! Sources and notices: {base}/lists/manifest.json\n'
        rules=['||'+d+'^' for d in sorted(reduced)]
        previous_cat=old.get('categories',{}).get(cat,{})
        if previous_cat and len(rules)<previous_cat['rules']*.75: raise ValueError('Category collapse: '+cat)
        added=removed=None
        if previous_cat:
            try:
                prev=set()
                for f in old['files']:
                    if f['category']==cat and not f['master']:
                        b,_=fetch(f['url'],cfg['hard_limit_bytes'])
                        if sha(b)!=f['sha256']: raise ValueError('Previous file changed')
                        prev.update(x for x in b.decode().splitlines() if x.startswith('||'))
                current=set(rules);added=len(current-prev);removed=len(prev-current)
            except Exception: pass
        else: added=len(rules);removed=0
        manifest['categories'][cat]={'rules':len(rules),'unique_domains_before_parent_reduction':len(ds),'covered_subdomains_removed':len(ds)-len(reduced),'new_entries':added,'removed_entries':removed,'files':0}
        for i,(b,n) in enumerate(split_rules(rules,cfg['max_part_bytes'],header),1):
            p=out/'lists'/f'{cat}-{i:02}.txt';p.write_bytes(b);manifest['files'].append(metadata(p,base,cat,n));manifest['categories'][cat]['files']+=1
        if cat=='gambling':
            p=out/'lists/gambling-master.txt';p.write_text(header+'\n'.join(rules)+'\n');manifest['files'].append(metadata(p,base,cat,len(rules),True))
    manifest['file_count']=len(manifest['files']);manifest['adguard_file_count']=sum(not f['master'] for f in manifest['files']);manifest['largest_adguard_file_bytes']=max(f['bytes'] for f in manifest['files'] if not f['master'])
    manifest['unique_rules_per_layer_total']=sum(c['rules'] for c in manifest['categories'].values())
    for name in ['sources.json','LICENSE','LICENSE-BLP.txt','LICENSE-StevenBlack.txt','LICENSE-hostsVN.txt','README.md','pipeline.py']:
        if (ROOT/name).exists():shutil.copy2(ROOT/name,out/name)
    validate(out,manifest,cfg);manifest['local_validation']={'result':'passed','checked_files':manifest['file_count'],'checks':['UTF-8','strict DNS rules','no HTML','no duplicates within category','byte limit','SHA-256','complete categories','master equality','source anomalies']}
    dump(out/'lists/manifest.json',manifest);(out/'.nojekyll').touch();render_status(out,manifest)
    dump(out/'LAST_KNOWN_GOOD_BUILD.json',{'build_id':build_id,'timestamp_utc':stamp,'validation':'passed before deployment; production verification is separate'})
    dump(ROOT/'.cache/build-summary.json',manifest)
    dest=ROOT/'_site';backup=ROOT/'.previous-site';shutil.rmtree(backup,ignore_errors=True)
    if dest.exists():dest.rename(backup)
    out.rename(dest)
    print(json.dumps({k:manifest[k] for k in ['build_id','raw_entries','unique_entries','duplicates_removed','adguard_file_count','largest_adguard_file_bytes']},indent=2))
    return manifest

def render_status(out,m):
    def esc(x):return html.escape(str(x))
    rows=[('Status geral',m['status']),('Última atualização UTC',m['timestamp_utc']),('Próxima atualização prevista',m['next_update_expected']),('Fontes',len(m['sources'])),('Fontes funcionando',sum(s['status']=='ok' for s in m['sources'])),('Fontes com erro',len(m['unavailable_sources'])),('Entradas brutas',m['raw_entries']),('Entradas únicas antes da redução de subdomínios',m['unique_entries']),('Duplicatas removidas globalmente',m['duplicates_removed']),('Maior arquivo AdGuard (bytes)',m['largest_adguard_file_bytes']),('Versão',m['build_id'])]
    for c,s in m['categories'].items():rows += [(c+' — regras',s['rules']),(c+' — arquivos',s['files']),(c+' — novas / removidas',str(s['new_entries'])+' / '+str(s['removed_entries']))]
    body=''.join('<tr><th>'+esc(k)+'</th><td>'+esc(v)+'</td></tr>' for k,v in rows)
    links=''
    for c in CATS:
        links+='<h2>'+esc(c)+'</h2>'
        if c!='gambling':links+='<p>Opcional e agressiva: pode bloquear serviços legítimos.</p>'
        for f in m['files']:
            if f['category']==c and not f['master']:links+='<p><a href="'+esc(f['url'])+'">'+esc(f['url'])+'</a> — '+str(f['rules'])+' regras; '+str(f['bytes'])+' bytes</p>'
    sources=''.join('<tr><td>'+esc(s['name'])+'</td><td>'+esc(s['status'])+'</td><td>'+esc(s.get('unique_entries',0))+'</td><td>'+esc(s.get('last_update_known'))+'</td><td>'+esc(s.get('error') or '')+'</td></tr>' for s in m['sources'])
    page='<!doctype html><html lang="pt-BR"><meta charset="utf-8"><meta name="viewport" content="width=device-width"><title>DNS Blocklists — Status</title><style>body{max-width:1100px;margin:40px auto;padding:20px;font:16px system-ui;background:#f5f7fa;color:#142638}table{border-collapse:collapse}td,th{padding:9px;text-align:left;border-bottom:1px solid #ccd3dc}a{overflow-wrap:anywhere}h2{margin-top:32px}</style><h1>DNS Blocklists</h1><p>Publicação de listas. Este serviço não recebe consultas DNS nem registra sua navegação. Sem analytics.</p><p>Cadastre todos os arquivos gambling numerados. A master é somente para auditoria. Não há garantia de cobertura total. A atualização no AdGuard depende do serviço e da configuração da sua conta.</p><table>'+body+'</table><h2>Fontes</h2><table>'+sources+'</table><p><a href="'+esc(m['sources'][0].get('project',''))+'">Projeto upstream principal</a> · <a href="'+esc(m['source_url'])+'">Código e documentação</a> · <a href="'+esc(json.loads((ROOT/'sources.json').read_text())['site_url'])+'/lists/manifest.json">Manifesto JSON</a></p>'+links+'<p>Agendamento previsto a cada 6 horas; o provedor pode atrasar execuções. Consulte o histórico Actions para falhas após o último build publicado. Ativação de listas opcionais não impede todo bypass por IP/VPN.</p></html>'
    (out/'status').mkdir(exist_ok=True);(out/'status/index.html').write_text(page,encoding='utf-8');(out/'index.html').write_text(page,encoding='utf-8')

def verify(base,expected=None):
    m=json.loads(fetch(base.rstrip('/')+'/lists/manifest.json',3_000_000)[0])
    if expected and m['build_id']!=expected: raise ValueError('Public manifest is not the expected build')
    results=[]
    def one(f):
        b,h=fetch(f['url'],190_000_000);typ=h.get('Content-Type','').split(';')[0].lower()
        if typ not in ('text/plain','application/octet-stream'): raise ValueError('Wrong Content-Type '+str(typ))
        if len(b)!=f['bytes'] or sha(b)!=f['sha256']:raise ValueError('Wrong bytes/hash '+f['path'])
        if not f['master'] and len(b)>=4_500_000:raise ValueError('File >=4.5MB')
        lines=[x for x in b.decode('utf-8').splitlines() if x and not x.startswith('!')]
        if len(lines)!=f['rules'] or len(lines)!=len(set(lines)) or not all(RULE.fullmatch(x) for x in lines):raise ValueError('Public content invalid')
        return {'url':f['url'],'http_status':200,'https_certificate_verified':True,'authentication':False,'cookies_sent':False,'content_type':typ,'bytes':len(b),'sha256':sha(b),'rules':len(lines),'result':'passed'}
    with concurrent.futures.ThreadPoolExecutor(max_workers=4) as pool:results=list(pool.map(one,m['files']))
    for route in ('/','/status/','/sources.json','/LICENSE'):
        b,_=fetch(base.rstrip('/')+route,5_000_000)
        if not b:raise ValueError('Empty endpoint')
    report={'verified_at':utc(),'build_id':m['build_id'],'result':'passed','files':results}
    dump(ROOT/'PRODUCTION_TESTS.json',report);print('Verified',len(results),'public files',flush=True);return report

def checkpoint():
    m=json.loads((ROOT/'_site/lists/manifest.json').read_text());r=json.loads((ROOT/'PRODUCTION_TESTS.json').read_text())
    if m['build_id']!=r['build_id']:raise ValueError('Verification/build mismatch')
    s={'project_version':VERSION,'last_checkpoint':utc(),'current_stage':'published_and_verified','completed_stages':['sources','normalization','deduplication','size_splitting','validation','scheduled_workflow','deployment','public_http_tests','documentation'],'pending_stages':[],'sources_configured':len(m['sources']),'sources_working':sum(x['status']=='ok' for x in m['sources']),'unique_rules':m['unique_entries'],'generated_files':m['file_count'],'deployment_status':'verified','last_successful_build':m['build_id'],'LAST_KNOWN_GOOD_BUILD':m['build_id'],'next_action':'Check the last Actions run and public manifest; do not recreate infrastructure.'}
    dump(ROOT/'state.json',s);dump(ROOT/'LAST_KNOWN_GOOD_BUILD.json',{'build_id':m['build_id'],'verified_at':r['verified_at']})
    (ROOT/'PROJECT_STATUS.md').write_text('# STATUS DO PROJETO\n\nÚltima atualização: '+s['last_checkpoint']+'\nEtapa atual: publicado e verificado\nPercentual aproximado concluído: 100% da infraestrutura; ativação no AdGuard é separada.\n\nCONCLUÍDO: fontes, pipeline, testes, automação, publicação e testes HTTPS.\nEM EXECUÇÃO: atualizações agendadas.\nPENDENTE: cadastrar URLs no AdGuard e conferir limite de listas/regras da conta.\nPROBLEMAS: '+str(m['unavailable_sources'])+'\nDECISÕES: GitHub Pages e Actions públicos; sem serviços pagos.\nSERVIÇOS: GitHub.\nLAST_KNOWN_GOOD_BUILD: '+m['build_id']+'\nNEXT_ACTION: verificar último Actions, state.json e manifesto; continuar sem recriar projeto.\n')

class Tests(unittest.TestCase):
    def test_normalize(self):
        self.assertEqual(parse_line(' 0.0.0.0 EXAMPLE.ORG # comment'),['example.org'])
        self.assertEqual(parse_line('https://ExAmPle.org/a','domains'),['example.org'])
        self.assertEqual(domain('café.org'),'xn--caf-dma.org')
        self.assertEqual(parse_line('||example.org^'),['example.org'])
    def test_injection(self):
        for x in ['<script>alert(1)</script>','||com^','@@||example.org^','||example.org^$redirect=noopjs','a..org','-a.org','127.0.0.1','xn--.org','a.org;rm','example.org && echo']:
            with self.subTest(x=x),self.assertRaises(ValueError):parse_line(x)
    def test_html_empty(self):
        for b in [b'',b'<html>error</html>',b'! comments only']:
            with self.assertRaises(ValueError):parse(b,{})
    def test_duplicate_parent(self):
        ds,st=parse(b'||example.org^\n||example.org^\n||a.example.org^',{})
        self.assertEqual(st['duplicates'],1);self.assertEqual(reduce_parents(ds),{'example.org'})
    def test_split_lossless(self):
        rules=['||a'+str(i)+'.example.org^' for i in range(100)]
        parts=list(split_rules(rules,150,'! test\n'))
        self.assertTrue(all(len(b)<=150 for b,n in parts));self.assertEqual(sum(n for b,n in parts),100)
        self.assertEqual([x for b,n in parts for x in b.decode().splitlines() if not x.startswith('!')],rules)
    def test_anomaly(self):
        s={'min_entries':100,'max_entries':100000}
        for n in [0,120,99999,100001]:
            with self.assertRaises(ValueError):check_anomaly(n,s,1000)
    def test_upstream_failure_preserves_cache(self):
        from unittest.mock import patch
        source={'id':'fixture','url':'https://upstream.example/list','format':'adguard','category':'gambling','max_bytes':1000,'min_entries':1,'max_entries':100}
        cfg={'site_url':'https://publisher.example'}
        with tempfile.TemporaryDirectory() as td, patch.dict(globals(),ROOT=Path(td)):
            with patch(__name__+'.fetch',return_value=(b'||example.org^\n',{})):
                values,report=source_load(source,cfg,{})
                self.assertEqual(report['status'],'ok')
            for failure in [RuntimeError('HTTP 404'),RuntimeError('timeout')]:
                with patch(__name__+'.fetch',side_effect=failure):
                    old,status=source_load(source,cfg,{})
                    self.assertEqual(old,values);self.assertEqual(status['status'],'stale')
            with patch(__name__+'.fetch',return_value=(b'<html>broken</html>',{})):
                old,status=source_load(source,cfg,{})
                self.assertEqual(old,values);self.assertEqual(status['status'],'stale')
    def test_generation_rejects_missing_or_oversize(self):
        with tempfile.TemporaryDirectory() as td:
            out=Path(td);(out/'lists').mkdir();p=out/'lists/gambling-01.txt';p.write_text('||example.org^\n')
            f=metadata(p,'https://publisher.example','gambling',1)
            m={'files':[f],'categories':{'gambling':{'rules':1}}}
            with self.assertRaises(ValueError):validate(out,m,{'hard_limit_bytes':10,'max_part_bytes':9})
            with self.assertRaises((ValueError,FileNotFoundError)):validate(out,m,{'hard_limit_bytes':100,'max_part_bytes':90})
    def test_tld_protection(self):
        self.assertEqual(domain('casino',True),'casino')
        self.assertEqual(safety({'com','adguard-dns.com','x.adguard-dns.com','bad.example.org'},{'protected_domains':['com','adguard-dns.com'],'protected_subtrees':['adguard-dns.com']})[0],{'bad.example.org'})

if __name__=='__main__':
    a=argparse.ArgumentParser();a.add_argument('command',choices=['build','test','verify','checkpoint']);a.add_argument('--base');a.add_argument('--expected');args=a.parse_args()
    if args.command=='test':unittest.main(argv=[sys.argv[0]])
    elif args.command=='build':build()
    elif args.command=='verify':verify(args.base or json.loads((ROOT/'sources.json').read_text())['site_url'],args.expected)
    elif args.command=='checkpoint':checkpoint()
