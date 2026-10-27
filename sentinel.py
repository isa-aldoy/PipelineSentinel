"""GitHub Actions workflow security gate, offline static analysis."""
import argparse,json,re,sys
from pathlib import Path
import yaml
class Loader(yaml.SafeLoader): pass
Loader.yaml_implicit_resolvers={k:[(tag,regex) for tag,regex in v if tag!='tag:yaml.org,2002:bool'] for k,v in Loader.yaml_implicit_resolvers.items()}
def issue(rule,severity,path,detail):return dict(rule=rule,severity=severity,file=str(path),detail=detail)
def scan(path):
 try:doc=yaml.load(Path(path).read_text(encoding='utf8'),Loader=Loader)
 except (OSError,yaml.YAMLError) as e:return [issue('parse-error','high',path,str(e))]
 if not isinstance(doc,dict):return [issue('invalid-workflow','high',path,'Expected mapping')]
 out=[];perms=doc.get('permissions')
 if perms=='write-all':out.append(issue('write-all','high',path,'Global write-all'))
 if perms is None:out.append(issue('implicit-permissions','medium',path,'Specify minimal permissions'))
 trigger=doc.get('on',{})
 if isinstance(trigger,str):trigger={trigger:None}
 if isinstance(trigger,list):trigger=dict.fromkeys(trigger)
 privileged=isinstance(trigger,dict) and any(x in trigger for x in ('pull_request_target','workflow_run'))
 for jobname,job in (doc.get('jobs') or {}).items():
  if not isinstance(job,dict):continue
  if job.get('permissions')=='write-all':out.append(issue('write-all','high',path,jobname))
  for i,step in enumerate(job.get('steps') or [],1):
   if not isinstance(step,dict):continue
   where=f'{jobname}/step {i}';uses=step.get('uses','')
   if isinstance(uses,str) and uses and not uses.startswith('./') and not re.search(r'@[a-f0-9]{40}$',uses):
    out.append(issue('unpinned-action','medium',path,f'{where}: {uses}'))
   if privileged and isinstance(uses,str) and uses.startswith('actions/checkout') and 'pull_request.head' in str((step.get('with') or {}).get('ref','')):
    out.append(issue('untrusted-checkout','high',path,where))
   if privileged and re.search(r'\$\{\{\s*github\.event\.pull_request\.(title|body|head\.ref)',str(step.get('run',''))):
    out.append(issue('untrusted-expression','high',path,where))
   for k,v in (step.get('env') or {}).items():
    if re.search(r'(TOKEN|SECRET|PASSWORD|KEY)',str(k),re.I) and isinstance(v,str) and v and not v.strip().startswith('${{ secrets.'):
     out.append(issue('literal-credential','high',path,f'{where}: {k}'))
 return out
def main():
 p=argparse.ArgumentParser();p.add_argument('path');p.add_argument('--json',action='store_true');p.add_argument('--fail-on',choices=['none','high','medium'],default='high');a=p.parse_args()
 target=Path(a.path);files=[target] if target.is_file() else sorted([*target.rglob('*.yml'),*target.rglob('*.yaml')]) if target.is_dir() else []
 if not files:p.error('No workflow files')
 found=[v for f in files for v in scan(f)]
 if a.json:print(json.dumps(dict(files_scanned=len(files),findings=found),indent=2))
 else:print('\n'.join(f"{x['severity']} {x['rule']}: {x['detail']}" for x in found));print(f'{len(found)} findings')
 return int(a.fail_on!='none' and any({'high':2,'medium':1}[x['severity']] >= {'high':2,'medium':1}[a.fail_on] for x in found))
if __name__=='__main__':sys.exit(main())
