from __future__ import annotations
import hashlib, json, re, xml.etree.ElementTree as ET
from dataclasses import dataclass
from datetime import datetime, timezone, timedelta
from typing import Any, Iterable
UTC8 = timezone(timedelta(hours=8), name="UTC+08:00")
TIMESTAMP_PATTERNS = [re.compile(r"(?P<ts>\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?)"), re.compile(r"(?P<ts>\d{2}/\d{2}/\d{4}[ T]\d{2}:\d{2}:\d{2}(?:\.\d+)?)"), re.compile(r"(?P<ts>\w{3}\s+\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}\s+\d{4})")]
@dataclass
class Event:
 timestamp:str; source_file:str; source_type:str; location:str; event_id:str=""; level:str="INFO"; provider:str=""; host:str=""; user:str=""; process:str=""; message:str=""; raw:str=""; sha256:str=""
@dataclass
class Finding:
 severity:str; title:str; rationale:str; evidence:str; source_file:str; location:str; timestamp:str; rule_id:str
RULES = [
("WIN-POWERSHELL-ENC","HIGH","Encoded or obfuscated PowerShell",r"(?i)(-enc(?:odedcommand)?\s+[A-Za-z0-9+/]{20,}={0,2}|frombase64string|\[convert\]::frombase64string)","Encoded/decoded command content can hide execution intent; inspect decoded command and parent process."),
("WIN-POWERSHELL-BYPASS","MEDIUM","PowerShell policy or profile bypass",r"(?i)(-executionpolicy\s+bypass|-ep\s+bypass|-nop(?:rofile)?\b|-w(?:indowstyle)?\s+hidden)","These options are sometimes legitimate administration but are also used to reduce visibility."),
("WEB-SHELL-CHILDPROC","CRITICAL","Web server spawned a command interpreter",r"(?i)(php-cgi\.exe|w3wp\.exe|httpd\.exe|apache\w*|nginx)\S?.{0,180}(cmd\.exe|powershell(?:\.exe)?|pwsh\.exe|wscript\.exe|cscript\.exe)","A web service process associated with a command interpreter is a high-value command-execution lead."),
("WEB-SHELL-PATH","HIGH","Possible web shell or executable upload path",r"(?i)(\\wwwroot\\|/htdocs/|/public_html/|/storage/app/|\\uploads?\\|/uploads?/).{0,160}\.(php|phtml|asp|aspx|jsp)\b","A script under a web-accessible or upload-related path merits file and access-log corroboration."),
("CRED-ENV-ACCESS","HIGH","Application environment or secret file access",r"(?i)(\.env\b|appsettings\.json|web\.config|credentials\.json|id_rsa|shadow\b).{0,140}(get-content|type\s+|cat\s+|readalltext|copy-item|curl|invoke-webrequest)?|(?:get-content|readalltext|cat\s+).{0,140}(\.env\b|appsettings\.json|web\.config)","Access to configuration or credential files can expose secrets; verify exact operation and outcome."),
("DISCOVERY-ACCOUNT","MEDIUM","Account or privilege discovery command",r"(?i)(net\s+(user|localgroup|group)|whoami\s+/all|Get-LocalGroupMember|Get-ADUser|dsquery)","Account and group enumeration may be administration or post-compromise discovery."),
("DISCOVERY-NETWORK","MEDIUM","Network discovery or connection enumeration",r"(?i)(netstat\s+-ano|arp\s+-a|ipconfig\s+/all|route\s+print|Get-NetTCPConnection|Test-NetConnection)","Network enumeration is a useful pivot when aligned with a suspicious process or account."),
("PERSIST-SERVICE","HIGH","Service or scheduled-task persistence command",r"(?i)(sc\.exe\s+create|New-Service\b|schtasks\s+/create|Register-ScheduledTask|systemctl\s+enable)","Creation or modification of services/tasks may establish persistence; inspect context."),
("DEFENSE-EVASION","HIGH","Potential security-control tampering",r"(?i)(Set-MpPreference.{0,100}DisableRealtimeMonitoring|Add-MpPreference.{0,100}Exclusion|wevtutil\s+cl|Clear-EventLog|auditpol\s+/clear)","These commands can weaken protection or erase logs; confirm success and authorization."),
("AUTH-BRUTEFORCE","MEDIUM","Authentication failure indicator",r"(?i)(failed password|logon failure|authentication failed|invalid credentials|event.?id[=: ]+4625)","A single event is not proof of brute force; group by account/source and calculate frequency."),
("UPLOAD-SCRIPT","HIGH","Script upload or write operation indicator",r"(?i)(writeallbytes|frombase64string|move_uploaded_file|file_put_contents|\.php.{0,100}(upload|write|created|saved)|(?:upload|write|created|saved).{0,100}\.php)","Correlate with web access logs and filesystem evidence to determine whether a script was placed or executed.")]
RULES=[(a,b,c,re.compile(d),e) for a,b,c,d,e in RULES]
def sha256(data:bytes)->str:return hashlib.sha256(data).hexdigest()
def normalize_time(value:Any)->str:
 if value is None or str(value).strip()=="":return ""
 text=str(value).strip()
 try: dt=datetime.fromisoformat(text.replace("Z","+00:00"))
 except ValueError:
  dt=None
  for fmt in ("%m/%d/%Y %H:%M:%S","%Y/%m/%d %H:%M:%S","%b %d %H:%M:%S %Y"):
   try:dt=datetime.strptime(text,fmt);break
   except ValueError:pass
  if dt is None:return text
 if dt.tzinfo is None:dt=dt.replace(tzinfo=UTC8)
 return dt.astimezone(UTC8).isoformat(timespec="seconds")
def sniff_timestamp(text:str)->str:
 for p in TIMESTAMP_PATTERNS:
  m=p.search(text)
  if m:
   n=normalize_time(m.group("ts"))
   if n:return n
 return ""
def local_name(tag:str)->str:return tag.rsplit("}",1)[-1] if "}" in tag else tag
def xml_event_to_event(node:ET.Element,filename:str,digest:str,index:int)->Event:
 flat={}
 for child in node.iter():
  name=local_name(child.tag)
  if child.text and child.text.strip():flat.setdefault(name,child.text.strip())
  for k,v in child.attrib.items():flat.setdefault(k,v)
 ts=next((v for k,v in flat.items() if k.lower() in {"systemtime","timecreated","timestamp","datetime","time"}),"")
 eid=next((v for k,v in flat.items() if k.lower() in {"eventid","event_id","id"}),"")
 provider=next((v for k,v in flat.items() if k.lower() in {"provider","name"}),"")
 level=next((v for k,v in flat.items() if k.lower() in {"level","severity"}),"INFO")
 host=next((v for k,v in flat.items() if k.lower() in {"computer","hostname","host"}),"")
 user=next((v for k,v in flat.items() if k.lower() in {"targetusername","subjectusername","username","user"}),"")
 message=" | ".join(f"{k}={v}" for k,v in flat.items())
 return Event(normalize_time(ts) or sniff_timestamp(message),filename,"XML",f"event[{index}]",eid,level,provider,host,user,"",message,ET.tostring(node,encoding="unicode"),digest)
def event_from_row(row:dict[str,Any],filename:str,stype:str,location:str,digest:str)->Event:
 serialized=json.dumps(row,ensure_ascii=False,default=str); lower={str(k).strip().lower().replace(" ","").replace("_",""):v for k,v in row.items()}
 def get(names:Iterable[str])->str:
  for name in names:
   key=name.lower().replace(" ","").replace("_","")
   if key in lower and str(lower[key]).strip() and str(lower[key]).lower()!="nan":return str(lower[key]).strip()
  return ""
 ts=get(["timestamp","timecreated","datetime","date/time","date","time","systemtime","utc time"]); eid=get(["eventid","event id","event_id","id"]); level=get(["level","severity","eventlevel"]) or "INFO"; provider=get(["provider","source","service","channel"]); host=get(["computer","hostname","host","device","server"]); user=get(["username","user","subjectusername","targetusername","account"]); process=get(["processname","process","image","application","executable","commandline","command line"]); message=get(["message","details","description","eventdata","commandline","command line","text"]) or serialized
 return Event(normalize_time(ts) or sniff_timestamp(serialized),filename,stype,location,eid,level,provider,host,user,process,message,serialized,digest)
def assess(events:list[Event])->list[Finding]:
 findings=[]
 for ev in events:
  haystack=" ".join([ev.process,ev.message,ev.raw])
  if not haystack.strip():continue
  for rid,sev,title,pattern,rationale in RULES:
   m=pattern.search(haystack)
   if m:findings.append(Finding(sev,title,rationale,m.group(0)[:500],ev.source_file,ev.location,ev.timestamp,rid))
 auth=[e for e in events if re.search(r"(?i)(failed password|logon failure|authentication failed|invalid credentials|4625)",e.message+" "+e.raw)]; grouped={}
 for e in auth:grouped.setdefault((e.user or "unknown-account",e.source_file),[]).append(e)
 for (user,source),rows in grouped.items():
  if len(rows)>=5:
   first=min((r.timestamp for r in rows if r.timestamp),default="")
   findings.append(Finding("HIGH","Repeated authentication failures",f"Observed {len(rows)} matching failure indicators in this source file for account hint '{user}'. Confirm distinct attempts, source IPs, and time window.",f"{len(rows)} records; account={user}",source,f"{rows[0].location} … {rows[-1].location}",first,"AUTH-REPEAT-005"))
 unique={(f.rule_id,f.source_file,f.location,f.evidence):f for f in findings}; order={"CRITICAL":0,"HIGH":1,"MEDIUM":2,"LOW":3,"INFO":4}
 return sorted(unique.values(),key=lambda x:(order.get(x.severity,5),x.timestamp,x.source_file))
