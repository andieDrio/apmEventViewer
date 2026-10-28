from __future__ import annotations
import base64,csv,io,json,os,re,tempfile,threading,uuid,xml.etree.ElementTree as ET
from collections import Counter
from dataclasses import asdict
from datetime import datetime,timedelta,timezone
from http.server import BaseHTTPRequestHandler,ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlparse
from core import Event,Finding,assess,build_case_assessment,event_from_row,sha256,sniff_timestamp,xml_event_to_event
try:
    from Evtx.Evtx import Evtx
except Exception:
    Evtx=None
HOST=os.environ.get("APMEVENTVIEWER_HOST","127.0.0.1"); PORT=int(os.environ.get("APMEVENTVIEWER_PORT","8765"))
UTC8=timezone(timedelta(hours=8),name="UTC+08:00"); ROOT=Path(__file__).resolve().parent
JOBS={}; LOCK=threading.Lock(); MAX_BODY=120*1024*1024
def decode_text(data):
    for enc in ("utf-8-sig","utf-16","cp1252","latin-1"):
        try:return data.decode(enc)
        except UnicodeDecodeError:pass
    return data.decode("utf-8",errors="replace")
def parse_evtx(data,name,digest,progress=None):
    if Evtx is None:raise RuntimeError("EVTX parser unavailable; install requirements.txt dependencies.")
    fd,path=tempfile.mkstemp(suffix=".evtx")
    try:
        with os.fdopen(fd,"wb") as out:out.write(data)
        result=[]
        with Evtx(path) as log:
            for i,record in enumerate(log.records(),1):
                raw=record.xml()
                try:event=xml_event_to_event(ET.fromstring(raw),name,digest,i)
                except ET.ParseError:event=Event("",name,"EVTX",f"record[{i}]",raw=raw,message=raw,sha256=digest)
                event.source_type="SYSMON" if "sysmon" in event.provider.lower() or "sysmon" in name.lower() else "EVTX"
                event.location=f"record[{i}]";result.append(event)
                if progress and i%250==0:progress(i)
        return result
    finally:
        try:os.unlink(path)
        except OSError:pass
def parse_upload(name,data,progress=None):
    ext=Path(name).suffix.lower(); digest=sha256(data)
    if ext==".evtx":return parse_evtx(data,name,digest,progress)
    if ext==".xml":
        head=data[:200000].upper()
        if b"<!DOCTYPE" in head or b"<!ENTITY" in head:raise ValueError("XML DTD/entity declarations are not accepted.")
        root=ET.fromstring(data); nodes=[n for n in root.iter() if n is not root and n.tag.rsplit("}",1)[-1].lower() in {"event","eventrecord","record","systemevent"}] or [root]
        return [xml_event_to_event(n,name,digest,i) for i,n in enumerate(nodes,1)]
    if ext==".csv":
        rows=csv.DictReader(io.StringIO(decode_text(data)))
        return [event_from_row(row,name,"CSV",f"row[{i}]",digest) for i,row in enumerate(rows,2)]
    if ext in {".log",".txt"}:
        out=[]
        for i,line in enumerate(decode_text(data).splitlines(),1):
            if not line.strip():continue
            m=re.search(r"(?i)\b(critical|fatal|error|warning|warn|information|info|debug)\b",line)
            out.append(Event(sniff_timestamp(line),name,"LOG",f"line[{i}]",level=m.group(1).upper() if m else "INFO",message=line.strip(),raw=line.strip(),sha256=digest))
        return out
    raise ValueError("Unsupported file type: "+ext)
def pdf_report(events,findings,case_name,notes):
    from reportlab.lib import colors
    from reportlab.lib.pagesizes import A4,landscape
    from reportlab.lib.styles import getSampleStyleSheet,ParagraphStyle
    from reportlab.lib.units import mm
    from reportlab.platypus import SimpleDocTemplate,Paragraph,Spacer,Table,TableStyle
    buf=io.BytesIO(); styles=getSampleStyleSheet()
    styles.add(ParagraphStyle(name="SmallCell",parent=styles["BodyText"],fontSize=7,leading=9))
    safe=lambda x:str(x).replace("&","&amp;").replace("<","&lt;").replace(">","&gt;")
    assessment=build_case_assessment(events,findings); counts=Counter(f.severity for f in findings)
    doc=SimpleDocTemplate(buf,pagesize=landscape(A4),rightMargin=12*mm,leftMargin=12*mm,topMargin=12*mm,bottomMargin=14*mm,title="Forensic assessment - "+case_name)
    story=[Paragraph("DIGITAL FORENSICS LOG ASSESSMENT",styles["Title"]),Paragraph(safe(case_name),styles["Heading2"]),Paragraph("Generated: "+datetime.now(UTC8).strftime("%Y-%m-%d %H:%M:%S UTC+08:00"),styles["Normal"]),Spacer(1,4*mm)]
    metrics=[["Events",str(len(events)),"Files",str(len({e.source_file for e in events})),"Findings",str(len(findings)),"Critical / High",str(counts.get("CRITICAL",0)+counts.get("HIGH",0))]]
    story.append(Table(metrics,colWidths=[20*mm,18*mm,15*mm,18*mm,20*mm,18*mm,30*mm,18*mm],style=TableStyle([("BACKGROUND",(0,0),(-1,-1),colors.HexColor("#EAF0F6")),("GRID",(0,0),(-1,-1),.4,colors.grey),("PADDING",(0,0),(-1,-1),5)])))
    story += [Paragraph("Evidence-based case assessment",styles["Heading2"]),Paragraph("<b>Activity level:</b> "+safe(assessment["activity_level"])+" &nbsp; <b>Confidence (rule-correlation breadth):</b> "+safe(assessment["confidence"]),styles["BodyText"]),Paragraph(safe(assessment["assessment"]),styles["BodyText"])]
    for title,items in (("Facts",assessment["facts"]),("Observations",assessment["observations"]),("Analyst attention",assessment["analyst_attention"])):
        story.append(Paragraph(title,styles["Heading3"]));story.append(Paragraph("<br/>".join("• "+safe(x) for x in items),styles["BodyText"]))
    story.append(Paragraph("Findings",styles["Heading2"]))
    rows=[["Severity","Rule","Finding / rationale","Timestamp","Source / location","Evidence"]]
    for f in findings:rows.append([safe(f.severity),safe(f.rule_id),Paragraph(safe(f.title)+"<br/>"+safe(f.rationale),styles["SmallCell"]),safe(f.timestamp),Paragraph(safe(f.source_file)+"<br/>"+safe(f.location),styles["SmallCell"]),Paragraph(safe(f.evidence),styles["SmallCell"])])
    if len(rows)==1:story.append(Paragraph("No rule matches. This does not establish that activity was benign.",styles["BodyText"]))
    else:story.append(Table(rows,repeatRows=1,colWidths=[17*mm,25*mm,65*mm,34*mm,42*mm,72*mm],style=TableStyle([("BACKGROUND",(0,0),(-1,0),colors.HexColor("#17365D")),("TEXTCOLOR",(0,0),(-1,0),colors.white),("GRID",(0,0),(-1,-1),.3,colors.grey),("VALIGN",(0,0),(-1,-1),"TOP"),("PADDING",(0,0),(-1,-1),4)])))
    story.append(Paragraph("Timeline excerpts (first 500 records)",styles["Heading2"]))
    rows=[["Timestamp","Type","Event ID","Host / user","Source / location","Message"]]
    for e in sorted(events,key=lambda x:x.timestamp or "~")[:500]:rows.append([Paragraph(safe(e.timestamp),styles["SmallCell"]),safe(e.source_type),safe(e.event_id),Paragraph(safe(" / ".join(x for x in (e.host,e.user) if x)),styles["SmallCell"]),Paragraph(safe(e.source_file)+"<br/>"+safe(e.location),styles["SmallCell"]),Paragraph(safe(e.message)[:1000],styles["SmallCell"])])
    story.append(Table(rows,repeatRows=1,colWidths=[32*mm,15*mm,16*mm,28*mm,42*mm,122*mm],style=TableStyle([("BACKGROUND",(0,0),(-1,0),colors.HexColor("#34495E")),("TEXTCOLOR",(0,0),(-1,0),colors.white),("GRID",(0,0),(-1,-1),.3,colors.grey),("VALIGN",(0,0),(-1,-1),"TOP"),("PADDING",(0,0),(-1,-1),3)])))
    story += [Paragraph("Analyst notes",styles["Heading2"]),Paragraph(safe(notes or "No analyst notes supplied").replace("\n","<br/>"),styles["BodyText"]),Paragraph("SHA-256 identifies the uploaded bytes. Preserve originals and validate findings against source artifacts. Rules are triage leads, not proof of compromise.",styles["Italic"])]
    def footer(canvas,document):
        canvas.saveState();canvas.setFont("Helvetica",7);canvas.setFillColor(colors.grey);canvas.drawString(12*mm,7*mm,"apmEventViewer | UTC+08:00 | CONFIDENTIAL");canvas.drawRightString(landscape(A4)[0]-12*mm,7*mm,f"Page {document.page}");canvas.restoreState()
    doc.build(story,onFirstPage=footer,onLaterPages=footer);return buf.getvalue()
def worker(jid,files,case,notes):
    events=[];manifest=[];errors=[]
    with LOCK:JOBS[jid].update(status="running",message="Starting analysis")
    for i,item in enumerate(files):
        name=os.path.basename(str(item.get("name","evidence.bin")))
        try:
            data=base64.b64decode(item.get("contentBase64",""),validate=True)
            if not data:raise ValueError("File is empty")
            digest=sha256(data)
            def progress(n):
                with LOCK:JOBS[jid].update(message=f"Parsing {name}: {n:,} records read")
            parsed=parse_upload(name,data,progress);events.extend(parsed);count=len(parsed);status="Parsed"
        except Exception as exc:
            errors.append(f"{name}: {type(exc).__name__}: {exc}");digest="";data=b"";count=0;status=errors[-1]
        manifest.append({"file":name,"bytes":len(data),"sha256":digest,"eventsParsed":count,"status":status})
        with LOCK:JOBS[jid].update(progress=int((i+1)/max(len(files),1)*90),files_done=i+1,files_total=len(files),message=f"Processed {i+1}/{len(files)}: {name}",manifest=manifest.copy(),errors=errors.copy())
    findings=assess(events);assessment=build_case_assessment(events,findings)
    with LOCK:JOBS[jid].update(status="complete",progress=100,message="Analysis complete",events=[asdict(e) for e in events],findings=[asdict(f) for f in findings],assessment=assessment,manifest=manifest,errors=errors,caseName=case,analystNotes=notes,eventCount=len(events),findingCount=len(findings))
class Handler(BaseHTTPRequestHandler):
    def log_message(self,fmt,*args):print(datetime.now(UTC8).strftime("[%H:%M:%S] ")+fmt%args)
    def send_data(self,status,data,ctype,headers=None):
        self.send_response(status);self.send_header("Content-Type",ctype);self.send_header("Content-Length",str(len(data)));self.send_header("X-Content-Type-Options","nosniff");self.send_header("Cache-Control","no-store")
        for k,v in (headers or {}).items():self.send_header(k,v)
        self.end_headers();self.wfile.write(data)
    def json(self,status,obj):self.send_data(status,json.dumps(obj,ensure_ascii=False).encode(), "application/json; charset=utf-8")
    def do_GET(self):
        path=urlparse(self.path).path
        if path=="/api/health":return self.json(200,{"status":"ok"})
        if path=="/":return self.send_data(200,(ROOT/"web"/"index.html").read_bytes(),"text/html; charset=utf-8")
        parts=path.strip("/").split("/")
        if len(parts)==3 and parts[:2]==["api","jobs"]:
            with LOCK:job=dict(JOBS.get(parts[2],{}))
            if not job:return self.json(404,{"error":"Job not found"})
            job.pop("events",None);job.pop("findings",None);return self.json(200,job)
        if len(parts)==4 and parts[:2]==["api","jobs"]:
            with LOCK:job=dict(JOBS.get(parts[2],{}))
            if not job:return self.json(404,{"error":"Job not found"})
            if job.get("status")!="complete":return self.json(409,{"error":"Analysis is not complete"})
            if parts[3]=="results":
                job={k:job.get(k) for k in ("caseName","analystNotes","events","findings","assessment","manifest","errors","eventCount","findingCount")}
                return self.json(200,job)
            if parts[3]=="report.pdf":
                try:pdf=pdf_report([Event(**x) for x in job["events"]],[Finding(**x) for x in job["findings"]],job.get("caseName","Investigation"),job.get("analystNotes",""))
                except Exception as exc:return self.json(500,{"error":f"PDF generation failed: {type(exc).__name__}: {exc}"})
                filename=re.sub(r"[^A-Za-z0-9._-]+","_",job.get("caseName","case")).strip("._") or "case"
                return self.send_data(200,pdf,"application/pdf",{"Content-Disposition":f'attachment; filename="{filename}_assessment.pdf"'})
        return self.json(404,{"error":"Not found"})
    def do_POST(self):
        if urlparse(self.path).path!="/api/analyze":return self.json(404,{"error":"Not found"})
        length=int(self.headers.get("Content-Length","0"))
        if length<=0 or length>MAX_BODY:return self.json(413,{"error":"Request must be 1 byte to 120 MiB"})
        try:
            payload=json.loads(self.rfile.read(length).decode("utf-8"));files=payload.get("files",[])
            if not isinstance(files,list) or not files:raise ValueError("Upload at least one file")
            if len(files)>25:raise ValueError("Maximum 25 files per analysis")
            for item in files:
                if os.path.splitext(os.path.basename(str(item.get("name",""))))[1].lower() not in {".evtx",".log",".txt",".csv",".xml"}:raise ValueError("Unsupported file type: "+str(item.get("name")))
            case=str(payload.get("caseName") or "Log Investigation")[:200];notes=str(payload.get("analystNotes") or "")[:10000]
        except Exception as exc:return self.json(400,{"error":str(exc)})
        jid=uuid.uuid4().hex
        with LOCK:JOBS[jid]={"id":jid,"status":"queued","progress":0,"message":"Queued","files_done":0,"files_total":len(files),"manifest":[],"errors":[]}
        threading.Thread(target=worker,args=(jid,files,case,notes),daemon=True).start()
        return self.json(202,{"jobId":jid,"status":"queued"})
def main():
    if not (ROOT/"web"/"index.html").exists():raise SystemExit("Missing web/index.html")
    server=ThreadingHTTPServer((HOST,PORT),Handler);print(f"apmEventViewer ready at http://{HOST}:{PORT} (local-only)")
    try:server.serve_forever()
    except KeyboardInterrupt:print("\nStopping apmEventViewer")
    finally:server.server_close()
if __name__=="__main__":main()
