from __future__ import annotations

import io
import os
import tempfile
import xml.etree.ElementTree as ET
from dataclasses import asdict
from collections import Counter
from datetime import datetime, timezone, timedelta

import pandas as pd
import streamlit as st

from core import Event, Finding, assess, build_case_assessment, event_from_row, sha256, sniff_timestamp, xml_event_to_event

try:
    from Evtx.Evtx import Evtx
except Exception:
    Evtx = None

UTC8 = timezone(timedelta(hours=8), name="UTC+08:00")

def decode_text(data: bytes) -> str:
    for enc in ("utf-8-sig", "utf-16", "cp1252", "latin-1"):
        try: return data.decode(enc)
        except UnicodeDecodeError: continue
    return data.decode("utf-8", errors="replace")

def parse_evtx(data: bytes, filename: str, digest: str) -> list[Event]:
    if Evtx is None: raise RuntimeError("EVTX parser unavailable. Install dependencies with: pip install -r requirements.txt")
    fd, path = tempfile.mkstemp(suffix=".evtx")
    try:
        with os.fdopen(fd, "wb") as f: f.write(data)
        result=[]
        with Evtx(path) as log:
            for index, record in enumerate(log.records(), start=1):
                raw=record.xml()
                try: event=xml_event_to_event(ET.fromstring(raw),filename,digest,index)
                except ET.ParseError: event=Event("",filename,"EVTX",f"record[{index}]",raw=raw,message=raw,sha256=digest)
                event.source_type="SYSMON" if "sysmon" in event.provider.lower() or "sysmon" in filename.lower() else "EVTX"; event.location=f"record[{index}]"; result.append(event)
        return result
    finally:
        try: os.unlink(path)
        except OSError: pass

def parse_xml(data: bytes, filename: str, digest: str) -> list[Event]:
    if b"<!DOCTYPE" in data[:200000].upper() or b"<!ENTITY" in data[:200000].upper(): raise ValueError("XML containing DTD/entity declarations is not accepted for safety.")
    root=ET.fromstring(data)
    nodes=[n for n in root.iter() if n is not root and n.tag and n.tag.rsplit("}",1)[-1].lower() in {"event","eventrecord","record","systemevent"}]
    if not nodes: nodes=[root]
    return [xml_event_to_event(n,filename,digest,idx) for idx,n in enumerate(nodes,1)]

def parse_upload(name: str, data: bytes) -> list[Event]:
    suffix="."+name.rsplit(".",1)[-1].lower() if "." in name else ""
    digest=sha256(data)
    if suffix==".evtx": return parse_evtx(data,name,digest)
    if suffix==".xml": return parse_xml(data,name,digest)
    if suffix==".csv":
        df=pd.read_csv(io.BytesIO(data),dtype=str,keep_default_na=False,on_bad_lines="warn")
        return [event_from_row(row,name,"CSV",f"row[{i}]",digest) for i,row in enumerate(df.to_dict(orient="records"),2)]
    if suffix in {".log",".txt"}:
        result=[]
        for i,line in enumerate(decode_text(data).splitlines(),1):
            if not line.strip(): continue
            import re
            m=re.search(r"(?i)\b(critical|fatal|error|warning|warn|information|info|debug)\b",line)
            level=m.group(1).upper() if m else "INFO"
            result.append(Event(sniff_timestamp(line),name,"LOG",f"line[{i}]",level=level,message=line.strip(),raw=line.strip(),sha256=digest))
        return result
    raise ValueError(f"Unsupported file type: {suffix or '(no extension)'}")

def pdf_report(events: list[Event], findings: list[Finding], case_name: str, analyst_notes: str) -> bytes:
    from reportlab.lib import colors
    from reportlab.lib.pagesizes import A4, landscape
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    from reportlab.lib.units import mm
    from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
    output=io.BytesIO(); styles=getSampleStyleSheet()
    styles.add(ParagraphStyle(name="SmallCell",parent=styles["BodyText"],fontSize=7,leading=9,spaceAfter=0))
    styles.add(ParagraphStyle(name="Section",parent=styles["Heading2"],textColor=colors.HexColor("#17365D"),spaceBefore=10))
    doc=SimpleDocTemplate(output,pagesize=landscape(A4),rightMargin=14*mm,leftMargin=14*mm,topMargin=14*mm,bottomMargin=14*mm,title=f"Forensic Log Assessment - {case_name}",author="apmEventViewer")
    safe=lambda s: str(s).replace("&","&amp;").replace("<","&lt;").replace(">","&gt;")
    counts=Counter(f.severity for f in findings)
    story=[Paragraph("DIGITAL FORENSICS LOG ASSESSMENT",styles["Title"]),Paragraph(safe(case_name),styles["Heading2"]),Paragraph(f"Generated: {datetime.now(UTC8).strftime('%Y-%m-%d %H:%M:%S UTC+08:00')}",styles["Normal"]),Spacer(1,5*mm)]
    metrics=[["Events analyzed",str(len(events)),"Files",str(len(set(e.source_file for e in events))),"Findings",str(len(findings)),"Critical / High",str(counts.get("CRITICAL",0)+counts.get("HIGH",0))]]
    t=Table(metrics,colWidths=[28*mm,18*mm,14*mm,18*mm,18*mm,18*mm,28*mm,18*mm]); t.setStyle(TableStyle([("BACKGROUND",(0,0),(-1,-1),colors.HexColor("#EAF0F6")),("GRID",(0,0),(-1,-1),0.4,colors.HexColor("#B8C4D1")),("FONTNAME",(0,0),(-1,-1),"Helvetica-Bold"),("FONTSIZE",(0,0),(-1,-1),8),("PADDING",(0,0),(-1,-1),6)]))
    story += [t,Paragraph("Scope and methodology",styles["Section"]),Paragraph("Uploaded EVTX (including Sysmon), LOG/TXT, CSV, and XML artifacts were parsed into a normalized event timeline. Sysmon Event IDs 8, 10, and 25 receive dedicated triage context when identified. Timestamps are displayed in UTC+08:00; timestamps without a source offset are assumed to represent local UTC+08:00. Rule-based detections are triage indicators and are not, by themselves, proof of compromise.",styles["BodyText"]),Paragraph("Evidence-based case assessment",styles["Section"])]
    case_assessment = build_case_assessment(events, findings)
    story.append(Paragraph("<b>Activity level:</b> " + safe(case_assessment["activity_level"]) + " &nbsp;&nbsp; <b>Assessment confidence (rule-correlation breadth):</b> " + safe(case_assessment["confidence"]),styles["BodyText"]))
    story.append(Spacer(1,2*mm))
    story.append(Paragraph("<b>Assessment:</b> " + safe(case_assessment["assessment"]),styles["BodyText"]))
    for section_title, items in (("Facts", case_assessment["facts"]), ("Observations", case_assessment["observations"]), ("Analyst attention", case_assessment["analyst_attention"])):
        story.append(Paragraph(section_title, styles["Heading3"]))
        story.append(Paragraph("<br/>".join("• " + safe(item) for item in items), styles["BodyText"]))
    story.append(Paragraph("<i>Assessment basis:</i> " + safe(case_assessment["basis"]), styles["SmallCell"]))
    story.append(Paragraph("Finding details",styles["Section"]))
    rows=[["Severity","Rule","Finding / rationale","Timestamp (UTC+08:00)","Source / location","Evidence"]]
    for f in findings: rows.append([Paragraph(safe(f.severity),styles["SmallCell"]),Paragraph(safe(f.rule_id),styles["SmallCell"]),Paragraph(safe(f.title)+"<br/>"+safe(f.rationale),styles["SmallCell"]),Paragraph(safe(f.timestamp),styles["SmallCell"]),Paragraph(safe(f.source_file)+"<br/>"+safe(f.location),styles["SmallCell"]),Paragraph(safe(f.evidence),styles["SmallCell"])])
    if len(rows)>1:
        ft=Table(rows,repeatRows=1,colWidths=[17*mm,25*mm,75*mm,37*mm,45*mm,55*mm]); ft.setStyle(TableStyle([("BACKGROUND",(0,0),(-1,0),colors.HexColor("#17365D")),("TEXTCOLOR",(0,0),(-1,0),colors.white),("FONTNAME",(0,0),(-1,0),"Helvetica-Bold"),("FONTSIZE",(0,0),(-1,0),8),("GRID",(0,0),(-1,-1),0.3,colors.HexColor("#C8D0D9")),("VALIGN",(0,0),(-1,-1),"TOP"),("LEFTPADDING",(0,0),(-1,-1),4),("RIGHTPADDING",(0,0),(-1,-1),4),("TOPPADDING",(0,0),(-1,-1),4),("BOTTOMPADDING",(0,0),(-1,-1),4)])); story.append(ft)
    else: story.append(Paragraph("No matches were found by the enabled rules. This does not establish that the activity is benign.",styles["BodyText"]))
    story.append(Paragraph("Timeline excerpts (first 500 records)",styles["Section"]))
    erows=[["Timestamp","Type","Event ID","Host / user","Source / location","Message"]]
    for e in sorted(events,key=lambda x:x.timestamp or "~")[:500]: erows.append([Paragraph(safe(e.timestamp),styles["SmallCell"]),safe(e.source_type),safe(e.event_id),Paragraph(safe(" / ".join(x for x in (e.host,e.user) if x)),styles["SmallCell"]),Paragraph(safe(e.source_file)+"<br/>"+safe(e.location),styles["SmallCell"]),Paragraph(safe(e.message)[:1200],styles["SmallCell"])])
    et=Table(erows,repeatRows=1,colWidths=[35*mm,15*mm,17*mm,28*mm,42*mm,117*mm]); et.setStyle(TableStyle([("BACKGROUND",(0,0),(-1,0),colors.HexColor("#34495E")),("TEXTCOLOR",(0,0),(-1,0),colors.white),("FONTNAME",(0,0),(-1,0),"Helvetica-Bold"),("FONTSIZE",(0,0),(-1,0),8),("GRID",(0,0),(-1,-1),0.3,colors.HexColor("#D2D8DE")),("VALIGN",(0,0),(-1,-1),"TOP"),("LEFTPADDING",(0,0),(-1,-1),3),("RIGHTPADDING",(0,0),(-1,-1),3),("TOPPADDING",(0,0),(-1,-1),3),("BOTTOMPADDING",(0,0),(-1,-1),3)])); story.append(et)
    story += [Paragraph("Analyst notes",styles["Section"]),Paragraph(safe(analyst_notes or "No analyst notes supplied.").replace("\n","<br/>"),styles["BodyText"]),Spacer(1,4*mm),Paragraph("Evidence integrity: SHA-256 values are included in the normalized event export. Preserve original evidence and validate conclusions against source artifacts. Rule results are preliminary triage, not a substitute for analyst review.",styles["Italic"])]
    def footer(canvas,document):
        canvas.saveState(); canvas.setFont("Helvetica",7); canvas.setFillColor(colors.grey); canvas.drawString(14*mm,7*mm,"apmEventViewer | UTC+08:00 | CONFIDENTIAL - HANDLE AS INVESTIGATION EVIDENCE"); canvas.drawRightString(landscape(A4)[0]-14*mm,7*mm,f"Page {document.page}"); canvas.restoreState()
    doc.build(story,onFirstPage=footer,onLaterPages=footer); return output.getvalue()

st.set_page_config(page_title="apmEventViewer | Forensic Log Analysis",page_icon="🛡️",layout="wide")
st.markdown("""<style>.block-container{padding-top:1.4rem;padding-bottom:2rem;max-width:1600px}[data-testid="stMetric"]{background:#111827;padding:16px 18px;border:1px solid #263244;border-radius:12px}[data-testid="stMetricLabel"]{color:#9CA3AF}[data-testid="stMetricValue"]{color:#F9FAFB}section[data-testid="stSidebar"]{background:#0b1220}</style>""",unsafe_allow_html=True)
st.title("🛡️ apmEventViewer"); st.caption("Digital forensics • Multi-source log analysis • Evidence-linked triage • UTC+08:00")
with st.sidebar:
 st.header("Case workspace"); case_name=st.text_input("Case name / reference",value="Log Investigation"); analyst_notes=st.text_area("Analyst notes",placeholder="Scope, questions, known timeline, caveats…",height=130); st.divider(); st.subheader("Analysis settings"); severity_filter=st.multiselect("Finding severity",["CRITICAL","HIGH","MEDIUM","LOW","INFO"],default=["CRITICAL","HIGH","MEDIUM"]); search_query=st.text_input("Search event text",placeholder="IP, username, process, event ID…"); st.caption("Files are processed locally in this app. Preserve original evidence and analyze working copies.")
uploads=st.file_uploader("Upload forensic artifacts",type=["evtx","log","txt","csv","xml"],accept_multiple_files=True,help="Supports Windows EVTX, text logs, CSV exports, and XML event exports.")
if "events" not in st.session_state: st.session_state.events=[]
if "file_meta" not in st.session_state: st.session_state.file_meta=[]
if st.button("Analyze uploaded files",type="primary",disabled=not uploads):
 all_events=[]; metadata=[]; errors=[]; progress=st.progress(0,text="Preparing files…")
 for i,f in enumerate(uploads):
  data=f.getvalue()
  try: parsed=parse_upload(f.name,data); all_events.extend(parsed); status="Parsed"; count=len(parsed)
  except Exception as exc: errors.append(f"{f.name}: {type(exc).__name__}: {exc}"); status=f"Failed: {exc}"; count=0
  metadata.append({"File":f.name,"Type":f.name.rsplit(".",1)[-1].upper(),"Bytes":len(data),"SHA-256":sha256(data),"Events parsed":count,"Status":status}); progress.progress((i+1)/len(uploads),text=f"Processed {i+1}/{len(uploads)} files")
 st.session_state.events=all_events; st.session_state.file_meta=metadata; st.session_state.parse_errors=errors; st.rerun()
events:list[Event]=st.session_state.events
if st.session_state.file_meta:
 st.subheader("Evidence manifest"); st.dataframe(pd.DataFrame(st.session_state.file_meta),use_container_width=True,hide_index=True)
 for err in st.session_state.get("parse_errors",[]): st.error(err)
if events:
 findings=assess(events); visible_events=events
 if search_query:
  q=search_query.casefold(); visible_events=[e for e in events if q in " ".join([e.timestamp,e.source_file,e.event_id,e.level,e.provider,e.host,e.user,e.process,e.message,e.raw]).casefold()]
 visible_findings=[f for f in findings if f.severity in severity_filter]; counts=Counter(f.severity for f in findings)
 c1,c2,c3,c4,c5=st.columns(5); c1.metric("Events parsed",f"{len(events):,}"); c2.metric("Evidence files",len(set(e.source_file for e in events))); c3.metric("Critical findings",counts.get("CRITICAL",0)); c4.metric("High findings",counts.get("HIGH",0)); c5.metric("Medium findings",counts.get("MEDIUM",0)); st.divider()
 tab_findings,tab_timeline,tab_sources,tab_export=st.tabs(["Assessment","Timeline","Evidence manifest","Export & report"])
 with tab_findings:
  st.subheader("Evidence-based case assessment"); st.caption("Assessment is generated deterministically from parsed evidence and enabled rule matches. It is a triage conclusion, not an automatic incident verdict.")
  case_assessment=build_case_assessment(events,findings)
  st.markdown(f"**Activity level:** {case_assessment['activity_level']} &nbsp; · &nbsp; **Assessment confidence (rule-correlation breadth):** {case_assessment['confidence']}")
  st.info(case_assessment["assessment"])
  with st.expander("Assessment basis: facts, observations, and analyst attention", expanded=True):
   st.markdown("**Facts**")
   for item in case_assessment["facts"]: st.markdown(f"- {item}")
   st.markdown("**Observations**")
   for item in case_assessment["observations"]: st.markdown(f"- {item}")
   st.markdown("**Analyst attention**")
   for item in case_assessment["analyst_attention"]: st.markdown(f"- {item}")
   st.caption(case_assessment["basis"])
  st.divider()
  st.subheader("Finding details and evidence references"); st.caption("Detections are investigative leads. Validate context, adjacent events, and successful execution before assigning a verdict.")
  if visible_findings:
   fdf=pd.DataFrame([asdict(f) for f in visible_findings]).rename(columns={"severity":"Severity","title":"Finding","rule_id":"Rule ID","timestamp":"Timestamp (UTC+08:00)","source_file":"Source file","location":"Evidence location","evidence":"Matched evidence","rationale":"Assessment rationale"}); st.dataframe(fdf[["Severity","Rule ID","Finding","Timestamp (UTC+08:00)","Source file","Evidence location","Matched evidence","Assessment rationale"]],use_container_width=True,hide_index=True,height=420)
   with st.expander("Finding details and evidence references"):
    for f in visible_findings: st.markdown(f"**[{f.severity}] {f.title}** — `{f.rule_id}`"); st.write(f"Source: `{f.source_file}` • {f.location} • {f.timestamp or 'Timestamp unavailable'}"); st.write(f"Evidence: `{f.evidence}`"); st.write(f.rationale)
  else: st.info("No findings match current filters. This is not proof that the activity is benign.")
  chart=pd.DataFrame({"Severity":["CRITICAL","HIGH","MEDIUM","LOW","INFO"],"Count":[counts.get(x,0) for x in ["CRITICAL","HIGH","MEDIUM","LOW","INFO"]]}).set_index("Severity"); st.bar_chart(chart)
 with tab_timeline:
  st.subheader("Normalized event timeline"); tdf=pd.DataFrame([{"Timestamp (UTC+08:00)":e.timestamp,"Type":e.source_type,"Provider":e.provider,"Level":e.level,"Event ID":e.event_id,"Host":e.host,"User":e.user,"Process":e.process,"Message":e.message[:2000],"Source file":e.source_file,"Location":e.location} for e in sorted(visible_events,key=lambda x:x.timestamp or "~")])
  if not tdf.empty:
   parsed=pd.to_datetime(tdf["Timestamp (UTC+08:00)"],errors="coerce",utc=True); dates=parsed.dropna()
   if not dates.empty:
    cfrom,cto=st.columns(2); min_date,max_date=dates.min().date(),dates.max().date()
    with cfrom: start_date=st.date_input("From date",value=min_date,min_value=min_date,max_value=max_date)
    with cto: end_date=st.date_input("To date",value=max_date,min_value=min_date,max_value=max_date)
    tdf=tdf[parsed.isna()|((parsed.dt.date>=start_date)&(parsed.dt.date<=end_date))]
   levels=st.multiselect("Level filter",sorted(tdf["Level"].fillna("INFO").unique().tolist()),default=sorted(tdf["Level"].fillna("INFO").unique().tolist()),key="timeline_levels"); tdf=tdf[tdf["Level"].isin(levels)]; st.dataframe(tdf,use_container_width=True,hide_index=True,height=560); st.caption(f"Showing {len(tdf):,} records. Missing timestamps cannot be chronologically placed with confidence.")
  else: st.info("No events match your search.")
 with tab_sources:
  st.dataframe(pd.DataFrame(st.session_state.file_meta),use_container_width=True,hide_index=True); st.markdown("**Integrity handling:** SHA-256 is calculated over uploaded file bytes before parsing. Keep original evidence unchanged; the digest identifies the bytes received by this application.")
 with tab_export:
  st.subheader("Export case outputs"); export_events=pd.DataFrame([asdict(e) for e in sorted(events,key=lambda x:x.timestamp or "~")]); export_findings=pd.DataFrame([asdict(f) for f in findings]); left,right=st.columns(2)
  with left:
   st.download_button("Download normalized events (CSV)",export_events.to_csv(index=False).encode("utf-8-sig"),file_name="apmEventViewer_events.csv",mime="text/csv",use_container_width=True); st.download_button("Download findings (CSV)",export_findings.to_csv(index=False).encode("utf-8-sig"),file_name="apmEventViewer_findings.csv",mime="text/csv",use_container_width=True)
  with right:
   try: st.download_button("Generate / download PDF assessment",pdf_report(events,findings,case_name,analyst_notes),file_name="apmEventViewer_assessment.pdf",mime="application/pdf",type="primary",use_container_width=True)
   except Exception as exc: st.error(f"PDF generation failed: {type(exc).__name__}: {exc}")
  st.info("PDF includes summary, evidence-linked findings, up to 500 timeline records, analyst notes, and UTC+08:00 timestamps.")
else:
 st.markdown("### Start an investigation"); st.write("Upload log artifacts. The application hashes each file, parses records, normalizes timestamps, runs conservative triage rules, and builds an evidence-linked timeline."); col1,col2,col3,col4=st.columns(4); col1.markdown("**EVTX**\n\nWindows Event Viewer binary logs"); col2.markdown("**LOG / TXT**\n\nApache, PHP, PowerShell, application, and plain-text logs"); col3.markdown("**CSV**\n\nExported event tables and SIEM data"); col4.markdown("**XML**\n\nWindows Event Viewer XML exports"); st.warning("No files have been analyzed in this session. This tool runs locally; do not expose it to untrusted networks.")