"""Generate the illustrated SentinelMesh project walkthrough."""
from pathlib import Path
from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER
from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, PageBreak, Table, TableStyle, Preformatted

ROOT=Path(__file__).resolve().parents[1]
OUT=ROOT/"output"/"pdf"/"SentinelMesh_How_It_Works.pdf"
styles=getSampleStyleSheet()
styles.add(ParagraphStyle(name="Cover",parent=styles["Title"],fontSize=27,leading=32,textColor=colors.HexColor("#12304a"),alignment=TA_CENTER,spaceAfter=18))
styles.add(ParagraphStyle(name="Sub",parent=styles["Normal"],fontSize=12,leading=18,alignment=TA_CENTER,textColor=colors.HexColor("#476276")))
styles.add(ParagraphStyle(name="Small",parent=styles["BodyText"],fontSize=9,leading=13))
def P(text,style="BodyText"): return Paragraph(text,styles[style])
def node(text):
    t=Table([[P(text,"Small")]],colWidths=[2.1*inch],rowHeights=[.72*inch])
    t.setStyle(TableStyle([("BACKGROUND",(0,0),(-1,-1),colors.HexColor("#e7f1f7")),("BOX",(0,0),(-1,-1),1,colors.HexColor("#36708a")),("VALIGN",(0,0),(-1,-1),"MIDDLE"),("ALIGN",(0,0),(-1,-1),"CENTER"),("LEFTPADDING",(0,0),(-1,-1),8),("RIGHTPADDING",(0,0),(-1,-1),8)]))
    return t
def footer(canvas,doc):
    canvas.saveState();canvas.setFont("Helvetica",8);canvas.setFillColor(colors.HexColor("#607080"))
    canvas.drawString(.65*inch,.4*inch,"SentinelMesh - defensive synthetic lab")
    canvas.drawRightString(7.85*inch,.4*inch,str(doc.page));canvas.restoreState()
story=[Spacer(1,1.15*inch),P("SentinelMesh","Cover"),P("How the defensive investigation platform works","Sub"),Spacer(1,.3*inch),P("A visual walkthrough of safe flow ingestion, explainable alerts, incident correlation, evidence-grounded reports, and analyst-approved simulations.","Sub"),Spacer(1,.45*inch),P("Local synthetic data only. No packet capture, external AI provider, shell access, or real network changes.","Sub"),PageBreak()]
story += [P("1. Purpose and system map","Heading1"),P("SentinelMesh turns prepared network-flow metadata into reviewable investigations. It validates each record, applies a small explainable ruleset, groups findings by source host, saves evidence in SQLite, and builds a report that separates observations from hypotheses."),Spacer(1,12)]
grid=Table([[node("CLI submits validated flow JSON"),node("Rules create evidence-linked findings"),node("Correlation stores incidents in SQLite")],[node("Dashboard reads the loopback API"),node("Investigator writes facts and hypotheses"),node("Analyst approval records a simulation only")]],colWidths=[2.1*inch,2.1*inch,2.1*inch])
grid.setStyle(TableStyle([("VALIGN",(0,0),(-1,-1),"MIDDLE"),("ALIGN",(0,0),(-1,-1),"CENTER"),("TOPPADDING",(0,0),(-1,-1),8),("BOTTOMPADDING",(0,0),(-1,-1),8)]))
story += [grid,Spacer(1,12),P("Why keep it local and deterministic? The project can run without API keys or third-party services. Each finding points to flow IDs and observed features. A score is only a triage signal; it is not proof of an attack.","Small"),P("2. Run the project","Heading1"),P("In PowerShell, from the SentinelMesh directory:")]
story += [Preformatted("py -3 -m venv .venv\n.\\.venv\\Scripts\\Activate.ps1\n.\\scripts\\run.ps1 analyze\n.\\scripts\\run.ps1 serve",styles["Code"]),P("Open http://127.0.0.1:8000. The analyze command validates the bundled sample and writes the SQLite database beneath data/generated/. The dashboard can rerun analysis on the bundled sample."),P("3. Understand a flow and finding","Heading1"),P("A flow record contains an ID, timestamp, source and destination addresses and ports, protocol, duration, packet count, byte count, and direction. The validator rejects malformed addresses, unsupported protocols, out-of-range counters, duplicate IDs, oversized files, and too many records."),P("The MVP rules flag outbound connections to commonly sensitive service ports, unusually high byte rates, and repeated multi-port activity. Each finding includes a rule name, severity, score, feature details, and evidence flow IDs."),PageBreak()]
story += [P("4. From findings to investigation","Heading1"),P("Correlation groups findings by source host. The incident keeps linked evidence IDs and the contributing findings, making a path back to observed flow records. The report helper reads only from a short allow-list of local data tools."),P("Reports separate observed facts from hypotheses. Suggested next steps ask an analyst to verify context. They do not execute shell commands or change network controls."),P("5. Human approval and audit","Heading1"),P("The dashboard can record a simulated mark-for-review or host-isolation decision. A named analyst is required. The audit record explicitly says simulated-only and network_changed=false. No firewall, endpoint, or network interface is connected to the project."),P("6. Folder map","Heading1")]
rows=[[P("<b>Path</b>","Small"),P("<b>Role</b>","Small")]]
for a,b in [("src/sentinelmesh/","Validation, detection, correlation, store, report, API, CLI"),("data/","Synthetic input; generated SQLite database is ignored"),("frontend/","Analyst dashboard"),("docs/","Architecture, safety, contract, walkthrough"),("scripts/","PowerShell runner and PDF generator"),("output/pdf/","This illustrated guide")]:
    rows.append([P(a,"Small"),P(b,"Small")])
t=Table(rows,colWidths=[1.7*inch,4.9*inch])
t.setStyle(TableStyle([("BACKGROUND",(0,0),(-1,0),colors.HexColor("#dceaf1")),("GRID",(0,0),(-1,-1),.4,colors.HexColor("#b7c7d1")),("VALIGN",(0,0),(-1,-1),"TOP"),("LEFTPADDING",(0,0),(-1,-1),8),("RIGHTPADDING",(0,0),(-1,-1),8),("TOPPADDING",(0,0),(-1,-1),6),("BOTTOMPADDING",(0,0),(-1,-1),6)]))
story += [t,Spacer(1,12),P("7. Evaluation and limitations","Heading1"),P("This starter has synthetic examples and heuristic rules, not a labeled benchmark or trained model. To add ML later, split captures by time/session to avoid leakage and report precision, recall, F1, and PR-AUC where appropriate. Measure parsing failures, false positives, and end-to-end latency."),P("PCAP parsing is intentionally not enabled. The local server has no authentication. Do not expose it beyond localhost or feed it sensitive traffic records. Findings are not proof of malicious activity. Use only benign, owned, or appropriately licensed lab data.")]
OUT.parent.mkdir(parents=True,exist_ok=True)
SimpleDocTemplate(str(OUT),pagesize=letter,rightMargin=.65*inch,leftMargin=.65*inch,topMargin=.65*inch,bottomMargin=.7*inch,title="SentinelMesh - How It Works",author="SentinelMesh Project").build(story,onFirstPage=footer,onLaterPages=footer)
print(OUT)
