"""Loopback-only dashboard API; no execution or network-control tools."""
from http.server import BaseHTTPRequestHandler,ThreadingHTTPServer
import json
from urllib.parse import unquote,urlparse
from sentinelmesh.assistant import investigate,propose_simulated_action
from sentinelmesh.config import ROOT,DB_PATH,SAMPLE_FLOWS
from sentinelmesh.ingest import parse_flow
from sentinelmesh.pipeline import run_pipeline
from sentinelmesh.store import Store

FRONTEND=ROOT/"frontend"/"index.html"
class Handler(BaseHTTPRequestHandler):
    def reply(self,value,status=200,content_type="application/json; charset=utf-8"):
        body=value if isinstance(value,bytes) else json.dumps(value,ensure_ascii=True).encode()
        self.send_response(status);self.send_header("Content-Type",content_type)
        self.send_header("X-Content-Type-Options","nosniff");self.send_header("Cache-Control","no-store")
        self.send_header("Content-Length",str(len(body)));self.end_headers();self.wfile.write(body)
    def do_GET(self):
        path=urlparse(self.path).path
        if path=="/":
            self.reply(FRONTEND.read_bytes(),content_type="text/html; charset=utf-8");return
        if path=="/api/health":self.reply({"status":"ok","mode":"synthetic-defense-lab"});return
        if path=="/sample":self.reply(SAMPLE_FLOWS.read_bytes(),content_type="application/json");return
        with Store(DB_PATH) as store:
            if path=="/api/summary":self.reply(store.summary())
            elif path=="/api/flows":self.reply(store.list_flows())
            elif path=="/api/findings":self.reply(store.list_findings())
            elif path=="/api/incidents":self.reply(store.list_incidents())
            elif path.startswith("/api/incidents/"):
                item=store.get_incident(unquote(path.rsplit("/",1)[-1]))
                self.reply(item or {"error":"incident not found"},200 if item else 404)
            else:self.reply({"error":"not found"},404)
    def do_POST(self):
        path=urlparse(self.path).path
        try:
            length=int(self.headers.get("Content-Length","0"))
            if length > 2_000_000: self.reply({"error":"request exceeds 2 MB limit"},413);return
            body=json.loads(self.rfile.read(length) or b"{}")
            if path=="/api/analyze":
                if not isinstance(body,list) or len(body)>20_000:raise ValueError("body must be a flow array with at most 20,000 records")
                flows=[parse_flow(row) for row in body]
                with Store(DB_PATH) as store:self.reply(run_pipeline(flows,store),201)
                return
            if not isinstance(body,dict):raise ValueError("request body must be a JSON object")
            with Store(DB_PATH) as store:
                if path.startswith("/api/incidents/") and path.endswith("/investigate"):
                    incident_id=unquote(path.split("/")[-2]);self.reply(investigate(store,incident_id),201);return
                if path.startswith("/api/incidents/") and path.endswith("/simulate"):
                    incident_id=unquote(path.split("/")[-2])
                    item=propose_simulated_action(store,incident_id,str(body.get("action","")),body.get("approved_by"))
                    self.reply(item,201);return
            self.reply({"error":"not found"},404)
        except KeyError as exc:self.reply({"error":str(exc)},404)
        except PermissionError as exc:self.reply({"error":str(exc)},403)
        except (ValueError,TypeError,json.JSONDecodeError) as exc:self.reply({"error":str(exc)},400)
    def log_message(self,fmt,*args):print(args[0]%args[1:])

def serve(host="127.0.0.1",port=8000):
    if host not in {"127.0.0.1","localhost"}:raise ValueError("Dashboard binds to loopback only")
    server=ThreadingHTTPServer((host,port),Handler)
    print(f"SentinelMesh dashboard: http://{host}:{port} (synthetic lab only)")
    try:server.serve_forever()
    except KeyboardInterrupt:print("\nStopping SentinelMesh.")
    finally:server.server_close()
