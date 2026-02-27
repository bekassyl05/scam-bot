# api/main.py
from fastapi import FastAPI, Request, Depends, Form, UploadFile, File, HTTPException
from fastapi.responses import HTMLResponse, JSONResponse, StreamingResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel
from typing import Optional, Any, Dict, List
import io, csv, json
import tldextract
from datetime import datetime
import tempfile, shutil, os

from api.models import Report, Feedback, SessionLocal, init_db

app = FastAPI(title="Scam Bot API (Stable)")

# --- Static & templates
templates = Jinja2Templates(directory="templates")
app.mount("/static", StaticFiles(directory="static"), name="static")

# DB init
@app.on_event("startup")
def on_startup():
    init_db()

# DB dependency
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

# Helper
def __extract_domain(url: Optional[str]) -> Optional[str]:
    try:
        if not url:
            return None
        dd = tldextract.extract(url)
        return dd.registered_domain or None
    except Exception:
        return None

# Pydantic input for POST
class ReportIn(BaseModel):
    url: Optional[str] = None
    reported_by: Optional[str] = None
    source: Optional[str] = None
    file_type: Optional[str] = None
    file_name: Optional[str] = None
    ocr_text: Optional[str] = None
    analysis_details: Optional[dict] = None
    confidence: Optional[float] = 0.0

    # new optional fields (renderer / LLM / screenshot)
    render_info: Optional[dict] = None
    llm_summary: Optional[str] = None
    screenshot: Optional[str] = None

@app.get("/report", response_class=HTMLResponse)
def view_reports_root(request: Request, date: Optional[str] = None, min_conf: Optional[int] = 0, source: Optional[str] = None, db = Depends(get_db)):
    q = db.query(Report)
    if date:
        try:
            q = q.filter(Report.created_at >= date)
        except Exception:
            pass
    if min_conf:
        try:
            mc = float(int(min_conf) / 100.0)
            q = q.filter(Report.confidence >= mc)
        except Exception:
            pass
    if source:
        q = q.filter(Report.source == source)
    reports = q.order_by(Report.created_at.desc()).limit(1000).all()

    def _maybe_unescape_string(s: str) -> str:
        if not isinstance(s, str):
            return s
        if "\\u" not in s:
            return s
        try:
            return s.encode("utf-8").decode("unicode_escape")
        except Exception:
            return s

    def _recurse_unescape(obj):
        if isinstance(obj, str):
            return _maybe_unescape_string(obj)
        if isinstance(obj, dict):
            out = {}
            for k, v in obj.items():
                out[k] = _recurse_unescape(v)
            return out
        if isinstance(obj, list):
            return [_recurse_unescape(i) for i in obj]
        return obj

    reports_data: List[Dict[str, Any]] = []
    for r in reports:
        analysis: Dict[str, Any] = {}
        try:
            raw = r.analysis_details
            if raw is None:
                analysis = {}
            elif isinstance(raw, dict):
                analysis = raw
            elif isinstance(raw, str):
                try:
                    analysis = json.loads(raw)
                except Exception:
                    try:
                        import ast
                        candidate = ast.literal_eval(raw)
                        analysis = candidate if isinstance(candidate, dict) else {"raw": raw}
                    except Exception:
                        analysis = {"raw": raw}
            else:
                try:
                    analysis_json_text = json.dumps(raw, default=str)
                    analysis = json.loads(analysis_json_text)
                except Exception:
                    analysis = {"raw": str(raw)}
        except Exception:
            analysis = {}

        try:
            analysis = _recurse_unescape(analysis)
        except Exception:
            pass

        first = None
        try:
            cand_list = None
            if isinstance(analysis, dict):
                cand_list = analysis.get("analyses") if isinstance(analysis.get("analyses"), list) else None
            if cand_list and len(cand_list) > 0:
                first = cand_list[0]
            else:
                if isinstance(analysis, dict) and (
                        "url" in analysis or "final_url" in analysis or "confidence" in analysis):
                    first = analysis
        except Exception:
            first = None

        reasons: List[str] = []
        final_url: Optional[str] = None
        candidates: List[str] = []
        page_info: Dict[str, Any] = {}
        raw_render_info: Dict[str, Any] = {}
        llm_summary: Optional[str] = None
        screenshot: Optional[str] = None

        try:
            if first and isinstance(first, dict):
                reasons = first.get("reasons") or []
                final_url = (first.get("analysis_details") or {}).get("final_url") or first.get("final_url") or first.get("url")
                if isinstance(analysis.get("analyses"), list):
                    candidates = [a.get("url") or a.get("file_name") or "" for a in analysis.get("analyses")]
                else:
                    candidates = []
                page_info = (first.get("analysis_details") or {}).get("page", {}) or {}
                raw_render_info = (first.get("analysis_details") or {}).get("render") or analysis.get("render") or {}
                llm_summary = (first.get("analysis_details") or {}).get("llm_summary") or analysis.get(
                    "llm_summary") or raw_render_info.get("llm_summary")
                screenshot = raw_render_info.get("screenshot") or (first.get("analysis_details") or {}).get(
                    "screenshot") or analysis.get("screenshot")
            else:
                reasons = analysis.get("reasons") or []
                final_url = analysis.get("final_url") or analysis.get("url")
                candidates = [a.get("url") or a.get("file_name") or "" for a in (analysis.get("analyses") or [])]
                page_info = (analysis.get("analysis_details") or {}).get("page", {}) or analysis.get("page", {}) or {}
                raw_render_info = analysis.get("render") or (analysis.get("analysis_details") or {}).get("render") or {}
                llm_summary = analysis.get("llm_summary") or raw_render_info.get("llm_summary")
                screenshot = raw_render_info.get("screenshot") or analysis.get("screenshot")
        except Exception:
            pass

        render_info: Dict[str, Any] = {}
        try:
            if isinstance(raw_render_info, dict):
                title = raw_render_info.get("title") or raw_render_info.get("short_title") or raw_render_info.get("meta_title")
                excerpt = raw_render_info.get("excerpt")
                if not excerpt:
                    text = raw_render_info.get("text") or raw_render_info.get("main_text") or ""
                    excerpt = (text[:800].rsplit(" ", 1)[0]) if text else ""
                top_images = raw_render_info.get("top_images") or raw_render_info.get("images") or []

                warnings = raw_render_info.get("warnings") or raw_render_info.get("fetch_warnings") or []
                status_code = raw_render_info.get("status_code")
                render_info = {
                    "title": title,
                    "text_excerpt": excerpt,
                    "top_images": top_images,
                    "warnings": warnings,
                    "status_code": status_code
                }
            else:
                render_info = {}
        except Exception:
            render_info = {}

        created_at_iso = None
        try:
            if isinstance(r.created_at, datetime):
                created_at_iso = r.created_at.isoformat()
            elif r.created_at:
                created_at_iso = str(r.created_at)
        except Exception:
            created_at_iso = None

        reports_data.append({
            "id": r.id,
            "url": r.url,
            "file_name": r.file_name,
            "domain": r.domain,
            "confidence": float(r.confidence) if r.confidence is not None else 0.0,
            "source": r.source,
            "reported_by": r.reported_by,
            "created_at": created_at_iso,
            "analysis": analysis,
            "analysis_pretty": json.dumps(analysis, ensure_ascii=False, indent=2),
            "reasons": reasons,
            "final_url": final_url,
            "candidates": candidates,
            "page_info": page_info,
            "render_info": render_info,
            "llm_summary": llm_summary,
            "screenshot": screenshot,
        })

    return templates.TemplateResponse("admin_reports.html", {
        "request": request,
        "reports": reports_data
    })

@app.get("/reports")
def redirect_reports():
    return RedirectResponse(url="/report")

@app.post("/report")
def post_report(payload: ReportIn, db = Depends(get_db)):
    domain = None
    if payload.url:
        domain = __extract_domain(payload.url)
    elif payload.analysis_details:
        try:
            analyses = payload.analysis_details.get("analyses")
            if analyses and len(analyses) > 0:
                domain = analyses[0].get("domain")
        except Exception:
            domain = None

    analysis_details: Dict[str, Any] = {}
    if payload.analysis_details:
        try:
            if isinstance(payload.analysis_details, dict):
                analysis_details = json.loads(json.dumps(payload.analysis_details, default=str, ensure_ascii=False))
            else:
                try:
                    analysis_details = json.loads(str(payload.analysis_details))
                except Exception:
                    analysis_details = {"raw": str(payload.analysis_details)}
        except Exception:
            analysis_details = {"raw": str(payload.analysis_details)}

    if payload.render_info:
        if "render" not in analysis_details:
            analysis_details["render"] = payload.render_info
        else:
            try:
                if isinstance(analysis_details["render"], dict):
                    for k, v in (payload.render_info or {}).items():
                        if k not in analysis_details["render"]:
                            analysis_details["render"][k] = v
                else:
                    analysis_details["render"] = payload.render_info
            except Exception:
                analysis_details["render"] = payload.render_info

    if payload.llm_summary:
        if "llm_summary" not in analysis_details:
            analysis_details["llm_summary"] = payload.llm_summary
        else:
            analysis_details.setdefault("llm_summary_extra", payload.llm_summary)

    if payload.screenshot:
        if "screenshot" not in analysis_details:
            analysis_details["screenshot"] = payload.screenshot
        else:
            analysis_details.setdefault("screenshot_extra", payload.screenshot)

    report = Report(
        url=payload.url,
        domain=domain,
        reported_by=payload.reported_by,
        source=payload.source,
        file_type=payload.file_type,
        file_name=payload.file_name,
        ocr_text=payload.ocr_text,
        analysis_details=analysis_details,
        confidence=payload.confidence or 0.0
    )
    db.add(report)
    db.commit()
    db.refresh(report)
    return {"status": "ok", "id": report.id}

@app.post("/false_positive")
def post_false_positive(payload: ReportIn, db = Depends(get_db)):
    try:
        payload_dict = payload.dict()
        payload_dict['source'] = 'false_positive'

        r_in = ReportIn(**payload_dict)
        return post_report(r_in, db)
    except Exception as ex:
        raise HTTPException(status_code=500, detail=f"Failed to save false_positive: {ex}")

class FeedbackIn(BaseModel):
    report_id: Optional[int] = None
    user_id: Optional[str] = None
    username: Optional[str] = None
    message: Optional[str] = None

@app.post("/feedback")
def post_feedback(payload: FeedbackIn, db = Depends(get_db)):
    try:
        fb = Feedback(
            report_id=payload.report_id,
            user_id=payload.user_id,
            username=payload.username,
            message=payload.message
        )
        db.add(fb)
        db.commit()
        db.refresh(fb)
        return {"status": "ok", "id": fb.id}
    except Exception as ex:
        raise HTTPException(status_code=500, detail=f"Failed to save feedback: {ex}")

@app.get("/report/test", response_class=HTMLResponse)
def report_test_form(request: Request):
    return templates.TemplateResponse("manual_test.html", {"request": request})

@app.post("/report/test")
def report_test_submit(
    url: Optional[str] = Form(None),
    reported_by: Optional[str] = Form(None),
    source: Optional[str] = Form(None),
    confidence: str = Form("0"),
    file: UploadFile = File(None),
    db = Depends(get_db)
):
    try:
        conf = float(confidence)
    except Exception:
        conf = 0.0

    file_name = None
    file_type = None
    tmp_path = None

    if file is not None:
        suffix = os.path.splitext(file.filename)[1] or ""
        tmp = tempfile.NamedTemporaryFile(delete=False, suffix=suffix)
        tmp_path = tmp.name
        tmp.close()
        try:
            with open(tmp_path, "wb") as f:
                shutil.copyfileobj(file.file, f)
            file_name = file.filename
            file_type = suffix.lower().lstrip(".")
        except Exception:
            try:
                if tmp_path and os.path.exists(tmp_path):
                    os.unlink(tmp_path)
            except Exception:
                pass

    report = Report(
        url=url,
        domain=__extract_domain(url) if url else None,
        reported_by=reported_by,
        source=source,
        file_type=file_type,
        file_name=file_name,
        confidence=conf
    )
    db.add(report)
    db.commit()
    db.refresh(report)

    if tmp_path and os.path.exists(tmp_path):
        try:
            os.unlink(tmp_path)
        except Exception:
            pass

    return RedirectResponse(url="/report", status_code=302)

@app.get("/reports/export")
def export_reports(format: str = "csv", db = Depends(get_db)):
    reports = db.query(Report).order_by(Report.created_at.desc()).all()
    if format == "json":
        arr = []
        for r in reports:
            try:
                analysis = r.analysis_details if r.analysis_details is not None else {}
                analysis = json.loads(json.dumps(analysis, default=str, ensure_ascii=False))
            except Exception:
                analysis = {"raw": str(r.analysis_details)}
            arr.append({
                "id": r.id,
                "url": r.url,
                "file_name": r.file_name,
                "domain": r.domain,
                "confidence": r.confidence,
                "source": r.source,
                "reported_by": r.reported_by,
                "created_at": r.created_at.isoformat() if r.created_at else None,
                "analysis_details": analysis
            })
        return JSONResponse(content=arr)
    def iter_csv():
        output = io.StringIO()
        writer = csv.writer(output)
        writer.writerow(["id","url","file_name","domain","confidence","source","reported_by","created_at"])
        yield output.getvalue(); output.seek(0); output.truncate(0)
        for r in reports:
            writer.writerow([r.id, r.url or "", r.file_name or "", r.domain or "", r.confidence, r.source or "", r.reported_by or "", r.created_at.isoformat() if r.created_at else ""])
            yield output.getvalue(); output.seek(0); output.truncate(0)
    headers = {"Content-Disposition": "attachment; filename=reports.csv"}
    return StreamingResponse(iter_csv(), media_type="text/csv", headers=headers)
