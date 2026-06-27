from fastapi import FastAPI, Request
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse
from fastapi.middleware.cors import CORSMiddleware
from fastapi.templating import Jinja2Templates
from capture.tshark_capture import TsharkCapture
from analysis.cipher_parser import CipherParser
from analysis.risk_engine import RiskEngine
from scoring.pqcri_engine import PQCRIEngine
from reports.report_generator import ReportGenerator

app = FastAPI(
    title="PQCRI Analyzer",
    description="Post-Quantum Cryptography Readiness Index Assessment Framework",
    version="1.0.0"
)
app.mount("/static", StaticFiles(directory="static"), name="static")
templates = Jinja2Templates(directory="templates")


# CORS Configuration
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

capture_engine = TsharkCapture()
parser = CipherParser()
risk_engine = RiskEngine()
pqcri_engine = PQCRIEngine()
report_generator = ReportGenerator()
# =====================================================
# HOME
# =====================================================

@app.get("/")
def home():
    return {
        "project": "PQCRI Analyzer",
        "status": "Running",
        "version": "1.0.0"
    }


# =====================================================
# HEALTH CHECK
# =====================================================

@app.get("/health")
def health():
    return {
        "server": "online",
        "api": "working"
    }


# =====================================================
# CAPTURE ENDPOINT
# (Will be connected to tshark later)
# =====================================================

@app.get("/capture")
def capture():

    data = capture_engine.capture_tls()
    return {
        "message":
        "Traffic captured",
        "size":
        len(data)
    }


# =====================================================
# ANALYSIS ENDPOINT
# (Will be connected to cipher parser later)
# =====================================================

@app.get("/analyze")
def analyze():
    with open(
        "capture_data.txt",
        "r",
        errors="ignore"
    ) as file:
        data = file.read()

    parsed_data = parser.parse(data)

    return {

        "handshake_algorithms":
            parsed_data["handshake_algorithms"],

        "data_exchange_algorithms":
            parsed_data["data_exchange_algorithms"]

    }

@app.get("/risk")
def risk_analysis():
    # Read captured data
    with open(
        "capture_data.txt",
        "r",
        errors="ignore"
    ) as file:
        data = file.read()
    # Extract algorithms
    parsed_data = parser.parse(data)

    result = risk_engine.calculate_vulnerability_score(
        parsed_data
    )
    # Add risk category
    risk_level = risk_engine.classify_risk(
        result["vulnerability_score"]
    )

    return {
        "handshake_algorithms":
        parsed_data["handshake_algorithms"],

        "data_exchange_algorithms":
        parsed_data["data_exchange_algorithms"],
        "vulnerability_score":
            result["vulnerability_score"],
        "risk_level":
            risk_level,
        "details":
            result["deductions"]
    }


@app.get("/pqcri")
def calculate_pqcri():
    # Read captured packet data
    with open(
        "capture_data.txt",
        "r",
        errors="ignore"
    ) as file:
        data = file.read()
    # Extract algorithms
    parsed_data = parser.parse(data)
    # Parameter A
    A = pqcri_engine.asset_discovery_score(
        parsed_data
    )
    # Parameter V
    risk_result = risk_engine.calculate_vulnerability_score(
        parsed_data
    )
    V = risk_result[
        "vulnerability_score"
    ]
    # Parameter M
    M = pqcri_engine.migration_readiness_score(
        parsed_data
    )
    # Parameter C
    C = pqcri_engine.compliance_score(
        parsed_data
    )
    # Parameter H
    H = pqcri_engine.hndl_risk_score(
        "social"
    )
    # Final PQCRI
    pqcri = pqcri_engine.calculate_pqcri(
        A,
        V,
        M,
        C,
        H
    )
    classification = pqcri_engine.classify_pqcri(
        pqcri
    )
    return {
        "handshake_algorithms":
        parsed_data["handshake_algorithms"],

        "data_exchange_algorithms":
        parsed_data["data_exchange_algorithms"],
        "parameters":{
            "A":A,
            "V":V,
            "M":M,
            "C":C,
            "H":H
        },

        "PQCRI":pqcri,
        "classification":classification
    }

@app.get("/scan")
def scan():
    return {
        "message": "PQCRI scan not implemented yet"
    }


# =====================================================
# SIMPLE DASHBOARD
# =====================================================

@app.get("/dashboard")
def dashboard(request: Request):
    return templates.TemplateResponse(
        "index.html",
        {
            "request": request
        }
    )
    
@app.get("/download-report")
def download_report():

    with open("capture_data.txt", "r", errors="ignore") as file:
        data = file.read()

    parsed_data = parser.parse(data)

    # Calculate scores
    A = pqcri_engine.asset_discovery_score(parsed_data)

    risk_result = risk_engine.calculate_vulnerability_score(parsed_data)
    V = risk_result["vulnerability_score"]

    M = pqcri_engine.migration_readiness_score(parsed_data)

    C = pqcri_engine.compliance_score(parsed_data)

    H = pqcri_engine.hndl_risk_score("social")

    pqcri = pqcri_engine.calculate_pqcri(A, V, M, C, H)

    classification = pqcri_engine.classify_pqcri(pqcri)

    # Create the algorithms dictionary expected by ReportGenerator
    algorithms = {
        "tls_version": parsed_data["handshake_algorithms"]["tls_version"],
        "cipher_suite": parsed_data["handshake_algorithms"]["cipher_suite"],
        "key_exchange": parsed_data["handshake_algorithms"]["key_exchange"],
        "digital_signature": parsed_data["handshake_algorithms"]["signature"],
        "encryption": parsed_data["data_exchange_algorithms"]["encryption"],
        "integrity": parsed_data["data_exchange_algorithms"]["integrity"],
        "hash": parsed_data["data_exchange_algorithms"]["hash"],
    }

    # Generate the PDF
    report_generator.create_pdf_report(
        application_name="https://example.com",
        algorithms=algorithms,
        A=A,
        V=V,
        M=M,
        C=C,
        H=H,
        pqcri=pqcri,
        classification=classification
    )

    return FileResponse(
        "PQCRI_Report.pdf",
        media_type="application/pdf",
        filename="PQCRI_Report.pdf"
    )