from fastapi import FastAPI
from fastapi.responses import HTMLResponse
from fastapi.middleware.cors import CORSMiddleware
from capture.tshark_capture import TsharkCapture
from analysis.cipher_parser import CipherParser
from analysis.risk_engine import RiskEngine
from scoring.pqcri_engine import PQCRIEngine

app = FastAPI(
    title="PQCRI Analyzer",
    description="Post-Quantum Cryptography Readiness Index Assessment Framework",
    version="1.0.0"
)

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

    algorithms = parser.parse(data)

    vulnerability = (
        risk_engine.calculate_vulnerability_score(
            algorithms
        )
    )
    return {
        "algorithms":
        algorithms,
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
    algorithms = parser.parse(
        data
    )
    # Calculate vulnerability
    result = risk_engine.calculate_vulnerability_score(
        algorithms
    )
    # Add risk category
    risk_level = risk_engine.classify_risk(
        result["vulnerability_score"]
    )

    return {
        "detected_algorithms": algorithms,
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
    algorithms = parser.parse(
        data
    )
    # Parameter A
    A = pqcri_engine.asset_discovery_score(
        algorithms
    )
    # Parameter V
    risk_result = risk_engine.calculate_vulnerability_score(
        algorithms
    )
    V = risk_result[
        "vulnerability_score"
    ]
    # Parameter M
    M = pqcri_engine.migration_readiness_score(
        algorithms
    )
    # Parameter C
    C = pqcri_engine.compliance_score(
        algorithms
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
        "algorithms":algorithms,
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

@app.get("/dashboard", response_class=HTMLResponse)
def dashboard():

    html = """
    <!DOCTYPE html>
    <html>
    <head>
        <title>PQCRI Dashboard</title>
        <style>
            body{
                font-family: Arial;
                margin:40px;
                background:#f4f4f4;
            }

            .card{
                background:white;
                padding:20px;
                border-radius:10px;
                box-shadow:0 0 10px rgba(0,0,0,0.1);
                width:600px;
            }

            h1{
                color:#333;
            }

            p{
                font-size:18px;
            }
        </style>
    </head>
    <body>

        <div class="card">

            <h1>PQCRI Analyzer</h1>

            <p>
                Post-Quantum Cryptography
                Readiness Assessment Framework
            </p>

            <hr>

            <p>Status: Running</p>

            <p>
                Available APIs:
            </p>

            <ul>
                <li>/</li>
                <li>/health</li>
                <li>/capture</li>
                <li>/analyze</li>
                <li>/scan</li>
            </ul>

        </div>

    </body>
    </html>
    """

    return html