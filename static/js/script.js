/* ===========================================================
   PQCRI Dashboard Script
   =========================================================== */

const API_URL = "http://127.0.0.1:8000";

/* -----------------------------------------------------------
   Utility
------------------------------------------------------------*/

function setText(id, value) {
    const element = document.getElementById(id);
    if (element) {
        element.textContent = value ?? "-";
    }
}

/* -----------------------------------------------------------
   Loading Button
------------------------------------------------------------*/

function showLoading(isLoading) {

    const btn = document.getElementById("captureBtn");

    if (!btn) return;

    if (isLoading) {
        btn.disabled = true;
        btn.innerHTML = "Capturing...";
    } else {
        btn.disabled = false;
        btn.innerHTML = "Start Capture";
    }
}

/* -----------------------------------------------------------
   Start Capture + Analysis
------------------------------------------------------------*/

async function startAnalysis() {

    showLoading(true);

    try {

        // Capture packets
        await fetch(`${API_URL}/capture`);

        // Parse algorithms
        const analyzeResponse = await fetch(`${API_URL}/analyze`);
        const analyze = await analyzeResponse.json();

        // Risk
        const riskResponse = await fetch(`${API_URL}/risk`);
        const risk = await riskResponse.json();

        // PQCRI
        const pqcriResponse = await fetch(`${API_URL}/pqcri`);
        const pqcri = await pqcriResponse.json();

        updateDashboard(analyze, risk, pqcri);

        alert("PQCRI Analysis Completed Successfully.");

    }
    catch (err) {

        console.error(err);
        alert("Analysis failed.");

    }
    finally {

        showLoading(false);

    }
}

/* -----------------------------------------------------------
   Dashboard
------------------------------------------------------------*/

function updateDashboard(analyze, risk, pqcri) {

    // Handshake

    setText(
        "tlsVersion",
        analyze.handshake_algorithms.tls_version
    );

    setText(
        "cipherSuite",
        analyze.handshake_algorithms.cipher_suite
    );

    setText(
        "keyExchange",
        analyze.handshake_algorithms.key_exchange
    );

    setText(
        "signature",
        analyze.handshake_algorithms.signature
    );

    // Data Exchange

    setText(
        "encryption",
        analyze.data_exchange_algorithms.encryption
    );

    setText(
        "integrity",
        analyze.data_exchange_algorithms.integrity
    );

    setText(
        "hash",
        analyze.data_exchange_algorithms.hash
    );

    // Risk

    setText(
        "riskScore",
        risk.vulnerability_score
    );

    setText(
        "riskClass",
        risk.risk_level
    );

    // PQCRI

    setText(
        "pqcriScore",
        pqcri.PQCRI
    );

    setText(
        "pqcriClass",
        pqcri.classification
    );

    // Algorithm Badges

    createBadges(analyze);

}

/* -----------------------------------------------------------
   Algorithm Badges
------------------------------------------------------------*/

function createBadges(analyze) {

    const container =
        document.getElementById("algorithmBadges");

    if (!container) return;

    container.innerHTML = "";

    const algorithms = [

        analyze.handshake_algorithms.tls_version,

        analyze.handshake_algorithms.cipher_suite,

        analyze.handshake_algorithms.key_exchange,

        analyze.handshake_algorithms.signature,

        analyze.data_exchange_algorithms.encryption,

        analyze.data_exchange_algorithms.integrity,

        analyze.data_exchange_algorithms.hash

    ];

    algorithms.forEach(algo => {

        const badge = document.createElement("span");

        badge.className = "badge";

        badge.innerText = algo;

        container.appendChild(badge);

    });

}

/* -----------------------------------------------------------
   Download Report
------------------------------------------------------------*/

function downloadReport() {

    window.location.href = `${API_URL}/download-report`;

}

/* -----------------------------------------------------------
   Event Listeners
------------------------------------------------------------*/

document.addEventListener("DOMContentLoaded", () => {

    const captureBtn =
        document.getElementById("captureBtn");

    const downloadBtn =
        document.getElementById("downloadBtn");

    if (captureBtn)
        captureBtn.addEventListener(
            "click",
            startAnalysis
        );

    if (downloadBtn)
        downloadBtn.addEventListener(
            "click",
            downloadReport
        );

});