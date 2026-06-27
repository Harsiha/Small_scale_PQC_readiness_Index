from datetime import datetime
from reportlab.platypus import (
    SimpleDocTemplate,
    Paragraph,
    Spacer
)
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.lib.enums import TA_CENTER
from reportlab.lib.colors import darkblue


class ReportGenerator:

    def __init__(self):

        self.styles = getSampleStyleSheet()

        self.title_style = self.styles["Heading1"]
        self.title_style.alignment = TA_CENTER
        self.title_style.textColor = darkblue

        self.heading = self.styles["Heading2"]

        self.normal = self.styles["BodyText"]

    def create_pdf_report(
        self,
        application_name,
        algorithms,
        A,
        V,
        M,
        C,
        H,
        pqcri,
        classification,
        filename="PQCRI_Report.pdf"
    ):

        recommendations = self.generate_recommendations(
            algorithms
        )

        report = {

            "report_timestamp":
                datetime.now().strftime("%Y-%m-%d %H:%M:%S"),

            "application":
                application_name,

            "algorithms_detected":
                algorithms,

            "parameter_scores":{

                "Asset Discovery (A)":A,
                "Vulnerability Assessment (V)":V,
                "Migration Readiness (M)":M,
                "Compliance (C)":C,
                "Application Handling Risk (H)":H

            },

            "PQCRI":
                round(pqcri,2),

            "classification":
                classification,

            "recommendations":
                recommendations

        }

        doc = SimpleDocTemplate(filename)

        story = []

        story.append(
            Paragraph(
                "Post-Quantum Cryptography Readiness Index",
                self.title_style
            )
        )

        story.append(
            Paragraph(
                "Assessment Report",
                self.heading
            )
        )

        story.append(Spacer(1,15))

        story.append(
            Paragraph(
                f"<b>Generated:</b> {report['report_timestamp']}",
                self.normal
            )
        )

        story.append(
            Paragraph(
                f"<b>Application:</b> {application_name}",
                self.normal
            )
        )

        story.append(Spacer(1,15))

        story.append(
            Paragraph(
                "Algorithms Detected",
                self.heading
            )
        )

        for key,value in algorithms.items():

            story.append(
                Paragraph(
                    f"<b>{key.replace('_',' ').title()}</b>: {value}",
                    self.normal
                )
            )

        story.append(Spacer(1,15))

        story.append(
            Paragraph(
                "Parameter Scores",
                self.heading
            )
        )

        for key,value in report["parameter_scores"].items():

            story.append(
                Paragraph(
                    f"<b>{key}</b>: {value}",
                    self.normal
                )
            )

        story.append(Spacer(1,15))

        story.append(
            Paragraph(
                f"<b>Overall PQCRI Score:</b> {pqcri}",
                self.normal
            )
        )

        story.append(
            Paragraph(
                f"<b>Classification:</b> {classification}",
                self.normal
            )
        )

        story.append(Spacer(1,15))

        story.append(
            Paragraph(
                "Recommendations",
                self.heading
            )
        )

        for item in recommendations:

            story.append(
                Paragraph(
                    "• " + item,
                    self.normal
                )
            )

        doc.build(story)

        return report

    def generate_recommendations(self, algorithms):

        recommendations = []

        values = " ".join(
            str(v).upper()
            for v in algorithms.values()
        )

        if "TLSV1.2" in values:

            recommendations.append(
                "Upgrade communication to TLS 1.3."
            )

        if "RSA" in values:

            recommendations.append(
                "Replace RSA with ML-KEM or Hybrid Key Exchange."
            )

        if "ECDHE" in values:

            recommendations.append(
                "Replace ECDHE with ML-KEM or Hybrid PQC."
            )

        if "ECDSA" in values:

            recommendations.append(
                "Replace ECDSA with ML-DSA."
            )

        if "SHA1" in values:

            recommendations.append(
                "Replace SHA-1 with SHA-384 or SHA-3."
            )

        if "AES-128" in values:

            recommendations.append(
                "AES-256-GCM is recommended for stronger quantum resistance."
            )

        if "ML-KEM" in values:

            recommendations.append(
                "ML-KEM provides quantum-safe key establishment."
            )

        if "ML-DSA" in values:

            recommendations.append(
                "ML-DSA provides quantum-safe digital signatures."
            )

        if "TLSV1.3" in values:

            recommendations.append(
                "TLS 1.3 is recommended for secure communication."
            )

        if len(recommendations) == 0:

            recommendations.append(
                "No major quantum-vulnerable algorithms detected."
            )

        recommendations.append(
            "Monitor NIST Post-Quantum Cryptography standardization updates."
        )

        recommendations.append(
            "Periodically reassess deployed cryptographic algorithms."
        )

        return recommendations