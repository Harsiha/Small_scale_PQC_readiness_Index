from datetime import datetime


class ReportGenerator:

    def generate_report(
        self,
        application_name,
        algorithms,
        A,
        V,
        M,
        C,
        H,
        pqcri,
        classification
    ):

        report = {

            "report_timestamp":
                str(datetime.now()),

            "application":
                application_name,

            "algorithms_detected":
                algorithms,

            "parameter_scores": {

                "Asset Discovery":
                    A,

                "Vulnerability":
                    V,

                "Migration Readiness":
                    M,

                "Compliance":
                    C,

                "HNDL Risk":
                    H
            },

            "PQCRI":
                pqcri,

            "classification":
                classification,

            "recommendations":
                self.generate_recommendations(
                    algorithms
                )
        }

        return report

    def generate_recommendations(
        self,
        algorithms
    ):

        recommendations = []

        if "RSA" in algorithms:

            recommendations.append(
                "Replace RSA with ML-KEM or a hybrid PQC key exchange."
            )

        if "ECDHE" in algorithms:

            recommendations.append(
                "Replace ECDHE with PQC-enabled key exchange mechanisms."
            )

        if "ECDSA" in algorithms:

            recommendations.append(
                "Consider migrating to PQC digital signature algorithms."
            )

        if "SHA1" in algorithms:

            recommendations.append(
                "Replace SHA-1 with SHA-256 or SHA-3."
            )

        if "AES128" in algorithms:

            recommendations.append(
                "Upgrade AES-128 to AES-256."
            )

        if len(recommendations) == 0:

            recommendations.append(
                "No immediate quantum-vulnerable algorithms detected."
            )

        return recommendations