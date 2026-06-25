class PQCRIEngine:

    def __init__(self):

        self.weights = {
            "A": 0.25,
            "V": 0.25,
            "M": 0.20,
            "C": 0.15,
            "H": 0.15
        }

    def asset_discovery_score(self, algorithms):

        score = min(
            len(algorithms) * 20,
            100
        )

        return score

    def migration_readiness_score(self, algorithms):

        score = 80

        if "RSA" in algorithms:
            score -= 20

        if "ECDHE" in algorithms:
            score -= 10

        if "ECDSA" in algorithms:
            score -= 10

        return max(score, 0)

    def compliance_score(self, algorithms):

        score = 100

        if "SHA1" in algorithms:
            score -= 30

        if "RSA" in algorithms:
            score -= 20

        return max(score, 0)

    def hndl_risk_score(
        self,
        app_type="social"
    ):

        risk_map = {

            "banking": 40,
            "healthcare": 30,
            "social": 70,
            "utility": 90,
            "education": 80
        }

        return risk_map.get(
            app_type,
            70
        )

    def calculate_pqcri(
        self,
        A,
        V,
        M,
        C,
        H
    ):

        score = (

            self.weights["A"] * A +

            self.weights["V"] * V +

            self.weights["M"] * M +

            self.weights["C"] * C +

            self.weights["H"] * H
        )

        return round(score, 2)

    def classify_pqcri(
        self,
        score
    ):

        if score >= 90:
            return "Excellent"

        elif score >= 80:
            return "Good"

        elif score >= 70:
            return "Satisfactory"

        elif score >= 60:
            return "Needs Improvement"

        elif score >= 40:
            return "High Risk"
        else:
            return "Critical Risk"