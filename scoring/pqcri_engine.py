class PQCRIEngine:

    def __init__(self):

        self.weights = {
            "A": 0.25,
            "V": 0.25,
            "M": 0.20,
            "C": 0.15,
            "H": 0.15
        }

    def asset_discovery_score(self, parsed_data):

        handshake = parsed_data["handshake_algorithms"]

        data = parsed_data["data_exchange_algorithms"]

        count = 0

        for value in handshake.values():

            if value:
                count += 1

        for value in data.values():

            if value:
                count += 1

        return min(count * 15, 100)

    def migration_readiness_score(self, parsed_data):

        handshake = parsed_data["handshake_algorithms"]

        score = 100

        key_exchange = str(
            handshake.get("key_exchange", "")
        )

        signature = str(
            handshake.get("signature", "")
        )
        if "RSA" in signature.upper():
            score -= 20
        if "ECDHE" in key_exchange.upper():
            score -= 10
        if "ECDH" in key_exchange.upper():
            score -= 10
        if "ECDSA" in signature.upper():
            score -= 10
        if "KYBER" in key_exchange.upper():
            score += 5
        if "ML-KEM" in key_exchange.upper():
            score += 5
        if "DILITHIUM" in signature.upper():
            score += 5
        if "ML-DSA" in signature.upper():
            score += 5
        return min(max(score, 0), 100)

    def compliance_score(self, parsed_data):
        score = 100
        handshake = parsed_data["handshake_algorithms"]
        data = parsed_data["data_exchange_algorithms"]
        signature = str(
            handshake.get("signature", "")
        )
        encryption = str(
            data.get("encryption", "")
        )
        hashing = str(
            data.get("hash", "")
        )
        if "RSA" in signature.upper():
            score -= 20
        if hashing.upper() == "SHA1":
            score -= 30
        if encryption.upper() == "AES-128-GCM":
            score -= 10
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