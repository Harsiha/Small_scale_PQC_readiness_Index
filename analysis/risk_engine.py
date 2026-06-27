class RiskEngine:

    def __init__(self):

        self.penalties = {
            # Handshake Algorithms
            "RSA": 20,
            "ECDH": 20,
            "ECDHE": 20,
            "ECDSA": 20,

            # PQC / Hybrid
            "ML-KEM": 0,
            "Kyber": 0,
            "ML-DSA": 0,
            "Dilithium": 0,
            "Falcon": 0,
            "SPHINCS": 0,

            # Data Exchange
            "AES-128-GCM": 5,
            "AES-256-GCM": 0,
            "ChaCha20": 0,

            "SHA1": 10,
            "SHA256": 0,
            "SHA384": 0,
            "SHA512": 0,
            "Poly1305": 0,
            "GCM": 0
        }
    def calculate_vulnerability_score(self, parsed_data):
        score = 100
        deductions = []
        handshake = parsed_data["handshake_algorithms"]
        data = parsed_data["data_exchange_algorithms"]
        values = [
            handshake.get("key_exchange"),
            handshake.get("signature"),
            data.get("encryption"),
            data.get("integrity"),
            data.get("hash")
        ]
        for value in values:
            if not value:
                continue
            matched = False
            for algorithm, penalty in self.penalties.items():
                if algorithm.lower() in value.lower():
                    score -= penalty
                    deductions.append({
                        "algorithm": algorithm,
                        "penalty": penalty
                    })
                    matched = True
                    break
            if not matched:
                deductions.append({
                    "algorithm": value,
                    "penalty": 0
                })
        score = max(score, 0)
        return {
            "vulnerability_score": score,
            "deductions": deductions
        }
    def classify_risk(self, score):
        if score >= 90:
            return "Excellent"
        elif score >= 80:
            return "Low Risk"
        elif score >= 70:
            return "Moderate Risk"
        elif score >= 60:
            return "Needs Improvement"
        elif score >= 40:
            return "High Risk"
        else:
            return "Critical Risk"