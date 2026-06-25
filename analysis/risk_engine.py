class RiskEngine:
    def __init__(self):
        self.penalties = {
            # Quantum vulnerable asymmetric crypto
            "RSA":20,
            "ECC":20,
            "ECDH":20,
            "ECDHE":20,
            "ECDSA":20,
            # Weak hashing
            "SHA1":10,
            # Symmetric algorithms
            "AES128":5,
            # Quantum safer
            "AES256":0,
            "SHA256":0
        }
    def calculate_vulnerability_score(
            self,
            algorithms
    ):
        score = 100
        deductions = []
        # remove duplicates
        algorithms = set(algorithms)

        for algorithm in algorithms:
            penalty = self.penalties.get(
                algorithm,
                0
            )
            score -= penalty

            deductions.append({
                "algorithm": algorithm,
                "penalty": penalty
            })
        score = max(score,0)

        return {
            "vulnerability_score": score,
            "deductions": deductions
        }

    def classify_risk(
            self,
            score
    ):
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