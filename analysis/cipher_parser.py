import re


class CipherParser:

    def __init__(self):

        self.patterns = {

            "RSA": [
                r"RSA"
            ],

            "ECDHE": [
                r"ECDHE"
            ],

            "ECDSA": [
                r"ECDSA"
            ],

            "ECDH": [
                r"\bECDH\b"
            ],

            "AES128": [
                r"AES_128",
                r"AES128"
            ],

            "AES256": [
                r"AES_256",
                r"AES256"
            ],

            "SHA1": [
                r"SHA1",
                r"SHA-1"
            ],

            "SHA256": [
                r"SHA256",
                r"SHA-256"
            ]
        }

    def parse(self, tshark_output):

        findings = set()

        for algorithm, patterns in self.patterns.items():

            for pattern in patterns:

                if re.search(
                    pattern,
                    tshark_output,
                    re.IGNORECASE
                ):

                    findings.add(
                        algorithm
                    )

                    break

        return sorted(
            list(findings)
        )

    def summary(self, algorithms):

        return {

            "total_algorithms":
                len(algorithms),

            "algorithms":
                algorithms
        }