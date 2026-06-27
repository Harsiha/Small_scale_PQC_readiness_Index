import re


class CipherParser:

    def __init__(self):


        self.data_patterns = {

            "AES-128-GCM": [
                r"TLS_AES_128_GCM_SHA256"
            ],

            "AES-256-GCM": [
                r"TLS_AES_256_GCM_SHA384"
            ],

            "ChaCha20-Poly1305": [
                r"TLS_CHACHA20_POLY1305_SHA256"
            ]
        }

        self.cipher_mapping = {

            "TLS_AES_128_GCM_SHA256": {

                "encryption": "AES-128-GCM",

                "integrity": "GCM",

                "hash": "SHA256"
            },

            "TLS_AES_256_GCM_SHA384": {

                "encryption": "AES-256-GCM",

                "integrity": "GCM",

                "hash": "SHA384"
            },

            "TLS_CHACHA20_POLY1305_SHA256": {

                "encryption": "ChaCha20",

                "integrity": "Poly1305",

                "hash": "SHA256"
            }
        }
        
        self.key_exchange_map = {

        "x25519": "ECDHE",

        "x448": "ECDHE",

        "secp256r1": "ECDHE",

        "secp384r1": "ECDHE",

        "secp521r1": "ECDHE",

        "mlkem512": "ML-KEM",

        "mlkem768": "ML-KEM",

        "mlkem1024": "ML-KEM",

        "x25519mlkem768": "Hybrid",

        "x25519kyber768": "Hybrid",

        "kyber512": "Kyber",

        "kyber768": "Kyber",

        "kyber1024": "Kyber",

        "rsa": "RSA",

        "ecdh": "ECDH",

        "ecdhe": "ECDHE"
        }

        self.signature_map = {

        "rsa": "RSA",

        "rsa-pss": "RSA",

        "ecdsa": "ECDSA",

        "mldsa44": "ML-DSA",

        "mldsa65": "ML-DSA",

        "mldsa87": "ML-DSA",

        "dilithium2": "Dilithium",

        "dilithium3": "Dilithium",

        "dilithium5": "Dilithium",

        "falcon512": "Falcon",

        "falcon1024": "Falcon",

        "sphincs": "SPHINCS+"
        }
        self.group_map = {

        "23": "secp256r1",

        "24": "secp384r1",

        "25": "secp521r1",

        "29": "X25519",

        "30": "X448",

        "31": "brainpoolP256r1",

        "32": "brainpoolP384r1",

        "33": "brainpoolP512r1",

        "34": "GC256A",

        "35": "GC256B",

        "36": "X25519",

        "4588": "ML-KEM-512",

        "4589": "ML-KEM-768",

        "4590": "ML-KEM-1024"
    }
    def normalize_algorithm(self, value, mapping):

        if not value:
            return None

        value = value.lower().replace("-", "").replace("_", "").replace(" ", "")

        for key, canonical in mapping.items():

            if key in value:

                return canonical

        return value
    
    def parse_handshake(self, tshark_output):

        handshake = {

            "tls_version": None,

            "cipher_suite": None,

            "key_exchange": None,

            "signature": None
        }

        version = re.search(
            r"TLSv1\.[23]",
            tshark_output,
            re.IGNORECASE
        )

        if version:
            handshake["tls_version"] = version.group()

        cipher = re.search(
            r"Cipher Suite:\s*([A-Za-z0-9_\-]+)",
            tshark_output
        )

        if cipher:
            handshake["cipher_suite"] = cipher.group(1)

        key_share = re.search(
            r"Key Share.*?:\s*([^\n]+)",
            tshark_output
        )
        cipher_suite = handshake["cipher_suite"]

        if cipher_suite:

            if cipher_suite.startswith("TLS_AES_") or \
            cipher_suite.startswith("TLS_CHACHA20_"):

                handshake["tls_version"] = "TLSv1.3"

            elif "_WITH_" in cipher_suite:

                handshake["tls_version"] = "TLSv1.2"
        if not key_share:

            key_share = re.search(
                r"Supported Group.*?:\s*([^\n]+)",
                tshark_output
            )   

        if key_share:

            raw_group = key_share.group(1).strip()

            # If tshark returns a numeric group ID, convert it
            raw_group = self.group_map.get(raw_group, raw_group)

            # Normalize to canonical algorithm names
            handshake["key_exchange"] = self.normalize_algorithm(
                raw_group,
                self.key_exchange_map
            )
            

        signature = re.search(
            r"Signature Algorithm:\s*([^\n]+)",
            tshark_output
        )

        if signature:

            raw_signature = signature.group(1).strip()

            handshake["signature"] = self.normalize_algorithm(

                raw_signature,

                self.signature_map

            )

        return handshake

    def parse_data_exchange(self, handshake):

        cipher_suite = handshake.get("cipher_suite")

        if cipher_suite in self.cipher_mapping:

            return self.cipher_mapping[cipher_suite]

        return {

            "encryption": "Unknown",

            "integrity": "Unknown",

            "hash": "Unknown"
        }

    def parse(self, tshark_output):

        handshake = self.parse_handshake(
            tshark_output
        )

        data_exchange = self.parse_data_exchange(
            handshake
        )

        return {

            "handshake_algorithms": handshake,

            "data_exchange_algorithms": data_exchange
        }

    def summary(self, parsed_data):

        handshake = parsed_data["handshake_algorithms"]

        data = parsed_data["data_exchange_algorithms"]

        return {

            "handshake_algorithms": handshake,

            "data_exchange_algorithms": data
        }