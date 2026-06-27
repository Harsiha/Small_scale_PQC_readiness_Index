import subprocess

class TsharkCapture:
    def __init__(self):
        self.interface = "4"
        self.duration = 20
        self.tshark_path = (
            r"C:\Program Files\Wireshark\tshark.exe"
        )

    def capture_tls(self):
        command = [
            self.tshark_path,
            "-i",
            self.interface,
            "-a",
            f"duration:{self.duration}",
            "-Y",
            "tls.handshake",
            "-V"
        ]

        result = subprocess.run(
            command,
            capture_output=True,
            text=True
        )

        # Save capture
        with open(
            "capture_data.txt",
            "w",
            errors="ignore"
        ) as file:
            file.write(
                result.stdout
            )
        return result.stdout