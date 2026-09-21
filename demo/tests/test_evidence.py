import json
import tempfile
import unittest
from pathlib import Path
from sys import path

path.insert(0, str(Path(__file__).resolve().parents[1]))
from run import append, verify


class EvidenceTest(unittest.TestCase):
    def test_chain_detects_tampering(self):
        with tempfile.TemporaryDirectory() as temp:
            file = Path(temp) / "evidence.jsonl"
            append(file, {"event": "policy_decision", "allowed": True})
            append(file, {"event": "deployment_simulated"})
            self.assertEqual(verify(file), 2)
            lines = file.read_text().splitlines()
            record = json.loads(lines[0])
            record["allowed"] = False
            lines[0] = json.dumps(record)
            file.write_text("\n".join(lines) + "\n")
            with self.assertRaises(ValueError):
                verify(file)


if __name__ == "__main__":
    unittest.main()
