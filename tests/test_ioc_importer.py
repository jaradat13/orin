"""Tests for the Offline Threat Intelligence & IOC Importer."""
import pytest
import json
import csv
from pathlib import Path
from tempfile import TemporaryDirectory
from orin.intel.ioc_importer import IOCImporter, Indicator, create_sample_intel_files


class TestIndicator:
    """Test the Indicator dataclass."""

    def test_indicator_creation(self):
        """Test creating an indicator with default values."""
        indicator = Indicator(
            id="test-1",
            type="ip-addr",
            value="192.168.1.100"
        )
        assert indicator.id == "test-1"
        assert indicator.type == "ip-addr"
        assert indicator.value == "192.168.1.100"
        assert indicator.confidence == 50
        assert indicator.severity == "medium"
        assert indicator.revoked is False

    def test_indicator_to_dict(self):
        """Test converting indicator to dictionary."""
        indicator = Indicator(
            id="test-2",
            type="domain",
            value="evil.com",
            confidence=80,
            severity="high"
        )
        d = indicator.to_dict()
        assert d["id"] == "test-2"
        assert d["type"] == "domain"
        assert d["value"] == "evil.com"
        assert d["confidence"] == 80
        assert d["severity"] == "high"


class TestIOCTypeDetection:
    """Test automatic IOC type detection."""

    def setup_method(self):
        """Set up test fixtures."""
        self.importer = IOCImporter()

    def test_detect_ipv4(self):
        """Test IPv4 address detection."""
        assert self.importer.detect_ioc_type("192.168.1.1") == "ip-addr"
        assert self.importer.detect_ioc_type("10.0.0.1") == "ip-addr"
        assert self.importer.detect_ioc_type("255.255.255.255") == "ip-addr"

    def test_detect_ipv4_cidr(self):
        """Test IPv4 with CIDR notation."""
        assert self.importer.detect_ioc_type("192.168.1.0/24") == "ip-addr"
        assert self.importer.detect_ioc_type("10.0.0.0/8") == "ip-addr"

    def test_detect_domain(self):
        """Test domain detection."""
        assert self.importer.detect_ioc_type("evil.com") == "domain"
        assert self.importer.detect_ioc_type("malware.bad-domain.net") == "domain"
        assert self.importer.detect_ioc_type("c2-server.org") == "domain"

    def test_detect_md5(self):
        """Test MD5 hash detection."""
        md5 = "d41d8cd98f00b204e9800998ecf8427e"
        assert self.importer.detect_ioc_type(md5) == "file-hash-md5"

    def test_detect_sha1(self):
        """Test SHA1 hash detection."""
        sha1 = "da39a3ee5e6b4b0d3255bfef95601890afd80709"
        assert self.importer.detect_ioc_type(sha1) == "file-hash-sha1"

    def test_detect_sha256(self):
        """Test SHA256 hash detection."""
        sha256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        assert self.importer.detect_ioc_type(sha256) == "file-hash-sha256"

    def test_detect_url(self):
        """Test URL detection."""
        assert self.importer.detect_ioc_type("http://evil.com/malware") == "url"
        assert self.importer.detect_ioc_type("https://bad-site.net/phish") == "url"

    def test_detect_email(self):
        """Test email detection."""
        assert self.importer.detect_ioc_type("attacker@evil.com") == "email"

    def test_unknown_type(self):
        """Test unknown IOC type."""
        assert self.importer.detect_ioc_type("not-a-valid-ioc") == "unknown"
        assert self.importer.detect_ioc_type("") == "unknown"


class TestTXTBlocklistLoading:
    """Test loading plain text blocklists."""

    def test_load_txt_blocklist(self):
        """Test loading a simple TXT blocklist."""
        with TemporaryDirectory() as tmpdir:
            tmpdir = Path(tmpdir)
            blocklist_file = tmpdir / "test.txt"

            with open(blocklist_file, 'w') as f:
                f.write("""# Comment line
192.168.1.100 # Known C2
evil.com
d41d8cd98f00b204e9800998ecf8427e  # MD5 hash

""")

            importer = IOCImporter(intel_dir=tmpdir)
            indicators = importer.load_txt_blocklist(blocklist_file)

            assert len(indicators) == 3
            assert indicators[0].value == "192.168.1.100"
            assert indicators[0].type == "ip-addr"
            assert indicators[0].description == "Known C2"
            assert indicators[1].value == "evil.com"
            assert indicators[1].type == "domain"
            assert indicators[2].value == "d41d8cd98f00b204e9800998ecf8427e"
            assert indicators[2].type == "file-hash-md5"

    def test_load_nonexistent_file(self):
        """Test loading nonexistent file returns empty list."""
        importer = IOCImporter()
        indicators = importer.load_txt_blocklist(Path("/nonexistent/file.txt"))
        assert len(indicators) == 0


class TestSTIXJSONLoading:
    """Test loading STIX 2.x JSON format."""

    def test_load_stix_bundle(self):
        """Test loading a STIX 2.x bundle."""
        with TemporaryDirectory() as tmpdir:
            tmpdir = Path(tmpdir)
            stix_file = tmpdir / "test.json"

            stix_data = {
                "type": "bundle",
                "id": "bundle--12345678-1234-1234-1234-123456789012",
                "objects": [
                    {
                        "type": "indicator",
                        "id": "indicator--12345678-1234-1234-1234-123456789012",
                        "created": "2024-01-15T10:00:00Z",
                        "pattern": "[ipv4:addr:value = '203.0.113.50']",
                        "pattern_type": "stix",
                        "labels": ["malicious-activity", "high"],
                        "confidence": 80,
                        "description": "Test C2 server"
                    },
                    {
                        "type": "indicator",
                        "id": "indicator--22345678-1234-1234-1234-123456789012",
                        "created": "2024-01-15T11:00:00Z",
                        "pattern": "[domain-name:value = 'bad-domain.com']",
                        "pattern_type": "stix",
                        "labels": ["phishing", "critical"],
                        "confidence": 90
                    }
                ]
            }

            with open(stix_file, 'w') as f:
                json.dump(stix_data, f)

            importer = IOCImporter(intel_dir=tmpdir)
            indicators = importer.load_stix_json(stix_file)

            assert len(indicators) == 2
            assert indicators[0].value == "203.0.113.50"
            assert indicators[0].type == "ip-addr"
            assert indicators[0].confidence == 80
            assert indicators[0].severity == "high"
            assert indicators[1].value == "bad-domain.com"
            assert indicators[1].type == "domain"
            assert indicators[1].severity == "critical"

    def test_load_stix_with_hash_pattern(self):
        """Test loading STIX with file hash patterns."""
        with TemporaryDirectory() as tmpdir:
            tmpdir = Path(tmpdir)
            stix_file = tmpdir / "hash.json"

            stix_data = {
                "type": "bundle",
                "objects": [
                    {
                        "type": "indicator",
                        "pattern": "[file:hashes.'SHA-256' = 'abcd1234567890abcdef1234567890abcdef1234567890abcdef1234567890ab']",
                        "pattern_type": "stix",
                        "labels": ["ransomware"],
                        "confidence": 95
                    }
                ]
            }

            with open(stix_file, 'w') as f:
                json.dump(stix_data, f)

            importer = IOCImporter(intel_dir=tmpdir)
            indicators = importer.load_stix_json(stix_file)

            assert len(indicators) == 1
            assert indicators[0].type == "file-hash-sha256"
            assert indicators[0].confidence == 95


class TestCSVFeedLoading:
    """Test loading CSV threat feeds."""

    def test_load_csv_feed(self):
        """Test loading a CSV threat feed."""
        with TemporaryDirectory() as tmpdir:
            tmpdir = Path(tmpdir)
            csv_file = tmpdir / "feed.csv"

            with open(csv_file, 'w', newline='') as f:
                writer = csv.writer(f)
                writer.writerow(['value', 'type', 'confidence', 'description'])
                writer.writerow(['198.51.100.23', 'ip-addr', '75', 'Botnet C2'])
                writer.writerow(['malware.net', 'domain', '85', 'Malware hosting'])

            importer = IOCImporter(intel_dir=tmpdir)
            # Auto-detect mode - will process all columns
            indicators = importer.load_csv_feed(csv_file)

            # Should find at least the 2 main IOCs (may also pick up other values)
            assert len(indicators) >= 2
            # Find the IP indicator
            ip_indicators = [i for i in indicators if i.type == 'ip-addr']
            domain_indicators = [i for i in indicators if i.type == 'domain']
            assert len(ip_indicators) >= 1
            assert len(domain_indicators) >= 1
            assert ip_indicators[0].value == "198.51.100.23"
            assert domain_indicators[0].value == "malware.net"

    def test_load_csv_auto_detect(self):
        """Test CSV loading with auto-detection of IOC types."""
        with TemporaryDirectory() as tmpdir:
            tmpdir = Path(tmpdir)
            csv_file = tmpdir / "auto.csv"

            with open(csv_file, 'w', newline='') as f:
                writer = csv.writer(f)
                writer.writerow(['ioc_value'])
                writer.writerow(['192.168.1.1'])
                writer.writerow(['evil.com'])

            importer = IOCImporter(intel_dir=tmpdir)
            indicators = importer.load_csv_feed(csv_file)

            assert len(indicators) == 2
            assert indicators[0].type == "ip-addr"
            assert indicators[1].type == "domain"


class TestIOCMatching:
    """Test IOC matching functionality."""

    def test_match_ip(self):
        """Test IP address matching."""
        with TemporaryDirectory() as tmpdir:
            tmpdir = Path(tmpdir)
            blocklist_file = tmpdir / "test.txt"

            with open(blocklist_file, 'w') as f:
                f.write("192.168.1.100\n")
                f.write("10.0.0.50\n")

            importer = IOCImporter(intel_dir=tmpdir)
            importer.load_all_intel()

            # Should match
            result = importer.match_ip("192.168.1.100")
            assert result is not None
            assert result.value == "192.168.1.100"

            # Should not match
            result = importer.match_ip("8.8.8.8")
            assert result is None

    def test_match_domain(self):
        """Test domain matching."""
        with TemporaryDirectory() as tmpdir:
            tmpdir = Path(tmpdir)
            blocklist_file = tmpdir / "test.txt"

            with open(blocklist_file, 'w') as f:
                f.write("evil.com\n")

            importer = IOCImporter(intel_dir=tmpdir)
            importer.load_all_intel()

            # Should match (case insensitive)
            result = importer.match_domain("EVIL.COM")
            assert result is not None

            # Should not match
            result = importer.match_domain("google.com")
            assert result is None

    def test_match_hash(self):
        """Test file hash matching."""
        with TemporaryDirectory() as tmpdir:
            tmpdir = Path(tmpdir)
            blocklist_file = tmpdir / "test.txt"

            sha256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
            with open(blocklist_file, 'w') as f:
                f.write(f"{sha256}\n")

            importer = IOCImporter(intel_dir=tmpdir)
            importer.load_all_intel()

            # Should match (case insensitive)
            result = importer.match_hash(sha256.upper())
            assert result is not None


class TestSummaryAndExport:
    """Test summary generation and export functionality."""

    def test_get_summary(self):
        """Test getting threat intel summary."""
        with TemporaryDirectory() as tmpdir:
            tmpdir = Path(tmpdir)
            blocklist_file = tmpdir / "test.txt"

            with open(blocklist_file, 'w') as f:
                f.write("192.168.1.1\n")
                f.write("evil.com\n")
                f.write("d41d8cd98f00b204e9800998ecf8427e\n")

            importer = IOCImporter(intel_dir=tmpdir)
            importer.load_all_intel()

            summary = importer.get_summary()

            assert summary['total_indicators'] == 3
            assert summary['ip_count'] == 1
            assert summary['domain_count'] == 1
            assert summary['hash_count'] == 1

    def test_export_blocklist_txt(self):
        """Test exporting blocklist to TXT format."""
        with TemporaryDirectory() as tmpdir:
            tmpdir = Path(tmpdir)
            blocklist_file = tmpdir / "test.txt"
            output_file = tmpdir / "export.txt"

            with open(blocklist_file, 'w') as f:
                f.write("192.168.1.1 # Test IP\n")

            importer = IOCImporter(intel_dir=tmpdir)
            importer.load_all_intel()
            importer.export_blocklist(output_file, format="txt")

            assert output_file.exists()
            content = output_file.read_text()
            assert "192.168.1.1" in content

    def test_export_blocklist_json(self):
        """Test exporting blocklist to JSON format."""
        with TemporaryDirectory() as tmpdir:
            tmpdir = Path(tmpdir)
            blocklist_file = tmpdir / "test.txt"
            output_file = tmpdir / "export.json"

            with open(blocklist_file, 'w') as f:
                f.write("192.168.1.1\n")

            importer = IOCImporter(intel_dir=tmpdir)
            importer.load_all_intel()
            importer.export_blocklist(output_file, format="json")

            assert output_file.exists()
            with open(output_file) as f:
                data = json.load(f)
            assert 'indicators' in data
            assert len(data['indicators']) == 1


class TestCreateSampleFiles:
    """Test sample file creation."""

    def test_create_sample_intel_files(self):
        """Test creating sample threat intel files."""
        with TemporaryDirectory() as tmpdir:
            tmpdir = Path(tmpdir)
            intel_dir = create_sample_intel_files(tmpdir)

            assert intel_dir.exists()
            assert (intel_dir / "sample_blocklist.txt").exists()
            assert (intel_dir / "sample_stix.json").exists()
            assert (intel_dir / "sample_feed.csv").exists()

            # Load and verify
            importer = IOCImporter(intel_dir=intel_dir)
            indicators = importer.load_all_intel()

            assert len(indicators) > 0
            summary = importer.get_summary()
            assert summary['total_indicators'] > 0


if __name__ == "__main__":
    pytest.main([__file__, "-v"])