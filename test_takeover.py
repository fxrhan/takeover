"""
Unit tests for takeover subdomain takeover scanner.
Run with: pytest test_takeover.py -v
"""

import pytest
import os
import json
import tempfile
from pathlib import Path
from takeover import (
    validate_domain,
    percent,
    checkurl,
    load_services,
    get_default_services,
    check_cname_match,
    ScanConfig,
)


class TestDomainValidation:
    """Tests for domain validation functionality."""
    
    def test_valid_domain(self):
        """Test valid domain formats."""
        assert validate_domain("example.com") == True
        assert validate_domain("subdomain.example.com") == True
        assert validate_domain("test-domain.example.co.uk") == True
        assert validate_domain("localhost") == True
    
    def test_invalid_domain(self):
        """Test invalid domain formats."""
        assert validate_domain("") == False
        assert validate_domain(None) == False
        assert validate_domain("invalid domain with spaces") == False
        assert validate_domain("http://") == False
        assert validate_domain("-.example.com") == False
    
    def test_domain_with_protocol(self):
        """Test domains with protocol prefixes."""
        assert validate_domain("http://example.com") == True
        assert validate_domain("https://example.com") == True


class TestURLChecking:
    """Tests for URL normalization."""
    
    def test_url_with_http(self):
        """Test URL with http protocol."""
        assert checkurl("http://example.com") == "http://example.com"
    
    def test_url_with_https(self):
        """Test URL with https protocol."""
        assert checkurl("https://example.com") == "https://example.com"
    
    def test_url_without_protocol(self):
        """Test URL without protocol."""
        assert checkurl("example.com") == "http://example.com"
    
    def test_url_with_path(self):
        """Test URL with path component."""
        result = checkurl("example.com/path")
        assert result.startswith("http://")


class TestPercentCalculation:
    """Tests for percentage calculation."""
    
    def test_normal_percentage(self):
        """Test normal percentage calculation."""
        assert percent(50, 100) == 50.0
        assert percent(1, 4) == 25.0
        assert percent(3, 4) == 75.0
    
    def test_zero_total(self):
        """Test percentage with zero total."""
        assert percent(10, 0) == 0
    
    def test_zero_current(self):
        """Test percentage with zero current."""
        assert percent(0, 100) == 0.0


class TestServiceLoading:
    """Tests for service signature loading."""
    
    def test_get_default_services(self):
        """Test getting default services."""
        services = get_default_services()
        assert isinstance(services, dict)
        assert len(services) > 0
        assert "AWS/S3" in services
        assert "Github" in services
        assert "Netlify" in services
    
    def test_load_services_from_json(self):
        """Test loading services from JSON file."""
        # Create temporary JSON file
        test_services = {
            "services": {
                "TestService": {
                    "error": "test error pattern",
                    "cname": ["test.example.com"]
                }
            }
        }
        
        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
            json.dump(test_services, f)
            temp_file = f.name
        
        try:
            services = load_services(temp_file)
            assert "TestService" in services
            assert services["TestService"]["error"] == "test error pattern"
        finally:
            os.unlink(temp_file)
    
    def test_load_services_fallback(self):
        """Test fallback to default services when file doesn't exist."""
        services = load_services("nonexistent_file.json")
        assert isinstance(services, dict)
        assert len(services) > 0


class TestCNAMEMatching:
    """Tests for CNAME matching functionality."""
    
    def test_cname_match_found(self):
        """Test when CNAME matches."""
        cnames = ["example.herokuapp.com", "other.com"]
        service_cnames = ["herokuapp.com"]
        assert check_cname_match(cnames, service_cnames) == True
    
    def test_cname_match_not_found(self):
        """Test when CNAME doesn't match."""
        cnames = ["example.github.io"]
        service_cnames = ["herokuapp.com", "netlify.app"]
        assert check_cname_match(cnames, service_cnames) == False
    
    def test_cname_empty_lists(self):
        """Test with empty lists."""
        assert check_cname_match([], []) == False
        assert check_cname_match(["example.com"], []) == False
        assert check_cname_match([], ["example.com"]) == False


class TestScanConfig:
    """Tests for ScanConfig dataclass."""
    
    def test_default_config(self):
        """Test default configuration values."""
        config = ScanConfig()
        assert config.threads == 1
        assert config.verbose == False
        assert config.verify_ssl == False
        assert config.check_dns == True
        assert config.rate_limit == 0
        assert config.domains == []
    
    def test_custom_config(self):
        """Test custom configuration values."""
        config = ScanConfig(
            domain="example.com",
            threads=10,
            verbose=True,
            rate_limit=5.0
        )
        assert config.domain == "example.com"
        assert config.threads == 10
        assert config.verbose == True
        assert config.rate_limit == 5.0


class TestFileOperations:
    """Tests for file reading operations."""
    
    def test_read_domain_list(self):
        """Test reading domains from file."""
        from takeover import readfile
        
        # Create temporary file with domains
        domains = ["example.com", "test.com", "subdomain.example.org"]
        with tempfile.NamedTemporaryFile(mode='w', suffix='.txt', delete=False) as f:
            for domain in domains:
                f.write(domain + "\n")
            temp_file = f.name
        
        try:
            result = readfile(temp_file)
            assert len(result) == 3
            assert "example.com" in result
            assert "test.com" in result
        finally:
            os.unlink(temp_file)
    
    def test_read_domain_list_with_invalid(self):
        """Test reading domains with some invalid entries."""
        from takeover import readfile
        
        # Create file with mix of valid and invalid domains
        with tempfile.NamedTemporaryFile(mode='w', suffix='.txt', delete=False) as f:
            f.write("example.com\n")
            f.write("invalid domain with spaces\n")
            f.write("test.com\n")
            temp_file = f.name
        
        try:
            result = readfile(temp_file)
            # Should only include valid domains
            assert "example.com" in result
            assert "test.com" in result
            assert "invalid domain with spaces" not in result
        finally:
            os.unlink(temp_file)


class TestOutputFormats:
    """Tests for output file generation."""
    
    def test_json_output(self):
        """Test JSON output generation."""
        from takeover import savejson
        
        test_data = [
            ("example.com", "Heroku", "no-such-app"),
            ("test.com", "Github", "404 not found")
        ]
        
        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
            temp_file = f.name
        
        try:
            savejson(temp_file, test_data, False, None)
            
            with open(temp_file, 'r') as f:
                data = json.load(f)
            
            assert "domains" in data
            assert "example.com" in data["domains"]
            assert data["domains"]["example.com"]["service"] == "Heroku"
        finally:
            os.unlink(temp_file)
    
    def test_csv_output(self):
        """Test CSV output generation."""
        from takeover import savecsv
        import csv
        
        test_data = [
            ("example.com", "Heroku", "no-such-app"),
            ("test.com", "Github", "404 not found")
        ]
        
        with tempfile.NamedTemporaryFile(mode='w', suffix='.csv', delete=False) as f:
            temp_file = f.name
        
        try:
            savecsv(temp_file, test_data, False, None)
            
            with open(temp_file, 'r', newline='') as f:
                reader = csv.reader(f)
                rows = list(reader)
            
            assert len(rows) == 3  # Header + 2 data rows
            assert rows[0] == ['Domain', 'Service', 'Error Pattern']
            assert rows[1][0] == 'example.com'
        finally:
            os.unlink(temp_file)
    
    def test_html_output(self):
        """Test HTML output generation."""
        from takeover import savehtml
        
        test_data = [
            ("example.com", "Heroku", "no-such-app"),
        ]
        
        with tempfile.NamedTemporaryFile(mode='w', suffix='.html', delete=False) as f:
            temp_file = f.name
        
        try:
            savehtml(temp_file, test_data, False, None)
            
            with open(temp_file, 'r', encoding='utf-8') as f:
                content = f.read()
            
            assert "<!DOCTYPE html>" in content
            assert "example.com" in content
            assert "Heroku" in content
        finally:
            os.unlink(temp_file)


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
