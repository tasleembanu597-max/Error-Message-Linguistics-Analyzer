import pytest
import os
from tests.mock_server import MockServerThread
from emla.cli import create_parser, main

@pytest.fixture(scope="module")
def mock_server():
    server = MockServerThread(port=8890)
    server.start()
    yield server
    server.stop()

def test_cli_parser_defaults():
    parser = create_parser()
    args = parser.parse_args(["--target", "http://localhost:8080"])
    assert args.target == "http://localhost:8080"
    assert args.single_url is False
    assert args.max_depth == 3
    assert args.max_pages == 50
    assert args.output == "report.json"
    assert args.verbose is False

def test_cli_parser_custom_flags():
    parser = create_parser()
    args = parser.parse_args([
        "-t", "http://localhost:9000",
        "--single-url",
        "--max-depth", "5",
        "--max-pages", "100",
        "-o", "custom.json",
        "-v"
    ])
    assert args.target == "http://localhost:9000"
    assert args.single_url is True
    assert args.max_depth == 5
    assert args.max_pages == 100
    assert args.output == "custom.json"
    assert args.verbose is True

def test_cli_execution_end_to_end(mock_server, tmp_path):
    report_file = tmp_path / "cli_test_report.json"
    exit_code = main([
        "--target", f"{mock_server.base_url}/about",
        "--single-url",
        "--output", str(report_file)
    ])

    assert exit_code == 0
    assert report_file.exists()
    assert report_file.stat().st_size > 0
