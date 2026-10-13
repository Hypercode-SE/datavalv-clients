import datavalv_client


def test_package_imports_and_reports_version():
    assert datavalv_client.__version__ == "0.7.0"
