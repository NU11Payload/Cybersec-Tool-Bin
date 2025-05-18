import json
import os
import sys  # Added for sys.prefix checks


def analyze_report(report_path):
    """
    CREATOR: Alana E / 0xEALANA
    Parses an ANY.RUN JSON report and extracts key information.
    Plans to expand are underway to have data fed into other tools
    Args:
        report_path (str): The path to the JSON report file.
    """
    try:
        with open(report_path, "r", encoding="utf-8") as f:
            report_data = json.load(f)
    except FileNotFoundError:
        print(f"Error: File not found at {report_path}")
        return
    except json.JSONDecodeError:
        print(f"Error: Could not decode JSON from {report_path}")
        return
    except Exception as e:
        print(f"An unexpected error occurred while reading/parsing the file: {e}")
        return

    analysis = report_data.get("analysis", {})

    print("--- General Analysis Information ---")
    print(f"UUID: {analysis.get('uuid')}")
    print(f"Permanent URL: {analysis.get('permanentUrl')}")
    creation_text = analysis.get("creationText")
    if creation_text:
        print(f"Analysis Creation Date: {creation_text}")

    verdict_info = analysis.get("scores", {}).get("verdict", {})
    if verdict_info:
        print(f"Verdict: {verdict_info.get('threatLevelText')}")
        print(f"Threat Score: {verdict_info.get('score')}")

    print("\n--- Main Object Analyzed ---")
    main_object = analysis.get("content", {}).get("mainObject", {})
    if main_object:
        print(f"Type: {main_object.get('type')}")
        print(f"URL/File: {main_object.get('url', main_object.get('filename', 'N/A'))}")
        hashes = main_object.get("hashes", {})
        if hashes:
            print(f"  MD5: {hashes.get('md5')}")
            print(f"  SHA1: {hashes.get('sha1')}")
            print(f"  SHA256: {hashes.get('sha256')}")

    print("\n--- Sample of Extracted Artifacts ---")
    screenshots = analysis.get("content", {}).get("screenshots", [])
    if screenshots:
        print("\nScreenshots (first 3):")
        for i, screenshot in enumerate(screenshots[:3]):
            print(f"  Screenshot {i+1} URL: {screenshot.get('permanentUrl')}")

    dumps = analysis.get("content", {}).get("dumps", [])
    if dumps:
        print("\nMemory Dumps:")
        for dump in dumps:
            print(
                f"  Process: {dump.get('processName')}, Size: {dump.get('size')}, Address: {dump.get('address')}"
            )
            print(f"    Dump URL: {dump.get('permanentUrl')}")

    processes_info = report_data.get("processes", [])
    if processes_info:
        print("\n--- Monitored Processes (Sample) ---")
        for i, process in enumerate(processes_info[:5]):
            print(f"  PID: {process.get('pid')}, Image: {process.get('image')}")
            verdict = process.get("scores", {}).get("verdict", {})
            print(f"    Process Verdict: {verdict.get('threatLevelText')}")
            if i == 4 and len(processes_info) > 5:
                print("    ... and more processes (output truncated for this example)")
                break

    print("\n--- Network Connection Summary (Counters) ---")
    network_counters = report_data.get("counters", {}).get("network", {})
    if network_counters:
        print(f"  HTTP Connections: {network_counters.get('http')}")
        print(f"  Total Connections: {network_counters.get('connections')}")
        print(f"  DNS Lookups: {network_counters.get('dns')}")
        print(f"  Network Threats Detected: {network_counters.get('threats')}")

    print("\n--- File Activity Summary (Counters) ---")
    file_counters = report_data.get("counters", {}).get("files", {})
    if file_counters:
        print(f"  Suspicious Files: {file_counters.get('suspicious')}")
        print(f"  Malicious Files: {file_counters.get('malicious')}")


if __name__ == "__main__":
    # IMPORTANT: Replace this with the actual path to your JSON file
    report_file_path = (
        "c:\\Users\\alana\\Downloads\\2bd91e59-e974-4948-83a7-0352ac8476c4.summary.json"
    )

    # Check for virtual environment (conceptual)
    if not (
        os.getenv("VIRTUAL_ENV")
        or hasattr(sys, "real_prefix")
        or sys.prefix != sys.base_prefix
    ):
        print("INFO: Consider running this script in a Python virtual environment.")

    analyze_report(report_file_path)

    print(
        "\nThis script demonstrates parsing the JSON report to extract specific data points."
    )
    print("You could extend this to:")
    print("- Feed IOCs (hashes, URLs, IPs) into other security tools.")
    print(
        "- Perform statistical analysis on data from multiple reports (e.g., common TTPs)."
    )
    print("- Generate custom reports in different formats (e.g., CSV).")
    print("- Search for specific patterns or keywords within the report's text fields.")

