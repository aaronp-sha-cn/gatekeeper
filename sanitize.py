#!/usr/bin/env python3
"""Sanitize check for generated DOCX file."""
import sys
import os

def check_docx(filepath):
    """Basic validation of a DOCX file."""
    issues = []

    # Check file exists
    if not os.path.exists(filepath):
        print(f"[FAIL] File does not exist: {filepath}")
        return False

    # Check file size
    size = os.path.getsize(filepath)
    if size < 1024:
        issues.append(f"File too small: {size} bytes (expected at least 1KB)")
    print(f"[INFO] File size: {size / 1024:.2f} KB")

    # Check it's a valid ZIP (DOCX is a ZIP archive)
    with open(filepath, 'rb') as f:
        header = f.read(4)
        if header != b'PK\x03\x04':
            issues.append("Invalid DOCX header (not a valid ZIP/DOCX file)")
        else:
            print("[PASS] Valid DOCX/ZIP header")

    # Try to parse with zipfile
    import zipfile
    try:
        with zipfile.ZipFile(filepath, 'r') as z:
            names = z.namelist()
            required = ['[Content_Types].xml', 'word/document.xml']
            for req in required:
                if req in names:
                    print(f"[PASS] Found required component: {req}")
                else:
                    issues.append(f"Missing required component: {req}")

            # Check for document.xml content
            if 'word/document.xml' in names:
                content = z.read('word/document.xml').decode('utf-8', errors='replace')
                # Check for CJK characters (Chinese content)
                cjk_count = sum(1 for c in content if '\u4e00' <= c <= '\u9fff')
                print(f"[INFO] CJK characters found in document: {cjk_count}")
                if cjk_count < 10:
                    issues.append(f"Very few CJK characters ({cjk_count}), expected Chinese content")

                # Check for tables
                table_count = content.count('<w:tbl>')
                print(f"[INFO] Tables found: {table_count}")
                if table_count < 5:
                    issues.append(f"Expected at least 5 tables, found {table_count}")

                # Check for headers/footers
                if 'word/header' in ' '.join(names):
                    print("[PASS] Header found")
                else:
                    issues.append("No header found in document")

                if 'word/footer' in ' '.join(names):
                    print("[PASS] Footer found")
                else:
                    issues.append("No footer found in document")

    except zipfile.BadZipFile:
        issues.append("File is not a valid ZIP archive")
    except Exception as e:
        issues.append(f"Error reading ZIP: {e}")

    # Summary
    print()
    if issues:
        print(f"[RESULT] Found {len(issues)} issue(s):")
        for issue in issues:
            print(f"  - {issue}")
        return False
    else:
        print("[RESULT] All checks passed!")
        return True

if __name__ == '__main__':
    filepath = sys.argv[1] if len(sys.argv) > 1 else "/workspace/GateKeeper安全网关对比评估报告.docx"
    success = check_docx(filepath)
    sys.exit(0 if success else 1)
