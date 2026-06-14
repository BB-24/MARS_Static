import os
import json
import datetime
from fpdf import FPDF
from pubsub import pub

class PDFReport(FPDF):
    """Custom FPDF Class to handle headers and footers."""
    def header(self):
        self.set_font("helvetica", "B", 15)
        self.cell(0, 10, "MARS - Static Analysis Report", border=False, ln=True, align="C")
        self.set_font("helvetica", "I", 10)
        self.cell(0, 10, f"Generated: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", border=False, ln=True, align="C")
        self.ln(10)

    def footer(self):
        self.set_y(-15)
        self.set_font("helvetica", "I", 8)
        self.cell(0, 10, f"Page {self.page_no()}/{{nb}}", align="C")

class ReportGenerator:
    def __init__(self, config):
        """Initializes the reporting module with configured paths."""
        self.reports_dir = config.get('system', {}).get('reports_dir', './workspace/reports')
        os.makedirs(self.reports_dir, exist_ok=True)

    def generate_reports(self, metadata, package_data, static_data):
        """Generates both JSON and PDF reports based on pipeline data."""
        pub.sendMessage("gui.log", msg="\n[*] --- Starting Reporting Module ---")
        
        analysis_id = metadata.get("Analysis ID", f"MARS_UNKNOWN_{datetime.datetime.now().strftime('%H%M%S')}")
        base_filename = os.path.join(self.reports_dir, f"{analysis_id}_Report")

        # Compile the unified data structure
        compiled_report = {
            "Analysis_Summary": metadata,
            "Package_Extraction": package_data,
            "Static_Analysis_Results": static_data
        }

        # 1. Generate JSON
        json_path = f"{base_filename}.json"
        with open(json_path, 'w') as json_file:
            json.dump(compiled_report, json_file, indent=4)
        pub.sendMessage("gui.log", msg=f"  [+] JSON Report Saved: {json_path}")

        # 2. Generate PDF
        pdf_path = f"{base_filename}.pdf"
        self._build_pdf(compiled_report, pdf_path)
        pub.sendMessage("gui.log", msg=f"  [+] PDF Report Saved: {pdf_path}")

    def _build_pdf(self, data, output_path):
        """Dynamically constructs the PDF document."""
        pdf = PDFReport()
        pdf.add_page()
        pdf.set_auto_page_break(auto=True, margin=15)

        # Helper function to write dictionary data to PDF
        def write_dict_to_pdf(pdf_obj, dictionary, indent=""):
            for key, value in dictionary.items():
                if isinstance(value, dict):
                    pdf_obj.set_font("helvetica", "B", 10)
                    pdf_obj.cell(0, 6, f"{indent}- {key}:", ln=True)
                    write_dict_to_pdf(pdf_obj, value, indent + "    ")
                elif isinstance(value, list):
                    pdf_obj.set_font("helvetica", "B", 10)
                    pdf_obj.cell(0, 6, f"{indent}- {key}:", ln=True)
                    pdf_obj.set_font("helvetica", "", 10)
                    for item in value:
                        pdf_obj.cell(0, 6, f"{indent}    * {item}", ln=True)
                else:
                    pdf_obj.set_font("helvetica", "B", 10)
                    # Convert to string to avoid encoding issues
                    clean_key = str(key).encode('latin-1', 'replace').decode('latin-1')
                    clean_val = str(value).encode('latin-1', 'replace').decode('latin-1')
                    
                    # Highlight Critical Findings in Red
                    if "[CRITICAL]" in clean_val or "[WARNING]" in clean_val or "Hits:" in clean_key and value != 0:
                        pdf_obj.set_text_color(200, 0, 0)
                        
                    pdf_obj.cell(60, 6, f"{indent}{clean_key}:", ln=False)
                    pdf_obj.set_font("helvetica", "", 10)
                    pdf_obj.multi_cell(0, 6, f"{clean_val}")
                    pdf_obj.set_text_color(0, 0, 0) # Reset to black

        # Section 1: Analysis Summary (Metadata)
        pdf.set_font("helvetica", "B", 12)
        pdf.set_fill_color(200, 220, 255)
        pdf.cell(0, 8, "1. File Intake Summary", ln=True, fill=True)
        pdf.ln(2)
        write_dict_to_pdf(pdf, data.get("Analysis_Summary", {}))
        pdf.ln(5)

        # Section 2: Package Data (If Applicable)
        pkg_data = data.get("Package_Extraction")
        if pkg_data:
            pdf.set_font("helvetica", "B", 12)
            pdf.cell(0, 8, "2. Package & Archive Unpacking", ln=True, fill=True)
            pdf.ln(2)
            pdf.set_font("helvetica", "", 10)
            pdf.cell(0, 6, f"Total Extracted Files: {len(pkg_data)}", ln=True)
            flagged = [f for f in pkg_data if f.get('Is_Flagged')]
            pdf.cell(0, 6, f"Flagged Payloads Found: {len(flagged)}", ln=True)
            pdf.ln(2)

            pdf.set_font("helvetica", "B", 10)
            pdf.cell(0, 6, "Extracted Artifacts:", ln=True)
            pdf.set_font("helvetica", "", 9)
            for item in pkg_data:
                path = item.get('Relative_Path', 'Unknown')
                ext = item.get('Extension', '')
                size = item.get('Size_Bytes', 0)
                sha256 = item.get('SHA256', 'N/A')
                flagged_label = " [FLAGGED]" if item.get('Is_Flagged') else ""
                line = f"{path} | {ext} | {size} bytes | SHA256: {sha256}{flagged_label}"
                if item.get('Is_Flagged'):
                    pdf.set_text_color(200, 0, 0)
                pdf.multi_cell(0, 5, line.encode('latin-1', 'replace').decode('latin-1'))
                pdf.set_text_color(0, 0, 0)
            pdf.ln(5)

        # Section 3: Static Analysis Results
        pdf.add_page() # Put static analysis on a fresh page
        pdf.set_font("helvetica", "B", 12)
        pdf.cell(0, 8, "3. Deep Static Analysis", ln=True, fill=True)
        pdf.ln(2)
        
        static_res = data.get("Static_Analysis_Results", {})
        if not static_res:
             pdf.set_font("helvetica", "I", 10)
             pdf.cell(0, 6, "No static analysis performed (Not a PE file).", ln=True)
        else:
            # If multiple executables were analyzed (e.g., from a ZIP), iterate them
            for target_exe, results in static_res.items():
                pdf.set_font("helvetica", "B", 11)
                pdf.set_text_color(0, 50, 150)
                pdf.cell(0, 8, f"Target: {target_exe}", ln=True)
                pdf.set_text_color(0, 0, 0)
                write_dict_to_pdf(pdf, results)
                pdf.ln(5)

        # Output the document
        pdf.output(output_path)