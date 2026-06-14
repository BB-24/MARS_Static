import os
import threading
import yaml
from pubsub import pub

# Import the core analysis modules
from core.intake import IntakeModule
from core.package import PackageModule
from core.static import StaticModule
from core.report import ReportGenerator # <-- NEW IMPORT

class AnalysisPipeline:
    def __init__(self, config_path="config/config.yaml"):
        self.config_path = config_path
        self.config = self._load_config()

        # Initialize the localized modules
        self.intake_module = IntakeModule(self.config)
        self.package_module = PackageModule(self.config)
        self.static_module = StaticModule(self.config)
        self.reporter = ReportGenerator(self.config) # <-- NEW INSTANCE

        pub.subscribe(self._on_analysis_start, "analysis.start")
        pub.sendMessage("gui.log", msg="[*] Analysis Pipeline Orchestrator Initialized and Ready.")

    def _load_config(self):
        try:
            with open(self.config_path, 'r') as f:
                return yaml.safe_load(f)
        except Exception:
            return {}

    def _on_analysis_start(self, filepath):
        pub.sendMessage("gui.log", msg=f"\n[*] Pipeline triggered for: {filepath}")
        thread = threading.Thread(target=self._execute_pipeline, args=(filepath,), daemon=True)
        thread.start()

    def _execute_pipeline(self, filepath):
        try:
            # Data Aggregators for the final report
            report_pkg_data = []
            report_static_data = {}

            # ==========================================
            # Phase 1: Intake & Validation
            # ==========================================
            metadata = self.intake_module.process_file(filepath)
            if not metadata:
                pub.sendMessage("gui.log", msg="[!] Pipeline aborted during Intake phase.")
                pub.sendMessage("analysis.complete", status="Failed")
                return

            analysis_id = metadata.get("Analysis ID")
            ext = metadata.get("Extension", "").lower()
            extracted_executables = []

            # ==========================================
            # Phase 2: Package Analysis (Unpacking)
            # ==========================================
            if ext in ['.zip', '.msi']:
                extract_dir, inventory = self.package_module.process_file(filepath, analysis_id)
                report_pkg_data = inventory # <-- SAVE FOR REPORT
                
                for item in inventory:
                    if item['Extension'] in ['.exe', '.dll', '.sys']:
                        full_extracted_path = os.path.join(extract_dir, item['Relative_Path'])
                        extracted_executables.append(full_extracted_path)

            # ==========================================
            # Phase 3: Static Analysis (PE Checking)
            # ==========================================
            if ext in ['.exe', '.dll', '.sys']:
                static_res = self.static_module.process_file(filepath)
                if static_res:
                    report_static_data[os.path.basename(filepath)] = static_res # <-- SAVE FOR REPORT
            
            if extracted_executables:
                pub.sendMessage("gui.log", msg=f"\n[*] --- Pushing {len(extracted_executables)} extracted payloads to Static Analysis ---")
                for exec_path in extracted_executables:
                    target_name = os.path.basename(exec_path)
                    pub.sendMessage("gui.update_table", module="Nested Execution", data={"Target": target_name})
                    
                    static_res = self.static_module.process_file(exec_path)
                    if static_res:
                        report_static_data[target_name] = static_res # <-- SAVE FOR REPORT

            # ==========================================
            # Phase 4: Reporting & Output Generation
            # ==========================================
            # Pass all collected dictionaries into the report generator
            self.reporter.generate_reports(metadata, report_pkg_data, report_static_data)

            pub.sendMessage("gui.log", msg="\n[*] === Pipeline Execution Completed Successfully ===")
            pub.sendMessage("analysis.complete", status="Success")

        except Exception as e:
            pub.sendMessage("gui.log", msg=f"\n[!] Critical Pipeline Fault: {str(e)}")
            pub.sendMessage("analysis.complete", status="Error")