"""
Execution script for Phase 1: Comprehensive Dataset Audit of NF-CSE-CIC-IDS2018.
"""

import sys
from pathlib import Path

# Add project root to path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from src.data.audit import run_dataset_audit
from src.utils.logger import setup_logger

logger = setup_logger("script_00_audit")

def main():
    logger.info("=== Starting Phase 1: Dataset Audit ===")
    try:
        audit_results = run_dataset_audit()
        logger.info("=== Dataset Audit completed successfully! ===")
        print("\n--- AUDIT SUMMARY ---")
        print(f"Total Records: {audit_results['total_records']:,}")
        print(f"Total Columns: {audit_results['total_columns']}")
        print(f"Duplicate Rows: {audit_results['duplicate_rows']:,} ({audit_results['duplicate_ratio']*100:.2f}%)")
        print(f"Binary Mapping Valid: {audit_results['is_label_mapping_valid']}")
        print(f"Benign Flows: {audit_results['binary_distribution']['Benign (0)']:,}")
        print(f"Attack Flows: {audit_results['binary_distribution']['Attack (1)']:,} ({audit_results['binary_distribution']['Attack_Percentage']:.2f}%)")
        print(f"Total Attack Categories: {len(audit_results['attack_distribution'])}")
        print(f"Outputs generated in 'outputs/audit/'")
    except Exception as e:
        logger.error(f"Dataset audit failed with error: {e}", exc_info=True)
        sys.exit(1)

if __name__ == "__main__":
    main()

