"""
Task 2: Dataset Loading & Initial Analysis (FIXED VERSION)
"""

import sys
import os
import pandas as pd
import json
from datetime import datetime

# Add src to Python path  
sys.path.append('src')

from src.preprocessing.data_loader import DatasetLoader

def safe_get(dictionary, key, default=None):
    """Safely get a key from dictionary, return default if not found"""
    try:
        return dictionary.get(key, default) if dictionary else default
    except:
        return default

def main():
    """Main execution function for Task 2 with ALL results in task2_results.json"""
    
    print(" TASK 2: DATASET LOADING & INITIAL ANALYSIS")
    print("=" * 70)
    print(f" Execution Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print()
    
    try:
        # Step 1: Initialize dataset loader
        print(" Initializing Dataset Loader...")
        loader = DatasetLoader()
        
        # Step 2: Load your excellent dataset
        print("\n Loading SQL Injection Dataset...")
        df = loader.load_sql_injection_dataset()
        
        if df is None:
            print(" FAILED TO LOAD DATASET")
            print("\n Troubleshooting Checklist:")
            print("  □ Dataset file is in data/raw/ directory")
            print("  □ Dataset is in CSV format") 
            print("  □ File contains query and label columns")
            print("  □ config.json exists and is properly formatted")
            return False
        
        # Step 3: Generate comprehensive overview
        print("\n Analyzing Dataset Quality...")
        overview_data = loader.dataset_overview(df)
        
        # Step 4: Display sample queries for inspection
        print("\n Inspecting Sample Queries...")
        loader.show_sample_queries(df, n_samples=3)
        
        # Step 5: Calculate comprehensive statistics SAFELY
        print("\n Computing Comprehensive Statistics...")
        
        # Query length analysis (calculate directly to avoid KeyError)
        query_lengths = df['query'].astype(str).str.len()
        
        # Safe extraction of query stats
        query_stats_safe = {
            'avg_length': query_lengths.mean(),
            'median_length': query_lengths.median(),
            'min_length': query_lengths.min(),
            'max_length': query_lengths.max(),
            'std_length': query_lengths.std()  # Calculate directly
        }
        
        # Class-wise detailed statistics
        class_detailed_stats = {}
        if 'label' in df.columns:
            for label in sorted(df['label'].unique()):
                label_name = "Normal/Safe" if label == 0 else "Malicious"
                class_data = df[df['label'] == label]
                class_query_lengths = class_data['query'].astype(str).str.len()
                
                class_detailed_stats[f"class_{label}_{label_name.lower().replace('/', '_')}"] = {
                    "label": label,
                    "name": label_name,
                    "count": len(class_data),
                    "percentage": round((len(class_data) / len(df)) * 100, 1),
                    "formatted_display": f"{label} ({label_name}): {len(class_data):,} ({(len(class_data) / len(df)) * 100:.1f}%)",
                    "query_stats": {
                        "avg_length": round(class_query_lengths.mean(), 1),
                        "median_length": round(class_query_lengths.median(), 1),
                        "min_length": int(class_query_lengths.min()),
                        "max_length": int(class_query_lengths.max()),
                        "std_length": round(class_query_lengths.std(), 1)
                    }
                }
        
        # Balance quality assessment
        balance_quality = "EXCELLENT"
        quality_description = "Minimal imbalance, ideal for training"
        
        if overview_data.get('balance_ratio'):
            if overview_data['balance_ratio'] <= 1.2:
                balance_quality = "EXCELLENT"
                quality_description = "Minimal imbalance, ideal for training"
            elif overview_data['balance_ratio'] <= 2.0:
                balance_quality = "GOOD"
                quality_description = "Slight imbalance, manageable"
            elif overview_data['balance_ratio'] <= 5.0:
                balance_quality = "FAIR"
                quality_description = "Moderate imbalance, may need techniques"
            else:
                balance_quality = "POOR"
                quality_description = "Severe imbalance, requires special handling"
        
        # Step 6: Save overview report to reports directory
        print("\n Saving Detailed Reports...")
        overview_report_path = loader.save_overview_report(overview_data)
        
        # Step 7: Create COMPLETE task2_results.json with ALL information (SAFELY)
        complete_task2_results = {
            # # ===== TASK INFORMATION =====
            # "task_info": {
            #     "task": "Task 2: Dataset Loading & Initial Analysis",
            #     "timestamp": datetime.now().isoformat(),
            #     "status": "COMPLETED",
            #     "version": "comprehensive_fixed"
            # },
            
            # ===== BASIC DATASET INFORMATION (Your Console Display) =====
            "dataset_basic_info": {
                "total_records": len(df),
                "total_columns": len(df.columns),
                "column_names": list(df.columns),
                "memory_usage_mb": round(safe_get(overview_data, 'memory_usage_mb', 0), 2),
                "file_size_description": f"{safe_get(overview_data, 'memory_usage_mb', 0):.2f} MB",
                
                # Console display format
                "console_summary": {
                    "total_records_formatted": f"Total Records: {len(df):,}",
                    "total_columns_formatted": f"Total Columns: {len(df.columns)}",
                    "memory_usage_formatted": f"Memory Usage: {safe_get(overview_data, 'memory_usage_mb', 0):.2f} MB",
                    "column_names_formatted": f"Column Names: {list(df.columns)}"
                }
            },
            
            # ===== CLASS DISTRIBUTION (Your Console Display) =====
            "class_distribution": {
                "summary": safe_get(overview_data, 'class_distribution', {}),
                "detailed_stats": class_detailed_stats,
                
                # Console display format
                "console_display": {
                    "class_0_formatted": class_detailed_stats.get("class_0_normal_safe", {}).get("formatted_display", ""),
                    "class_1_formatted": class_detailed_stats.get("class_1_malicious", {}).get("formatted_display", "")
                },
                
                # Balance Analysis (Your Console Display)
                "balance_analysis": {
                    "balance_ratio": round(safe_get(overview_data, 'balance_ratio', 1.0), 2),
                    "balance_ratio_formatted": f"Balance Ratio: {safe_get(overview_data, 'balance_ratio', 1.0):.2f}:1",
                    "balance_quality": balance_quality,
                    "balance_quality_formatted": f"Balance Quality: {balance_quality} ",
                    "quality_assessment": quality_description
                }
            },
            
            # ===== QUERY STATISTICS (FIXED) =====
            "query_statistics": {
                "overall": {
                    "average_length": round(query_stats_safe['avg_length'], 1),
                    "median_length": round(query_stats_safe['median_length'], 1),
                    "min_length": int(query_stats_safe['min_length']),
                    "max_length": int(query_stats_safe['max_length']),
                    "std_deviation": round(query_stats_safe['std_length'], 1)  # Fixed key name
                },
                
                "by_class": class_detailed_stats,
                
                "length_distribution": {
                    "short_queries_under_50": int((query_lengths < 50).sum()),
                    "short_percentage": round((query_lengths < 50).sum() / len(df) * 100, 1),
                    "medium_queries_50_200": int(((query_lengths >= 50) & (query_lengths < 200)).sum()),
                    "medium_percentage": round(((query_lengths >= 50) & (query_lengths < 200)).sum() / len(df) * 100, 1),
                    "long_queries_over_200": int((query_lengths >= 200).sum()),
                    "long_percentage": round((query_lengths >= 200).sum() / len(df) * 100, 1)
                }
            },
            
            # ===== DATA QUALITY ASSESSMENT =====
            "data_quality": {
                "missing_values": safe_get(overview_data, 'missing_values', {}),
                "missing_values_total": sum(safe_get(overview_data, 'missing_values', {}).values()),
                "has_missing_values": sum(safe_get(overview_data, 'missing_values', {}).values()) > 0,
                "data_types": {col: str(dtype) for col, dtype in df.dtypes.items()},
                "duplicate_count": int(df.duplicated().sum()),
                "quality_status": "EXCELLENT" if sum(safe_get(overview_data, 'missing_values', {}).values()) == 0 else "NEEDS_ATTENTION"
            },
            
            # ===== SAMPLE DATA =====
            "sample_data": {
                "normal_queries_samples": df[df['label'] == 0]['query'].head(3).tolist() if 'label' in df.columns else [],
                "malicious_queries_samples": df[df['label'] == 1]['query'].head(3).tolist() if 'label' in df.columns else [],
                "random_samples": df['query'].head(5).tolist()
            },
            
            # ===== FILES & STATUS =====
            "files_generated": [
                overview_report_path,
                'data/processed/task2_results.json'
            ],
            
            "project_status": {
                "ready_for_next_task": True,
                "next_task": "Task 3: Exploratory Data Analysis",
                "recommendations": [
                    f"Dataset quality is {balance_quality.lower()} for ML training",
                    "Class balance is ideal - no special handling needed" if balance_quality == "EXCELLENT" else f"Class balance is {balance_quality.lower()}",
                    "Proceed with confidence to EDA phase",
                    "Consider query length analysis in EDA"
                ]
            },
            
            # ===== LEGACY COMPATIBILITY =====
            "dataset_loaded": True,
            "balance_ratio": round(safe_get(overview_data, 'balance_ratio', 1.0), 10),
            "ready_for_eda": True,
            "columns": list(df.columns),
            "file_size_mb": round(safe_get(overview_data, 'memory_usage_mb', 0), 2)
        }
        
        # Save COMPLETE results to task2_results.json
        os.makedirs('data/processed', exist_ok=True)
        results_path = 'data/processed/task2_results.json'
        with open(results_path, 'w') as f:
            json.dump(complete_task2_results, f, indent=4, default=str)
        
        # ===== DISPLAY COMPREHENSIVE CONSOLE OUTPUT =====
        print(f"\n TASK 2 COMPLETED SUCCESSFULLY!")
        print("=" * 70)
        
        # Basic Information (Your Format)
        basic = complete_task2_results['dataset_basic_info']['console_summary']
        print(f" BASIC INFORMATION:")
        print(f"   {basic['total_records_formatted']}")
        print(f"   {basic['total_columns_formatted']}")
        print(f"   {basic['memory_usage_formatted']}")
        print(f"   {basic['column_names_formatted']}")
        
        # Class Distribution (Your Format)
        print(f"\n CLASS DISTRIBUTION:")
        class_console = complete_task2_results['class_distribution']['console_display']
        if class_console['class_0_formatted']:
            print(f"   {class_console['class_0_formatted']}")
        if class_console['class_1_formatted']:
            print(f"   {class_console['class_1_formatted']}")
        
        # Balance Analysis (Your Format)
        balance = complete_task2_results['class_distribution']['balance_analysis']
        print(f"\n BALANCE ANALYSIS:")
        print(f"   {balance['balance_ratio_formatted']}")
        print(f"   {balance['balance_quality_formatted']}")
        print(f"   Assessment: {balance['quality_assessment']}")
        
        # Query Statistics (Fixed)
        print(f"\n QUERY STATISTICS:")
        stats = complete_task2_results['query_statistics']['overall']
        print(f"   Average Length: {stats['average_length']} characters")
        print(f"   Median Length: {stats['median_length']} characters")
        print(f"   Length Range: {stats['min_length']} - {stats['max_length']} characters")
        print(f"   Standard Deviation: {stats['std_deviation']} characters")
        
        # Length Distribution
        length_dist = complete_task2_results['query_statistics']['length_distribution']
        print(f"\n LENGTH DISTRIBUTION:")
        print(f"   Short (<50 chars): {length_dist['short_queries_under_50']:,} ({length_dist['short_percentage']:.1f}%)")
        print(f"   Medium (50-200 chars): {length_dist['medium_queries_50_200']:,} ({length_dist['medium_percentage']:.1f}%)")
        print(f"   Long (>200 chars): {length_dist['long_queries_over_200']:,} ({length_dist['long_percentage']:.1f}%)")
        
        # Data Quality
        print(f"\n DATA QUALITY:")
        quality = complete_task2_results['data_quality']
        if quality['missing_values_total'] == 0:
            print(f"   Missing Values: {quality['missing_values_total']} ( None found)")
        else:
            print(f"   Missing Values: {quality['missing_values_total']} ( Attention needed)")
        print(f"   Duplicate Queries: {quality['duplicate_count']}")
        print(f"   Quality Status: {quality['quality_status']}")
        
        print(f"\n ALL RESULTS SAVED TO: {results_path}")
        print(f" STATUS: Ready for Task 3 (Exploratory Data Analysis)")
        
        return True
        
    except FileNotFoundError as e:
        print(f" FILE ERROR: {e}")
        print(f"\n Current directory contents:")
        if os.path.exists("data/raw"):
            files = os.listdir("data/raw")
            if files:
                for file in files:
                    if not file.startswith('.'):
                        print(f"    {file}")
            else:
                print(f"   (empty directory)")
        else:
            print(f"   data/raw/ directory not found")
        return False
        
    except Exception as e:
        print(f" UNEXPECTED ERROR: {e}")
        print(f"\n Debug Information:")
        print(f"   Current Directory: {os.getcwd()}")
        print(f"   Python Path: {sys.path}")
        print(f"   Error Details: {type(e).__name__}: {str(e)}")
        return False

if __name__ == "__main__":
    success = main()
    
    print("\n" + "="*70)
    if success:
        print(" NEXT STEP: Type 'proceed' to continue to Task 3: Exploratory Data Analysis")
        print(" ALL comprehensive dataset information is saved in data/processed/task2_results.json")
    else:
        print("  Please resolve the issues above before proceeding")
    print("="*70)

