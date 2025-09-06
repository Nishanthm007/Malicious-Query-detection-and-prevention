import pandas as pd
import numpy as np
import os
import json
from pathlib import Path
import warnings
warnings.filterwarnings('ignore')

class DatasetLoader:
    def __init__(self, config_path="config.json"):
        """Initialize with configuration"""
        with open(config_path, 'r') as f:
            self.config = json.load(f)
        self.raw_data_path = self.config['data_paths']['raw_data']
        self.processed_data_path = self.config['data_paths']['processed_data']
    
    def load_sql_injection_dataset(self, filename=None, auto_detect=True):
        """Load your SQL injection dataset (malicious + normal)"""
        
        print("LOADING SQL INJECTION DATASET")

        
        # Auto-detect dataset file if not specified
        if filename is None and auto_detect:
            raw_path = Path(self.raw_data_path)
            csv_files = list(raw_path.glob("*.csv"))
            
            if csv_files:
                filename = csv_files[0].name
                print(f"Auto-detected dataset: {filename}")
            else:
                raise FileNotFoundError("No CSV files found in data/raw/ directory")
        
        file_path = os.path.join(self.raw_data_path, filename)
        
        if not os.path.exists(file_path):
            raise FileNotFoundError(f"Dataset not found at: {file_path}")
        
        try:
            # Load dataset
            print(f" Loading from: {file_path}")
            df = pd.read_csv(file_path)
            
            # Detect column names (handle different naming conventions)
            query_col = self._detect_query_column(df)
            label_col = self._detect_label_column(df)
            
            # Standardize column names
            if query_col != 'query':
                df = df.rename(columns={query_col: 'query'})
            if label_col != 'label':
                df = df.rename(columns={label_col: 'label'})
            
            print(f" Successfully loaded {len(df):,} records")
            print(f" Columns: {list(df.columns)}")
            
            return df
            
        except Exception as e:
            print(f" Error loading dataset: {e}")
            return None
    
    def _detect_query_column(self, df):
        """Auto-detect the query column"""
        possible_names = ['query', 'Query', 'sql', 'SQL', 'statement', 'Payload', 'payload']
        
        for col in possible_names:
            if col in df.columns:
                return col
        
        # If no match, use first text column
        text_cols = df.select_dtypes(include=['object']).columns
        if len(text_cols) > 0:
            return text_cols[0]
        
        raise ValueError("Could not detect query column")
    
    def _detect_label_column(self, df):
        """Auto-detect the label column"""
        possible_names = ['label', 'Label', 'target', 'class', 'Label ']
        
        for col in possible_names:
            if col in df.columns:
                return col
        
        # Look for numeric columns with binary values
        numeric_cols = df.select_dtypes(include=[np.number]).columns
        for col in numeric_cols:
            unique_vals = df[col].nunique()
            if unique_vals == 2:
                return col
        
        raise ValueError("Could not detect label column")
    
    def dataset_overview(self, df):
        """Get comprehensive overview of the dataset WITHOUT modifying original DataFrame"""
        
        print("\n DATASET OVERVIEW:")

        
        # Basic information
        total_records = len(df)
        total_columns = len(df.columns)
        memory_usage = df.memory_usage(deep=True).sum() / 1024**2
        
        print(f" Basic Information:")
        print(f"  Total Records: {total_records:,}")
        print(f"  Total Columns: {total_columns}")  # This should show 2 now
        print(f"  Memory Usage: {memory_usage:.2f} MB")
        print(f"  Column Names: {list(df.columns)}")
        
        # Class distribution analysis
        balance_ratio = None
        if 'label' in df.columns:
            print(f"\n CLASS DISTRIBUTION:")
            label_counts = df['label'].value_counts().sort_index()
            
            for label, count in label_counts.items():
                label_name = "Normal/Safe" if label == 0 else "Malicious"
                percentage = (count / total_records) * 100
                print(f"  {label} ({label_name}): {count:,} ({percentage:.1f}%)")
            
            # Balance ratio
            max_count = label_counts.max()
            min_count = label_counts.min()
            balance_ratio = max_count / min_count
            print(f"\n Balance Ratio: {balance_ratio:.2f}:1")
            
            # Quality assessment
            if balance_ratio <= 1.2:
                quality = "EXCELLENT "
            elif balance_ratio <= 2.0:
                quality = "GOOD "
            elif balance_ratio <= 5.0:
                quality = "FAIR "
            else:
                quality = "POOR "
            
            print(f" Balance Quality: {quality}")
        
        # Missing values analysis
        print(f"\n🔍 DATA QUALITY:")
        missing_values = df.isnull().sum()
        
        if missing_values.sum() == 0:
            print(f"  Missing Values:  None found")
        else:
            print(f"  Missing Values:")
            for col, count in missing_values.items():
                if count > 0:
                    percentage = (count / total_records) * 100
                    print(f"    {col}: {count:,} ({percentage:.2f}%)")
        
        # Data types
        print(f"\n DATA TYPES:")
        for col, dtype in df.dtypes.items():
            print(f"  {col}: {dtype}")
        
        # Query statistics (CALCULATE WITHOUT MODIFYING DATAFRAME)
        query_stats = None
        if 'query' in df.columns:
            print(f"\n QUERY STATISTICS:")
            
            # Calculate query lengths WITHOUT adding column to DataFrame
            query_lengths = df['query'].astype(str).str.len()  # ✅ This creates a Series, not a column
            
            avg_length = query_lengths.mean()
            max_length = query_lengths.max()
            min_length = query_lengths.min()
            median_length = query_lengths.median()
            std_length = query_lengths.std()
            
            print(f"  Average Length: {avg_length:.1f} characters")
            print(f"  Median Length: {median_length:.1f} characters")
            print(f"  Min Length: {min_length} characters")
            print(f"  Max Length: {max_length} characters")
            print(f"  Std Deviation: {std_length:.1f} characters")
            
            # Length distribution
            short_queries = (query_lengths < 50).sum()
            medium_queries = ((query_lengths >= 50) & (query_lengths < 200)).sum()
            long_queries = (query_lengths >= 200).sum()
            
            print(f"\n  Length Distribution:")
            print(f"    Short (<50 chars): {short_queries:,} ({short_queries/total_records*100:.1f}%)")
            print(f"    Medium (50-200 chars): {medium_queries:,} ({medium_queries/total_records*100:.1f}%)")
            print(f"    Long (>200 chars): {long_queries:,} ({long_queries/total_records*100:.1f}%)")
            
            query_stats = {
                'avg_length': avg_length,
                'median_length': median_length,
                'min_length': min_length,
                'max_length': max_length,
                'std_length': std_length  # ✅ Now consistent key name
            }
        
        return {
            'total_records': total_records,
            'total_columns': total_columns,  # ✅ Will be 2, not 3
            'columns': list(df.columns),     # ✅ Will be ['query', 'label']
            'class_distribution': label_counts.to_dict() if 'label' in df.columns else None,
            'balance_ratio': balance_ratio,
            'missing_values': missing_values.to_dict(),
            'memory_usage_mb': memory_usage,
            'query_stats': query_stats
        }
    
    def show_sample_queries(self, df, n_samples=3):
        """Display sample queries from each class"""
        
        print(f"\n SAMPLE QUERIES")
        print("=" * 80)
        
        if 'label' in df.columns:
            # Show samples from each class
            for label in sorted(df['label'].unique()):
                label_name = "NORMAL/SAFE QUERIES" if label == 0 else "MALICIOUS QUERIES"
                print(f"\n🔹 {label_name} (Label={label}):")
                print("-" * 60)
                
                samples = df[df['label'] == label]['query'].head(n_samples)
                
                for i, (idx, query) in enumerate(samples.items(), 1):
                    query_str = str(query)
                    # Show more of the query for analysis
                    display_query = query_str[:200] + "..." if len(query_str) > 200 else query_str
                    print(f"  {i}. Length: {len(query_str)} chars")
                    print(f"     Query: {display_query}")
                    print()
        else:
            # Show random samples if no labels
            print(f"\n RANDOM QUERY SAMPLES:")
            print("-" * 60)
            samples = df['query'].head(n_samples)
            
            for i, (idx, query) in enumerate(samples.items(), 1):
                query_str = str(query)
                display_query = query_str[:200] + "..." if len(query_str) > 200 else query_str
                print(f"  {i}. Length: {len(query_str)} chars")
                print(f"     Query: {display_query}")
                print()
    
    def save_overview_report(self, overview_data, filename="dataset_overview.json"):
        """Save dataset overview to reports directory"""
        # Ensure reports directory exists
        reports_dir = self.config['data_paths']['reports']
        os.makedirs(reports_dir, exist_ok=True)
        
        output_path = os.path.join(reports_dir, filename)
        
        with open(output_path, 'w') as f:
            json.dump(overview_data, f, indent=4, default=str)
        
        print(f"\n Overview report saved to: {output_path}")
        return output_path
