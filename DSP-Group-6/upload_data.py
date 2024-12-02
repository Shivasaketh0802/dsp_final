import pandas as pd
from sqlalchemy import create_engine
from hashlib import sha256

# Database Configuration
DATABASE_URI = 'mysql+pymysql://root:Ashish%402199@127.0.0.1/healthcare_db'

# Connect to the Database
engine = create_engine(DATABASE_URI)

# Load Excel Data
excel_file = r"C:\Users\ashish\Downloads\Group 6\userdetials.xlsx"  # Use raw string for the file path
df = pd.read_excel(excel_file)

# Map Gender Values to Integers
gender_mapping = {'M': 'Male', 'F': 'Female'}
df['gender'] = df['gender'].map(gender_mapping)

# Check for unmapped values (optional)
if df['gender'].isnull().any():
    print("Warning: Some gender values could not be mapped. Check your data.")

# Compute hash for integrity
def compute_hash(row):
    # Concatenate all fields of the record into a single string
    record_str = f"{row['first_name']}{row['last_name']}{row['age']}{row['gender']}{row['weight']}{row['height']}{row['health_history']}"
    return sha256(record_str.encode()).hexdigest()

# Insert Data into Database
try:
    # Add a new 'hash' column for data integrity
    df['hash'] = df.apply(compute_hash, axis=1)

    # Insert data into the database
    df.to_sql('healthrecord', con=engine, if_exists='append', index=False)
    print("Data successfully inserted into healthrecord table.")
except Exception as e:
    print(f"An error occurred: {e}")
