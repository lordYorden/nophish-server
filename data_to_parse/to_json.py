import csv
import json

def csv_to_json_lines(input_file, output_file):
    try:
        # Changed encoding to 'latin-1' which handles byte 0xb0 and other special characters
        with open(input_file, mode='r', encoding='latin-1') as csv_f:
            reader = csv.DictReader(csv_f)
            
            with open(output_file, mode='w', encoding='utf-8') as json_f:
                for row in reader:
                    # ensure_ascii=False keeps special characters as they are
                    json_line = json.dumps(row, ensure_ascii=False)
                    json_f.write(json_line + '\n')
                    
        print(f"Successfully converted '{input_file}' to '{output_file}'")
    
    except FileNotFoundError:
        print("Error: The input CSV file was not found.")
    except Exception as e:
        print(f"An error occurred: {e}")

# Configuration
INPUT_CSV = 'analysisdataset.csv'
OUTPUT_JSONL = 'test.jsonl'

if __name__ == "__main__":
    csv_to_json_lines(INPUT_CSV, OUTPUT_JSONL)