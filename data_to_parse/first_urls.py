import json

def extract_top_5_urls(input_jsonl, output_file):
    extracted_data = []
    count = 0
    
    try:
        with open(input_jsonl, mode='r', encoding='utf-8') as f:
            for line in f:
                data = json.loads(line)
                
                # Check if 'Url' exists and is not empty
                url_val = data.get('Url')
                if url_val and url_val.strip():
                    # Create a clean dictionary with only the requested fields
                    clean_entry = {
                        "body": data.get("MainText"),
                        "Url": url_val
                    }
                    extracted_data.append(clean_entry)
                    count += 1
                
                if count == 20:
                    break
        
        # Save the filtered results to a new JSON file
        with open(output_file, mode='w', encoding='utf-8') as out_f:
            json.dump(extracted_data, out_f, indent=4, ensure_ascii=False)
            
        print(f"Successfully saved {count} records to '{output_file}'")
        
        # Also print to console so you can see them immediately
        print(json.dumps(extracted_data, indent=4, ensure_ascii=False))

    except FileNotFoundError:
        print(f"Error: '{input_jsonl}' not found.")
    except Exception as e:
        print(f"An error occurred: {e}")

if __name__ == "__main__":
    extract_top_5_urls('test.jsonl', 'first_5_urls.json')