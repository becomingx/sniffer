import csv

def load_protocols(filepath='protocol-numbers-1.csv'):
    protocols = {}
    try:
        with open(filepath, newline='', encoding='utf-8') as csvfile:
            reader = csv.reader(csvfile)
            next(reader)  # Skip header
            for row in reader:
                # row[0] = Decimal, row[1] = Keyword, row[2] = Protocol
                try:
                    proto_num = int(row[0])
                    protocols[proto_num] = {
                        'keyword': row[1],
                        'description': row[2]
                    }
                except ValueError:
                    continue  # Skip rows with invalid protocol numbers
    except FileNotFoundError:
        print(f"CSV file not found: {filepath}")
    return protocols