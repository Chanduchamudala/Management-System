import hashlib, json, os

DB_FILE = "hash_db.json"

def generate_hash(file_path, algo="sha256"):
    h = hashlib.new(algo)
    with open(file_path, "rb") as f:
        for chunk in iter(lambda: f.read(4096), b""):
            h.update(chunk)
    return h.hexdigest()

def store_hash(file_path, hash_value, algo):
    db = {}
    if os.path.exists(DB_FILE):
        with open(DB_FILE, "r") as f:
            db = json.load(f)
    db[file_path] = {"hash": hash_value, "algorithm": algo}
    with open(DB_FILE, "w") as f:
        json.dump(db, f, indent=4)
    print(f"[+] Stored hash for {file_path}")

def verify_file(file_path):
    if not os.path.exists(DB_FILE):
        return "❌ No database found."

    with open(DB_FILE, "r") as f:
        db = json.load(f)

    if file_path not in db:
        return "❌ File not registered."

    algo = db[file_path]["algorithm"]
    old_hash = db[file_path]["hash"]
    new_hash = generate_hash(file_path, algo)

    return ("✅ Intact" if old_hash == new_hash else "⚠️ Modified")

def main():
    while True:
        print("\n--- File Integrity Verification ---")
        print("1. Register File (Generate & Store Hash)")
        print("2. Verify File Integrity")
        print("3. Exit")
        choice = input("Enter choice: ")

        if choice == "1":
            file_path = input("Enter file path: ").strip()
            algo = input("Algorithm (md5/sha1/sha256): ").lower()
            if os.path.exists(file_path):
                h = generate_hash(file_path, algo)
                store_hash(file_path, h, algo)
            else:
                print("❌ File not found.")

        elif choice == "2":
            file_path = input("Enter file path: ").strip()
            print(verify_file(file_path))

        elif choice == "3":
            break
        else:
            print("❌ Invalid option.")

if __name__ == "__main__":
    main()
