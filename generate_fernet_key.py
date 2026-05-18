from cryptography.fernet import Fernet


if __name__  == '__main__':
    try:
        key = Fernet.generate_key()

        with open("fernet_key.key", "wb") as f:
            f.write(key)

        print("Fernet key generated successfully.")
    except Exception as e:
        print("Error generating Fernet key:", e)
    
    raise SystemExit(0)
