import json
import requests

API_URL = "https://eajeyq4r3zljoq4rpovy2nthda0vtjqf.lambda-url.ap-south-1.on.aws"

def request_seed(student_id: str, github_repo_url: str):
    # 1. Read student public key
    try:
        with open("student_public.pem", "r") as f:
            public_key = f.read()
    except FileNotFoundError:
        print("❌ ERROR: student_public.pem not found in folder!")
        return

    # 2. Prepare JSON body
    payload = {
        "student_id": student_id,
        "github_repo_url": github_repo_url,
        "public_key": public_key
    }

    # 3. Send POST request
    try:
        response = requests.post(API_URL, json=payload, timeout=15)

    except Exception as e:
        print("❌ API Connection Error:", str(e))
        return

    # 4. Handle response
    try:
        data = response.json()
    except:
        print("❌ Invalid API response (not JSON)")
        print(response.text)
        return

    if "encrypted_seed" in data:
        print("✅ SUCCESS! Encrypted seed received.")
        print("Encrypted Seed:", data["encrypted_seed"])

        # 5. Save to file
        with open("encrypted_seed.txt", "w") as f:
            f.write(data["encrypted_seed"])
        print("📁 Saved to encrypted_seed.txt")
    else:
        print("❌ API Error:", data)

if __name__ == "__main__":
    student_id = input("Enter your STUDENT ID: ")
    github_url = input("Enter your GitHub Repo URL: ")
    request_seed(student_id, github_url)