import requests
import json
import random
import string
import time
import datetime

# --- Configuration ---
CREATE_API_URL = "https://api1.jiosaavn.com/user/create"
LOGIN_API_URL = "https://api1.jiosaavn.com/user/emailLogin"
UPDATE_API_URL = "https://www.jiosaavn.com/api.php"

API_PARAMS_COMMON = {
    "api_version": "4",
    "_format": "json",
    "_marker": "0",
    "ctx": "wap6dot0"
}

# --- Helper Functions ---
# (generate_random_string, generate_fake_email, generate_fake_password,
#  generate_fake_name, generate_fake_dob - remain unchanged)
def generate_random_string(length=10):
    """Generates a random alphanumeric string."""
    characters = string.ascii_lowercase + string.digits
    return ''.join(random.choice(characters) for i in range(length))

def generate_fake_email(domain="jkotypc.com"):
    """Generates a pseudo-random email address using specified domain."""
    return f"{generate_random_string()}@{domain}"

def generate_fake_password(length=12):
    """Generates a random password."""
    characters = string.ascii_letters + string.digits + string.punctuation
    password = [
        random.choice(string.ascii_lowercase),
        random.choice(string.ascii_uppercase),
        random.choice(string.digits),
        random.choice(string.punctuation)
    ]
    password += [random.choice(characters) for _ in range(length - len(password))]
    random.shuffle(password)
    return ''.join(password)

def generate_fake_name():
    """Generates a simple fake first or last name."""
    first_parts = ["Har", "Ven", "Clo", "Bre", "Al", "Jo", "Mi", "Da", "Ste", "Rob"]
    second_parts = ["venger", "aker", "x", "son", "ton", "ley", "chael", "vid", "phen", "erts"]
    return random.choice(first_parts) + random.choice(second_parts)

def generate_fake_dob(min_year=1985, max_year=2005):
    """Generates a fake date of birth in YYYY-MM-DD format."""
    year = random.randint(min_year, max_year)
    month = random.randint(1, 12)
    if month in [4, 6, 9, 11]:
        day = random.randint(1, 30)
    elif month == 2:
        is_leap = (year % 4 == 0 and year % 100 != 0) or (year % 400 == 0)
        day = random.randint(1, 29 if is_leap else 28)
    else:
        day = random.randint(1, 31)
    return f"{year:04d}-{month:02d}-{day:02d}"

# --- Common Headers ---
def get_common_headers():
    """Returns a dictionary of common headers for requests."""
    return {
        'accept': 'application/json, text/plain, */*',
        'accept-language': 'en-US,en;q=0.9',
        'user-agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/136.0.0.0 Safari/537.36',
        'origin': 'https://www.jiosaavn.com',
        'referer': 'https://www.jiosaavn.com/',
        'sec-ch-ua': '"Chromium";v="136", "Google Chrome";v="136", "Not.A/Brand";v="99"',
        'sec-ch-ua-mobile': '?0',
        'sec-ch-ua-platform': '"Windows"',
        'sec-fetch-dest': 'empty',
        'sec-fetch-mode': 'cors',
        'sec-fetch-site': 'same-site', # Default, will be adjusted
    }

# --- Utility function to print response details ---
def print_response_details(response):
    """Prints the status code and body of a requests.Response object."""
    print(f"    Response Status Code: {response.status_code}")
    # Attempt to print pretty JSON if possible, otherwise print raw text
    try:
        parsed_json = response.json()
        print(f"    Response JSON Body:\n{json.dumps(parsed_json, indent=4)}")
    except json.JSONDecodeError:
        print(f"    Response Text Body:\n{response.text}")
    print("-" * 20) # Separator after response details


# --- Account Creation Function (Revised Validation + Response Printing) ---
def attempt_create_jiosaavn_account(email, username, password, recaptcha_token):
    print(f"[*] Attempting account creation for: {email}...")
    headers = get_common_headers()
    headers['sec-fetch-site'] = 'same-site'
    headers['content-type'] = 'application/json'
    params = {**API_PARAMS_COMMON, "__call": "user.create"}
    payload = {
        "email": email, "username": username, "password": password,
        "recaptcha_response": recaptcha_token
    }
    response = None # Initialize response to None

    try:
        response = requests.post(
            CREATE_API_URL, params=params, headers=headers, json=payload, timeout=30
        )
        print("--- Creation Request Sent ---")
        print_response_details(response) # Print details immediately after request

        response.raise_for_status() # Check HTTP status after printing response
        response_data = response.json() # Attempt to parse JSON after checking status

        # Validation logic remains the same
        if isinstance(response_data, dict) and "data" in response_data and \
           isinstance(response_data["data"], dict) and \
           "uid" in response_data["data"] and "email" in response_data["data"]:
            print(f"[+] Creation Success (Validated Structure) for {email}.")
            return True, response_data
        else:
            print(f"[!] Creation Failed (Unexpected Response Structure) for {email}.")
            # Already printed full response above
            return False, response_data

    except requests.exceptions.HTTPError as http_err:
        print(f"[!] HTTP error during creation for {email}: {http_err}")
        # Response details should have been printed just before this exception if response was received
        error_message = response.text if response else str(http_err)
        return False, error_message
    except requests.exceptions.RequestException as req_err:
        print(f"[!] Request exception during creation for {email}: {req_err}")
        return False, str(req_err)
    except json.JSONDecodeError:
        # This case is less likely if raise_for_status() didn't fail, but handle anyway
        print(f"[!] Failed to decode JSON creation response for {email} (after status check). Status: {response.status_code if response else 'N/A'}")
        return False, response.text if response else "JSON Decode Error, No Response Object"

# --- Login Function (Revised + Response Printing) ---
def attempt_login(username, password, recaptcha_token):
    print(f"[*] Attempting login for: {username}...")
    headers = get_common_headers()
    headers['sec-fetch-site'] = 'same-site'
    headers['content-type'] = 'application/json'
    params = {**API_PARAMS_COMMON, "__call": "user/emailLogin"}
    payload = {
        "username": username, "password": password,
        "recaptcha_response": recaptcha_token
    }
    session = requests.Session()
    session.headers.update({k:v for k,v in headers.items() if k != 'content-type'})
    response = None

    try:
        response = session.post(
            LOGIN_API_URL, params=params, json=payload, timeout=30
        )
        print("--- Login Request Sent ---")
        print_response_details(response) # Print details immediately

        response.raise_for_status()
        response_data = response.json()

        # Validation logic remains the same
        if response.cookies and ("email" in response_data or "uid" in response_data or response_data.get("status") == "success" or "user" in response_data):
            print(f"[+] Login Successful for {username}.")
            return session, response_data
        else:
            print(f"[!] Login Failed (API Response Indicates Failure) for {username}.")
            return None, response_data

    except requests.exceptions.HTTPError as http_err:
        print(f"[!] HTTP error during login for {username}: {http_err}")
        error_message = response.text if response else str(http_err)
        return None, error_message
    except requests.exceptions.RequestException as req_err:
        print(f"[!] Request exception during login for {username}: {req_err}")
        return None, str(req_err)
    except json.JSONDecodeError:
        print(f"[!] Failed to decode JSON login response for {username} (after status check). Status: {response.status_code if response else 'N/A'}")
        return None, response.text if response else "JSON Decode Error, No Response Object"


# --- Profile Update Function (Revised + Response Printing) ---
def attempt_update_profile(session, email):
    print(f"[*] Attempting profile update for: {email}...")
    first_name = generate_fake_name()
    last_name = generate_fake_name()
    dob = generate_fake_dob()
    gender = 'u'
    print(f"    Updating with: Name={first_name} {last_name}, DOB={dob}, Gender={gender}")

    # Headers are largely managed by the session, but adjust specific ones
    headers = { # Create specific headers for this request context
        'origin': 'https://www.jiosaavn.com',
        'referer': 'https://www.jiosaavn.com/me/account',
        'sec-fetch-site': 'same-origin',
    }
    # Update the session headers temporarily ONLY for this request if needed, or pass directly
    # Note: `requests` sets Content-Type for `data=` automatically

    params = {**API_PARAMS_COMMON, "__call": "user.update"}
    payload_data = {
        "firstname": first_name, "lastname": last_name, "gender": gender, "dob": dob,
        "email": email, "phone_number": "", "idToken": "", "correlation_id": "", "otp": ""
    }
    response = None

    try:
        response = session.post(
            UPDATE_API_URL, params=params, data=payload_data, headers=headers, timeout=30
        )
        print("--- Profile Update Request Sent ---")
        print_response_details(response) # Print details immediately

        response.raise_for_status() # Check status AFTER printing

        # Attempt validation based on response content
        try:
            response_data = response.json()
            if isinstance(response_data, dict) and response_data.get('status') == 'success':
                 print(f"[+] Profile Update Success (Validated Structure) for {email}.")
                 return True, response_data
            elif "Successfully updated" in response.text: # Check text if json check fails
                 print(f"[+] Profile Update Success (Validated Text) for {email}.")
                 return True, response.text # Return raw text if JSON structure wasn't 'success'
            else:
                print(f"[!] Profile Update Failed (API Indicates Failure - check response above) for {email}.")
                return False, response_data
        except json.JSONDecodeError:
             # Assume success if status is 200 OK but response isn't valid JSON
             if response.status_code == 200:
                  print(f"[+] Profile Update potentially successful (200 OK, Non-JSON Response) for {email}.")
                  return True, response.text
             else: # Should have been caught by raise_for_status, but belt and suspenders
                  print(f"[!] Profile Update Failed (Non-JSON Response, Status {response.status_code}) for {email}.")
                  return False, response.text

    except requests.exceptions.HTTPError as http_err:
        print(f"[!] HTTP error during profile update for {email}: {http_err}")
        error_message = response.text if response else str(http_err)
        return False, error_message
    except requests.exceptions.RequestException as req_err:
        print(f"[!] Request exception during profile update for {email}: {req_err}")
        return False, str(req_err)

# --- Main Execution (Unchanged from previous update) ---
if __name__ == "__main__":
    print("--- JioSaavn Account Creation, Login & Profile Update Attempt ---")
    print("!!! WARNING: Relies on reverse-engineered APIs and VIOLATES ToS.")
    print("!!!          Requires VALID, real-time reCAPTCHA tokens for creation/login.")
    print("!!!          WILL FAIL without proper external CAPTCHA solving.")
    print("!!!          High risk of detection and blocking.")
    print("-" * 40)

    # 1. Generate Fake Data
    email_to_create = generate_fake_email()
    password_to_create = generate_fake_password()
    username_to_create = email_to_create

    # 2. Obtain Creation reCAPTCHA (EXTERNAL)
    creation_recaptcha = "PLACEHOLDER_INVALID_TOKEN_FOR_CREATION"
    print(f"Generated credentials: {email_to_create} / {password_to_create}")
    print(f"Using Creation reCAPTCHA: {creation_recaptcha} (INVALID - NEEDS EXTERNAL SOLVER)")

    # 3. Attempt Creation
    creation_success, creation_data = attempt_create_jiosaavn_account(
        email_to_create, username_to_create, password_to_create, creation_recaptcha
    )

    # 4. Attempt Login if Creation OK
    if creation_success:
        print("-" * 40)
        print("[*] Creation reported success, attempting login...")
        time.sleep(2)

        # Obtain Login reCAPTCHA (EXTERNAL)
        login_recaptcha = "PLACEHOLDER_INVALID_TOKEN_FOR_LOGIN"
        print(f"Using Login reCAPTCHA: {login_recaptcha} (INVALID - NEEDS EXTERNAL SOLVER)")

        logged_in_session, login_data = attempt_login(
            username_to_create, password_to_create, login_recaptcha
        )

        # 5. Attempt Update if Login OK
        if logged_in_session:
            print("-" * 40)
            print("[*] Login successful, attempting profile update...")
            time.sleep(2)

            update_success, update_data = attempt_update_profile(
                logged_in_session,
                email_to_create
            )

            if update_success:
                print("\n[+] Profile update process reported completion based on API response.")
            else:
                print("\n[-] Profile update failed or reported failure during API interaction.")

        else:
            print("\n[-] Login failed after successful creation report.")

    else:
        print("\n[-] Account creation failed or reported as failed by API.")

    print("-" * 40)
    print("Script finished.")
