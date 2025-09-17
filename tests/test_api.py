import requests
import json

BASE_URL = "http://localhost:8000/apps/api"

USERNAME = "admin"
EMAIL = "ionganea77@gmail.com"
PASSWORD = "admin"


# Login to get JWT

resp = requests.post(
    f"{BASE_URL}/token/", json={"username": USERNAME, "password": PASSWORD}
)
tokens = resp.json()
print("Login:", resp.status_code, tokens)

JWT_TOKEN = tokens.get("access")
if not JWT_TOKEN:
    raise RuntimeError("Login failed; cannot get JWT token")

# Example authenticated request
resp = requests.get(
    f"{BASE_URL}/split-bill/", headers={"Authorization": f"Bearer {JWT_TOKEN}"}
)
print("Split bills:", resp.status_code, resp.json())

HEADERS = {
    "Authorization": f"Bearer {JWT_TOKEN}",
    "Content-Type": "application/json",
}


def register_user(username, email, password):
    url = f"{BASE_URL}/register/"
    data = {"username": username, "email": email, "password": password}
    resp = requests.post(url, json=data, headers={"Content-Type": "application/json"})
    return resp.json(), resp.status_code


def create_split_bill(title, currency="EUR", member_inputs=None):
    url = f"{BASE_URL}/split-bill/"
    data = {"title": title, "currency": currency}
    if member_inputs:
        data["member_inputs"] = member_inputs
    resp = requests.post(url, json=data, headers=HEADERS)
    return resp.json(), resp.status_code


def list_split_bills():
    url = f"{BASE_URL}/split-bill/"
    resp = requests.get(url, headers=HEADERS)
    return resp.json()


def get_split_bill(split_bill_id):
    url = f"{BASE_URL}/split-bill/{split_bill_id}/"
    resp = requests.get(url, headers=HEADERS)
    return resp.json(), resp.status_code


def add_member(split_bill_id, alias, email=None):
    url = f"{BASE_URL}/split-bill/{split_bill_id}/add-member/"
    data = {"alias": alias}
    if email:
        data["email"] = email
    resp = requests.post(url, json=data, headers=HEADERS)
    return resp.json(), resp.status_code


def update_member(split_bill_id, member_id, alias=None, email=None):
    url = f"{BASE_URL}/split-bill/{split_bill_id}/members/{member_id}/update/"
    data = {}
    if alias:
        data["alias"] = alias
    if email:
        data["email"] = email
    resp = requests.put(url, json=data, headers=HEADERS)
    return resp.json(), resp.status_code


def remove_member(split_bill_id, alias=None, email=None):
    url = f"{BASE_URL}/split-bill/{split_bill_id}/remove-member/"
    data = {}
    if alias:
        data["alias"] = alias
    if email:
        data["email"] = email
    resp = requests.post(url, json=data, headers=HEADERS)
    return resp.json(), resp.status_code


def create_equal_expense(title, amount, paid_by_member, split_bill_id, assignments):
    url = f"{BASE_URL}/expenses/equal"
    data = {
        "title": title,
        "amount": amount,
        "paid_by_member": paid_by_member,
        "split_bill": split_bill_id,
        "assignments": assignments,
    }
    resp = requests.post(url, json=data, headers=HEADERS)
    return resp.json(), resp.status_code


def list_expenses():
    url = f"{BASE_URL}/expenses/"
    resp = requests.get(url, headers=HEADERS)
    return resp.json()


def add_comment(split_bill_id, text):
    url = f"{BASE_URL}/comments/"
    data = {"split_bill": split_bill_id, "text": text}
    resp = requests.post(url, json=data, headers=HEADERS)
    return resp.json(), resp.status_code


def drop_split_bill(split_bill_id):
    url = f"{BASE_URL}/split-bill/{split_bill_id}/"
    print(f"DELETE URL: {url}")
    print(f"Headers: {HEADERS}")

    resp = requests.delete(url, headers=HEADERS)
    try:
        content = resp.json()
    except ValueError:
        content = resp.text
    return content, resp.status_code


# -------------------------------
# Example usage
# -------------------------------
if __name__ == "__main__":
    print("Creating Split Bill...")
    sb_resp, sb_status = create_split_bill(
        "Test Bill", member_inputs=[{"alias": "Alice"}, {"email": "bob@example.com"}]
    )
    print(sb_status, sb_resp)

    split_bill_id = sb_resp.get("id")

    print("Fetching split bill details...")
    split_bill_data, split_status = get_split_bill(split_bill_id)
    print(split_status, split_bill_data)

    print("Adding member 'Charlie'...")
    add_resp, add_status = add_member(split_bill_id, "Charlie", "charlie@example.com")
    print(add_status, add_resp)

    print("Updating member 'Charlie' alias to 'Chuck'...")
    member_id = add_resp["member"]["id"]
    update_resp, update_status = update_member(split_bill_id, member_id, alias="Chuck")
    print(update_status, update_resp)

    print("Removing member 'Chuck'...")
    remove_resp, remove_status = remove_member(split_bill_id, alias="Chuck")
    print(remove_status, remove_resp)

    print("Listing Split Bills...")
    print(json.dumps(list_split_bills(), indent=2))

    # Collect all member IDs into a list
    member_ids = [m["id"] for m in split_bill_data["members"]]
    print("Members:", member_ids)

    print("Creating Equal Expense for members [first, second]...")
    expense_resp, expense_status = create_equal_expense(
        "Dinner",
        100,
        member_ids[0],  # paid_by
        split_bill_id,
        [member_ids[0], member_ids[1]],  # participants
    )
    print(expense_status, expense_resp)

    print("Listing all expenses...")
    print(json.dumps(list_expenses(), indent=2))

    print("Adding a comment...")
    comment_resp, comment_status = add_comment(split_bill_id, "This is a test comment")
    print(comment_status, comment_resp)

    print("Fetching split bill details...")
    split_bill_data, split_status = get_split_bill(split_bill_id)
    print(split_status, split_bill_data)

    print("Deleting split_bill")
    remove_resp, remove_status = drop_split_bill(split_bill_id)
    print(remove_status, remove_resp)
