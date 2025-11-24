# fix_iterative.py
# Purpose: safe implementation using iterative exact match and input validation
import xml.etree.ElementTree as ET
import re

XML_FILE = "users.xml"

def safe_search_by_username(username_input):
    tree = ET.parse(XML_FILE)
    root = tree.getroot()

    username = username_input.strip()
    if not username or len(username) > 64:
        print("Invalid username input")
        return

    # allow only letters, numbers, dash, underscore, dot
    if not re.fullmatch(r"[A-Za-z0-9\-\_\.]+", username):
        print("Username contains disallowed characters")
        return

    found = False
    for u in root.findall(".//user"):
        uname = u.findtext("username")
        if uname == username:
            role = u.findtext("role")
            email = u.findtext("email")
            print(f"Found user -> username: {uname}, role: {role}, email: {email}")
            found = True

    if not found:
        print("No matching user found for:", username)

if __name__ == "__main__":
    print("=== XPath Injection - Fixed Demo ===")
    user = input("Enter username to search: ")
    safe_search_by_username(user)
