# vuln_xpath_demo.py
# Purpose: educational demo of unsafe XPath usage (run locally only)
import xml.etree.ElementTree as ET

XML_FILE = "users.xml"

def build_xpath_for_display(username_input):
    # Build an XPath expression in a way ElementTree supports:
    # use user[username='...'] OR user[username="..."] depending on quotes inside input.
    if "'" in username_input and '"' in username_input:
        # both quotes present — this is unusual for normal usernames; show it as raw (won't be executed)
        return None
    if "'" in username_input:
        # username contains single quote -> use double-quote wrapper
        return './/user[username="%s"]' % username_input
    else:
        # default: use single-quote wrapper
        return ".//user[username='%s']" % username_input

def search_by_username(username_input):
    tree = ET.parse(XML_FILE)
    root = tree.getroot()

    xpath = build_xpath_for_display(username_input)
    if xpath is None:
        print("DEBUG: cannot safely construct a simple XPath for this input (contains both types of quotes).")
        print("Please try a normal username like 'bob' or 'alice'.")
        return

    # DEBUG: show the exact constructed XPath for demonstration
    print("DEBUG: constructed xpath ->", xpath)

    # UNSAFE: execute the constructed XPath (this is the vulnerable pattern we're demonstrating)
    try:
        results = root.findall(xpath)
    except SyntaxError as e:
        print("ERROR: XPath syntax error:", e)
        return

    if not results:
        print("No matching user found for:", username_input)
    else:
        for u in results:
            uname = u.findtext("username")
            role = u.findtext("role")
            email = u.findtext("email")
            print(f"Found user -> username: {uname}, role: {role}, email: {email}")

if __name__ == "__main__":
    print("=== XPath Injection - Vulnerable Demo ===")
    user = input("Enter username to search: ")
    search_by_username(user)
