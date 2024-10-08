import re
import sys

# Define plain text filters
plain_text_filters = [
    "gold",
    "gp",
    "cheap",
    "buy",
    "sell",
    "discount",
    "visit"
]

# Define regex filters
regex_filters = [
    # Match common spam keywords with potential variations
    r"\b(?:g[o0]ld|g[\.]p|chea[p]+|se[!1]l+l+|b[uü]y|best[\s\W]price)\b",
    
    # Match URLs (http, https, www)
    r"http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\\(\\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+",
    r"\bwww\.[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b",
    
    # Match messages with repeated characters or symbols often used to bypass filters
    r"([a-zA-Z])\1{2,}",
    
    # Match obfuscated words like "g0ld", "g.p", etc.
    r"\b(?:g[o0]ld|g[\.]p|se[!1]l+l+|b[uü]y)\b"
]

# Function to check if a message matches any of the filters
def is_spam(message):
    # Check plain text filters
    for text in plain_text_filters:
        if text.lower() in message.lower():
            return True

    # Check regex filters
    for pattern in regex_filters:
        if re.search(pattern, message, re.IGNORECASE):
            return True

    return False

# Main function to read from a specified log file and print spam messages
def main():
    log_file_path = input("Please enter the log file name: ")

    try:
        with open(log_file_path, 'r', encoding='utf-8') as file:
            for line in file:
                message = line.strip()
                if is_spam(message):
                    print(f"Spam: {message}")
    except FileNotFoundError:
        print(f"Error: File '{log_file_path}' not found.")
        sys.exit(1)

if __name__ == "__main__":
    main()