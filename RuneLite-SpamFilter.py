''' 
                    RuneLite Spam Filter - Created By Virtuace Security
Uses logs from RuneLite's Chat Log plugin to create spam bot filters for RuneLite's Chat Filter Plugin 
'''

import re
import sys
import os
from datetime import datetime
import json
import csv

# Define regex filters for spam patterns related to services, pricing, and fraudulent aspects
regex_filters = [
    # Match advertisements for services mentioning safety, low ban rate, etc.
    r"\b(?:safe\s*transfer|safest|ban rate|no ban|risk-free)\b",
    
    # Match pricing for gold buying services
    r"\b(?:\$\s*\d+\.\d*\s*(per|each)?\s*(mil|m|million)?)\b",
    
    # Match mentions of payment services (cashapp, paypal, venmo, bitcoin, etc.)
    r"\b(?:cashapp|paypal|venmo|bitcoin|crypto|zelle|telegram|applepay|skrill)\b",
    
    # Match phrases related to large GP giveaways on streams or videos
    r"\b(?:giveaway|massive\s*drop|free\s*gp|youtube\s*channel|twitch\s*stream|kick\s*stream)\b",
    
    # Match URLs (http, https, www, discord)
    r"http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\(\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+",
    r"\bwww\.[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b",
    r"\bdiscord\.gg/[a-zA-Z0-9]+\b",
]

# Define exclusions for collection, skilling items, and legitimate in-game trades
collection_exclusions = [
    "burnt food",
    "crushed gems",
    "skilling supplies",
    "collectibles",
    "inq mace",
    "marrentill",
    "dramen staff",
    "grand exchange",
    "splitting loot"
]

# Define a whitelist of common non-spam phrases
whitelist_phrases = [
    "keep them safe",
    "keeping the ones you gave me",
    "buying for gp",
    "flipping on the grand exchange",
    "splitting boss loot",
    "trading items for gp"
]

# Load or initialize the adaptive configuration
def load_adaptive_config():
    config_path = "adaptive_config.json"
    if os.path.exists(config_path):
        with open(config_path, 'r') as config_file:
            return json.load(config_file)
    else:
        # Default configuration
        return {
            "spam_score_threshold": 2,
            "spam_messages": [],
            "non_spam_messages": []
        }

# Save the adaptive configuration
def save_adaptive_config(config):
    config_path = "adaptive_config.json"
    with open(config_path, 'w') as config_file:
        json.dump(config, config_file, indent=4)

# Extract commonly used spam terms and phrases
def extract_common_spam_phrases(spam_messages):
    common_phrases = set()
    for message in spam_messages:
        # Split message into words and filter for common phrases
        words = re.split(r'\W+', message)
        for word in words:
            if len(word) > 3 and word.isalpha():  # Only consider words longer than 3 characters and alphabetic
                common_phrases.add(word.lower())
    return [phrase for phrase in common_phrases if phrase not in whitelist_phrases and phrase not in collection_exclusions]

# Save common spam phrases to a CSV file
def save_common_phrases_to_csv(phrases, csv_path):
    with open(csv_path, mode='w', newline='') as file:
        writer = csv.writer(file)
        for phrase in phrases:
            writer.writerow([phrase])

# Function to check if a message matches any of the filters
def is_spam(message, config):
    # Check if message contains collection or skilling items (exclude these from spam)
    for exclusion in collection_exclusions:
        if exclusion.lower() in message.lower():
            return False

    # Check if message contains any whitelisted phrases (considered non-spam)
    for phrase in whitelist_phrases:
        if phrase.lower() in message.lower():
            return False

    # Calculate a spam score based on regex matches
    spam_score = 0
    for pattern in regex_filters:
        if re.search(pattern, message, re.IGNORECASE):
            spam_score += 1

    # Consider message as spam if the spam score exceeds a threshold
    return spam_score >= config["spam_score_threshold"]

# Main function to read from a specified log file and output spam messages to a log file
def main():
    if len(sys.argv) < 2 or len(sys.argv) > 3:
        print("Usage: python script.py [-v] <logfile>")
        sys.exit(1)

    verbose = len(sys.argv) == 3 and sys.argv[1] == "-v"
    log_file_path = sys.argv[2] if verbose else sys.argv[1]
    logs_folder = "logs"
    timestamp = datetime.now().strftime("%m_%d-%H-%M")
    output_file_path = os.path.join(logs_folder, f"spam_log_{timestamp}.txt")
    csv_output_path = os.path.join(logs_folder, f"common_spam_phrases_{timestamp}.csv")

    # Load adaptive configuration
    config = load_adaptive_config()

    # Create logs folder if it doesn't exist
    if not os.path.exists(logs_folder):
        os.makedirs(logs_folder)

    try:
        with open(log_file_path, 'r', encoding='utf-8') as file, open(output_file_path, 'w', encoding='utf-8') as output_file:
            for line in file:
                # Remove timestamp and username (assuming format: xx:xx:xx USERNAME: message)
                message = re.sub(r"^\d{2}:\d{2}:\d{2}.*?:\s+", "", line.strip())
                # Remove trailing numbers at the end of the message
                message = re.sub(r"\s+\d+$", "", message)
                if is_spam(message, config):
                    output_file.write(f"{message}\n")
                    config["spam_messages"].append(message)
                    if verbose:
                        print(f"Spam: {message}")
                else:
                    config["non_spam_messages"].append(message)

        # Extract common spam phrases and save to CSV
        common_phrases = extract_common_spam_phrases(config["spam_messages"])
        save_common_phrases_to_csv(common_phrases, csv_output_path)

        # Adjust spam score threshold based on feedback (simple heuristic)
        if len(config["spam_messages"]) > len(config["non_spam_messages"]):
            config["spam_score_threshold"] += 1
        elif len(config["non_spam_messages"]) > len(config["spam_messages"]):
            config["spam_score_threshold"] = max(1, config["spam_score_threshold"] - 1)

        # Save the updated adaptive configuration
        save_adaptive_config(config)

    except FileNotFoundError:
        print(f"Error: File '{log_file_path}' not found.")
        sys.exit(1)

if __name__ == "__main__":
    main()
