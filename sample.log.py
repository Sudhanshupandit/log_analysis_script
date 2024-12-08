import re
import csv
from collections import Counter

# Define constants
LOG_FILE = "sample.log"
OUTPUT_CSV = "log_analysis_results.csv"
FAILED_LOGIN_THRESHOLD = 10

# Helper function to parse the log file
def parse_log_file(file_path):
    with open(file_path, 'r') as file:
        logs = file.readlines()
    return logs

# Function to count requests per IP address
def count_requests_per_ip(logs):
    ip_pattern = r"(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})"
    ip_addresses = [re.match(ip_pattern, log).group(1) for log in logs if re.match(ip_pattern, log)]
    ip_count = Counter(ip_addresses)
    return sorted(ip_count.items(), key=lambda x: x[1], reverse=True)

# Function to identify the most frequently accessed endpoint
def most_frequent_endpoint(logs):
    endpoint_pattern = r'"(?:GET|POST) (.*?) HTTP/1\.\d"'
    endpoints = [re.search(endpoint_pattern, log).group(1) for log in logs if re.search(endpoint_pattern, log)]
    endpoint_count = Counter(endpoints)
    return max(endpoint_count.items(), key=lambda x: x[1])

# Function to detect suspicious activity
def detect_suspicious_activity(logs):
    suspicious_pattern = r"(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}).*401"
    failed_logins = [re.search(suspicious_pattern, log).group(1) for log in logs if re.search(suspicious_pattern, log)]
    failed_login_count = Counter(failed_logins)
    return [(ip, count) for ip, count in failed_login_count.items() if count >= FAILED_LOGIN_THRESHOLD]

# Function to save results to a CSV file
def save_to_csv(ip_counts, most_accessed, suspicious_activities):
    with open(OUTPUT_CSV, 'w', newline='') as csvfile:
        writer = csv.writer(csvfile)
        
        # Write Requests per IP
        writer.writerow(["IP Address", "Request Count"])
        writer.writerows(ip_counts)
        
        # Write Most Accessed Endpoint
        writer.writerow([])
        writer.writerow(["Most Accessed Endpoint", "Access Count"])
        writer.writerow([most_accessed[0], most_accessed[1]])
        
        # Write Suspicious Activity
        writer.writerow([])
        writer.writerow(["IP Address", "Failed Login Attempts"])
        writer.writerows(suspicious_activities)

# Main function
def main():
    logs = parse_log_file(LOG_FILE)
    
    # Count requests per IP
    ip_counts = count_requests_per_ip(logs)
    print("Requests per IP Address:")
    for ip, count in ip_counts:
        print(f"{ip}: {count}")
    
    # Identify most frequently accessed endpoint
    most_accessed = most_frequent_endpoint(logs)
    print("\nMost Frequently Accessed Endpoint:")
    print(f"{most_accessed[0]} ({most_accessed[1]} times)")
    
    # Detect suspicious activity
    suspicious_activities = detect_suspicious_activity(logs)
    print("\nSuspicious Activity Detected:")
    for ip, count in suspicious_activities:
        print(f"{ip}: {count} failed login attempts")
    
    # Save results to CSV
    save_to_csv(ip_counts, most_accessed, suspicious_activities)
    print(f"\nResults saved to {OUTPUT_CSV}")

if __name__ == "__main__":
    main()
