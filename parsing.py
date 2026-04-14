import re
import pandas as pd

log_file = "access_trimmed1.log"

with open(log_file, "r", encoding="utf-8") as file:
    lines = file.readlines()

log_pattern = re.compile(
    r'(?P<ip>\d+\.\d+\.\d+\.\d+)'          # IP
    r'\s+-\s+-\s+'                         # - -
    r'\[(?P<timestamp>[^\]]+)\]\s+'        # [time]
    r'"(?P<method>\S+)\s+'                 # method
    r'(?P<url>\S+)\s+'                     # /path
    r'(?P<protocol>HTTP/\d\.\d*)"\s+'      # HTTP/1.1"
    r'(?P<status>\d{3})\s+'                # status
    r'(?P<bytes>\S+)\s+'                   # bytes
    r'"(?P<referer>[^"]*)"\s+'             # referer
    r'"(?P<user_agent>[^"]*)"\s+'          # user agent
    r'"(?P<proxy>[^"]*)"'                  # last field
)

parsed_logs = []
failed_lines = 0

for line in lines:
    match = log_pattern.match(line.strip())
    if match:
        parsed_logs.append(match.groupdict())
    else:
        failed_lines += 1


df = pd.DataFrame(parsed_logs)

df["status"] = df["status"].astype(int)

def categorize_status(code):
    if 200 <= code < 300: return "Success"
    elif 300 <= code < 400: return "Redirect"
    elif 400 <= code < 500: return "Client Error"
    elif 500 <= code < 600: return "Server Error"
    else: return "Unknown"

df["status_category"] = df["status"].apply(categorize_status)

# Browser detection
def extract_browser(agent):
    if "Edg" in agent:         return "Edge"
    elif "Chrome" in agent:    return "Chrome"
    elif "Firefox" in agent:   return "Firefox"
    elif "Safari" in agent:    return "Safari"
    elif "curl" in agent:      return "curl"
    elif "bot" in agent.lower() or "spider" in agent.lower(): return "Bot/Crawler"
    else:                      return "Other"

df["browser"] = df["user_agent"].apply(extract_browser)

# OS detection
def extract_os(agent):
    if "Windows NT" in agent:  return "Windows"
    elif "Android" in agent:   return "Android"
    elif "iPhone" in agent:    return "iOS"
    elif "Linux" in agent:     return "Linux"
    elif "Mac OS" in agent:    return "Mac OS"
    else:                      return "Other"

df["operating_system"] = df["user_agent"].apply(extract_os)

# Device type
def extract_device(agent):
    if "Mobile" in agent or "Android" in agent or "iPhone" in agent:
        return "Mobile"
    elif "Tablet" in agent or "iPad" in agent:
        return "Tablet"
    else:
        return "Desktop"

df["device_type"] = df["user_agent"].apply(extract_device)

# Suspicious activity flag
def flag_suspicious(row):
    suspicious_paths = [".env", "wp-login", "admin", "phpmyadmin", ".git", "passwd", "etc/"]
    if row["status"] in [401, 403]:
        return "Suspicious"
    elif any(p in row["url"].lower() for p in suspicious_paths):
        return "Suspicious"
    else:
        return "Normal"

df["activity_flag"] = df.apply(flag_suspicious, axis=1)


df.drop(columns=["user_agent"], inplace=True)  # Remove raw user agent (too long for Power BI)
df.to_csv("parsed_logs3.csv", index=False)
