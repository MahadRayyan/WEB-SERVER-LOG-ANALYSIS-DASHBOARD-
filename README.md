# 🌐 Web Server Log Analysis Dashboard

A full data pipeline that parses 3.15M+ raw web server log entries using Python, transforms them into structured CSV data, and visualizes traffic patterns, bot activity, device usage, and suspicious requests in an interactive Power BI dashboard.

---

### ⚡ Technologies

- Python
- Pandas
- Regex (`re`)
- Power BI
- CSV (structured data output)

---

### 🚀 Features

- Parses raw `.log` files using a custom Regex pattern capturing IP, timestamp, method, URL, status, bytes, referer, and user agent
- Categorizes HTTP status codes into Success, Redirect, Client Error, and Server Error
- Detects browser type (Chrome, Firefox, Edge, Safari, curl, Bot/Crawler)
- Identifies operating system (Windows, Android, iOS, Linux, Mac OS)
- Classifies device type (Mobile, Tablet, Desktop)
- Flags suspicious activity — unauthorized access attempts, sensitive path probing (`.env`, `wp-login`, `phpmyadmin`, `.git`, etc.)
- Exports clean, structured CSV ready for Power BI import
- Interactive Power BI dashboard with bookmark-based filtering to explore traffic patterns, top IPs, device distribution, and bot detection

---

### 🧠 The Process

I had 3.15M+ lines of messy raw server logs and wanted to make sense of them. The logs had no structure out of the box — just walls of text. So I wrote a Regex parser in Python to extract every meaningful field from each line: IP address, request method, URL path, HTTP status, bytes transferred, referer, and user agent.

Once the data was parsed into a DataFrame, I layered on feature engineering — detecting browsers and operating systems from user agent strings, flagging suspicious requests targeting sensitive endpoints, and categorizing every status code. Failed lines were tracked separately so nothing got silently dropped.

The final CSV went straight into Power BI where I built a dashboard with dynamic slicers, bookmarks for multi-page navigation, and visuals tracking real-time order summaries, traffic patterns, top IPs, and bot/crawler traffic. Ended up detecting 46K+ unique requests and 38.92bn bytes of total data transfer across the log period.

---

### 🛠 Running the Project

1. Place your `.log` file in the project directory and update the `log_file` variable in `parsing.py`
2. Install dependencies:
   ```
   pip install pandas
   ```
3. Run the parser:
   ```
   python parsing.py
   ```
4. Open the generated `parsed_logs3.csv` in Power BI Desktop
5. Load the `.pbix` dashboard file and refresh the data source to point to your CSV

---

### 📁 Preview

<img width="1227" height="683" alt="image" src="https://github.com/user-attachments/assets/dff54aa4-ffdf-497a-87e7-49ab093ca1cd" />
<img width="1366" height="392" alt="image" src="https://github.com/user-attachments/assets/d983ed71-5610-4c89-8270-8721cb57ac40" />
<img width="886" height="505" alt="image" src="https://github.com/user-attachments/assets/4729f22d-a94c-4b67-9ca2-9df8b7ffafa8" />

<img width="891" height="490" alt="image" src="https://github.com/user-attachments/assets/7632f79f-8668-47b4-ac85-dfc36fd5b3c0" />
<img width="1315" height="707" alt="image" src="https://github.com/user-attachments/assets/e3470769-37d4-42f0-b3a9-62f89cfcc0c4" />



