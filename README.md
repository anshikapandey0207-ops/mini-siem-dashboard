

\# SENTINEL — Mini SIEM Dashboard



An educational Cyber Security project built with Python, Streamlit and Pandas.



\## Features

\- Security log CSV upload

\- Failed-login detection

\- Possible brute-force indicators

\- Suspicious event detection

\- Severity filtering

\- IP address analysis

\- Security charts and downloadable reports

\- Local demonstration login



\## Setup



Install Python, then clone this repository and open its folder in PowerShell.



Create a virtual environment:



```powershell

python -m venv .venv

```



Activate it:



```powershell

.\\.venv\\Scripts\\Activate.ps1

```



Install dependencies:



```powershell

python -m pip install -r requirements.txt

```



Create `.streamlit/secrets.toml` with your own local demo credentials:



```toml

\[auth]

username = "admin"

password = "change-this-password"

```



Run the app:



```powershell

python -m streamlit run app.py

```



\## CSV format



Required columns: `Time`, `IP Address`, `Event`.



\## Limitations



This is an educational prototype, not a production SIEM. Detection uses rules and may produce false positives. Repeated login failures are counted across the uploaded dataset, not within a time window. The demo login is not intended for public deployment.



\## Author



Add your name and academic details here.



