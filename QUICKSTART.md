# SentinelFlow Quickstart

SentinelFlow is a single-file Streamlit demo for a multi-agent SOC incident response workflow. It is designed to run from the terminal and produce a final approved incident blueprint for hackathon screenshots.

## 1. What You Need

- Python 3.11 or newer
- A terminal or PowerShell window
- Optional: `GOOGLE_API_KEY` if you want the ADK/Gemini path instead of the local fallback

## 2. Install

Use the same Python interpreter for installation and running the app.

```powershell
C:/Users/Asus/AppData/Local/Programs/Python/Python313/python.exe -m pip install streamlit google-adk google-genai
```

If you want to use the Google model path, set the API key:

```powershell
$env:GOOGLE_API_KEY="YOUR_KEY_HERE"
```

This variable is optional. If it is not set, the app will use the local sequential fallback and still run successfully.

## 3. Run

```powershell
C:/Users/Asus/AppData/Local/Programs/Python/Python313/python.exe -m streamlit run app.py
```

If port 8501 is already in use, run with a different port:

```powershell
C:/Users/Asus/AppData/Local/Programs/Python/Python313/python.exe -m streamlit run app.py --server.port 8502
```

## 4. How To Use

1. Open the Streamlit app in your browser after running the command.
2. Leave the sample SOC logs in the text area, or paste your own suspicious log bundle.
3. Click `Run Investigation`.
4. Wait for the three stages to execute:
   - `LogInvestigator`
   - `ThreatReasoner`
   - `ReportReviewer`
5. Review the `Final Approved Incident Blueprint` section at the bottom of the page.

## 5. What To Screenshot

For a clean submission screenshot, capture:

- The title and subtitle
- The logs input area
- The `Run Investigation` button
- The workflow card
- The three agent cards
- The final approved incident blueprint
- The terminal output showing the stage banners

## 6. Expected Terminal Output

When the investigation runs, the terminal should show lines like:

```text
[SentinelFlow] LogInvestigator: analyzing raw logs
[SentinelFlow] ThreatReasoner: building incident brief
[SentinelFlow] ReportReviewer: validating and approving the brief
```

## 7. Sample Input

The app already includes a sample log bundle, but you can paste this again if needed:

```text
[LOG] 2026-05-29T21:00:05Z - sshd[4112]: Failed password for invalid user root from 203.0.113.195 port 49210 ssh2
[LOG] 2026-05-29T21:00:10Z - sshd[4112]: Failed password for invalid user root from 203.0.113.195 port 49214 ssh2
[LOG] 2026-05-29T21:01:45Z - sshd[4122]: Accepted password for developer from 203.0.113.195 port 49302 ssh2
[LOG] 2026-05-29T21:02:12Z - sudo: developer : TTY=pts/1 ; PWD=/home/developer ; USER=root ; COMMAND=/usr/bin/apt-get install netcat
```

## 8. Troubleshooting

- If the app does not start, reinstall the packages in the same Python environment.
- If imports fail, check that no local file named `google.py`, `streamlit.py`, or `google/` is shadowing the installed packages.
- If `GOOGLE_API_KEY` is missing, the app still works using the local fallback pipeline.
- If port 8501 is busy, switch to another port such as 8502.

## 9. What The App Does

The workflow is:

1. `LogInvestigator` extracts indicators and a timeline from the raw logs.
2. `ThreatReasoner` turns those findings into a structured incident brief.
3. `ReportReviewer` checks realism and approves the final report.

The app is intentionally minimal, grayscale, and screenshot-friendly.