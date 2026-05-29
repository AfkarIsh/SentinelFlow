# SentinelFlow

SentinelFlow is a backend-first, single-page Streamlit demo that presents a multi-agent SOC incident response pipeline. It is designed for a hackathon submission where the goal is to show a successful multi-agent execution in the terminal and on screen, without building a separate frontend application.

## What It Does

SentinelFlow accepts a suspicious log bundle, analyzes it through a sequential multi-agent workflow, and returns a final approved incident blueprint.

The output includes:

- Incident summary
- Severity level
- Indicators of compromise
- Attack timeline
- Likely attack pattern
- Recommended remediation actions
- Reviewer approval note

## Project Structure

The project is intentionally minimal.

- `app.py` contains the Streamlit UI and the backend investigation pipeline.
- There is no database.
- There is no separate frontend framework.
- There is no Docker setup.

## Architecture

The app uses a simple sequential pipeline:

1. `LogInvestigator`
2. `ThreatReasoner`
3. `ReportReviewer`

The code is written so it can run in two modes:

- ADK mode when `GOOGLE_API_KEY` is available
- Local fallback mode when credentials are not present

This makes the demo safer for deadline use because the app still runs even if the Google model path is unavailable.

## How The Agents Work

### 1. LogInvestigator

Role: Tier-2 SOC analyst.

This agent inspects raw logs and extracts evidence such as:

- Suspicious IP addresses
- Usernames
- Failed login attempts
- Successful login events
- Privilege escalation activity
- Suspicious commands

It also builds a concise event timeline.

### 2. ThreatReasoner

Role: Incident commander.

This agent reviews the investigator findings and turns them into a structured incident brief. It classifies the likely attack vector, estimates severity, explains impact, and recommends containment and remediation.

### 3. ReportReviewer

Role: Senior security architect.

This agent reviews the incident brief for realism and consistency, removes unsupported claims, and approves the final report.

## UI Summary

The Streamlit page is intentionally minimal and grayscale:

- Title: SentinelFlow
- Subtitle: Multi-Agent SOC Incident Response System
- Text area for suspicious logs
- Run Investigation button
- Three agent cards
- Workflow card labeled Sequential Multi-Agent Pipeline
- Final Approved Incident Blueprint panel

The page is designed to be screenshot-friendly for a hackathon demo.

## Runtime Requirements

Recommended:

- Python 3.11 or newer

Packages used:

- streamlit
- google-adk
- google-genai

## Install

Use the same Python interpreter for install and run.

```powershell
python -m pip install streamlit google-adk google-genai
```

If you want to use the Google model path, add a local `.env` file with your key:

```text
GOOGLE_API_KEY=your_key_here
```

This file is ignored by git, so your personal key stays local. If the variable is not set, the app uses the local sequential fallback.

## Run

```powershell
python -m streamlit run app.py
```

If port 8501 is busy, use a different port:

```powershell
python -m streamlit run app.py --server.port 8502
```

If your system needs a specific interpreter path, replace `python` with your local Python executable.

## Sample Input

The app includes a default SOC log sample:

```text
[LOG] 2026-05-29T21:00:05Z - sshd[4112]: Failed password for invalid user root from 203.0.113.195 port 49210 ssh2
[LOG] 2026-05-29T21:00:10Z - sshd[4112]: Failed password for invalid user root from 203.0.113.195 port 49214 ssh2
[LOG] 2026-05-29T21:01:45Z - sshd[4122]: Accepted password for developer from 203.0.113.195 port 49302 ssh2
[LOG] 2026-05-29T21:02:12Z - sudo: developer : TTY=pts/1 ; PWD=/home/developer ; USER=root ; COMMAND=/usr/bin/apt-get install netcat
```

## Expected Terminal Output

When the investigation runs, the terminal prints stage banners such as:

```text
[SentinelFlow] LogInvestigator: analyzing raw logs
[SentinelFlow] ThreatReasoner: building incident brief
[SentinelFlow] ReportReviewer: validating and approving the brief
```

That output is what you can capture in a terminal screenshot to prove the multi-agent pipeline executed.

## Screenshot Checklist

For a clean hackathon submission screenshot, show:

1. The page title and subtitle.
2. The text area containing the logs.
3. The Run Investigation button.
4. The workflow card.
5. The three agent cards.
6. The final approved incident blueprint.
7. The terminal output with the stage banners.

## Troubleshooting

If the app fails to start:

- Reinstall Streamlit and the ADK packages in the same Python environment.
- Verify that `google.adk` and `google.genai` import correctly.
- Check for local files named `google.py`, `streamlit.py`, or `google/` that may shadow the installed packages.
- If `GOOGLE_API_KEY` is not set, the app will still run using the local fallback pipeline.

## Why This Is Submission-Safe

This implementation is suitable for a deadline because it:

- Stays in one file for the executable app
- Avoids frontend complexity
- Uses an installed ADK runtime path when credentials are present
- Still works without credentials
- Prints clear terminal stage banners for screenshot proof
- Produces a final approved incident blueprint that looks like a real SOC workflow result

## Notes

The current code intentionally favors stability over over-engineering. If you want to extend it later, the easiest next step would be to add structured model output or a richer evidence parser, but that is not required for the hackathon submission.
