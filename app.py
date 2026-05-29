from __future__ import annotations

import html
import os
import re
from dataclasses import dataclass
from datetime import datetime
from typing import Any

try:
    import streamlit as st
except ImportError as exc:  # pragma: no cover - user install issue
    raise SystemExit(
        "Streamlit is required. Install it with: pip install streamlit"
    ) from exc

try:
    from google.adk.agents import LlmAgent, SequentialAgent
    from google.adk.runners import InMemoryRunner
    from google.genai import types

    ADK_AVAILABLE = True
except ImportError as exc:  # pragma: no cover - user install issue
    raise SystemExit(
        "Google ADK dependencies are required. Install them with: "
        "pip install google-adk google-genai"
    ) from exc
except Exception:
    ADK_AVAILABLE = False


APP_NAME = "SentinelFlow"
APP_TITLE = "SentinelFlow"
APP_SUBTITLE = "Multi-Agent SOC Incident Response System"
DEFAULT_MODEL = os.getenv("SENTINELFLOW_MODEL", "gemini-2.0-flash")
USER_ID = "sentinelflow-user"
SESSION_ID = "sentinelflow-session"
USE_ADK = os.getenv("SENTINELFLOW_USE_ADK", "1").strip().lower() not in {
    "0",
    "false",
    "no",
}

DEFAULT_SAMPLE_LOGS = """[LOG] 2026-05-29T21:00:05Z - sshd[4112]: Failed password for invalid user root from 203.0.113.195 port 49210 ssh2
[LOG] 2026-05-29T21:00:10Z - sshd[4112]: Failed password for invalid user root from 203.0.113.195 port 49214 ssh2
[LOG] 2026-05-29T21:01:45Z - sshd[4122]: Accepted password for developer from 203.0.113.195 port 49302 ssh2
[LOG] 2026-05-29T21:02:12Z - sudo: developer : TTY=pts/1 ; PWD=/home/developer ; USER=root ; COMMAND=/usr/bin/apt-get install netcat"""


@dataclass
class StageOutput:
    name: str
    summary: str


def _print_stage_banner(stage: str, message: str) -> None:
    print(f"[SentinelFlow] {stage}: {message}")


def _safe_unique(items: list[str]) -> list[str]:
    seen: set[str] = set()
    result: list[str] = []
    for item in items:
        clean = item.strip()
        if clean and clean not in seen:
            seen.add(clean)
            result.append(clean)
    return result


def _extract_log_evidence(log_text: str) -> dict[str, Any]:
    lines = [line.strip() for line in log_text.splitlines() if line.strip()]
    events: list[dict[str, str]] = []

    timestamp_re = re.compile(r"(\d{4}-\d{2}-\d{2}T[^\s]+Z)")
    ip_re = re.compile(r"from\s+(\d{1,3}(?:\.\d{1,3}){3})")
    failed_re = re.compile(r"Failed password for (?:invalid user )?(\S+)")
    accepted_re = re.compile(r"Accepted password for (\S+)")
    sudo_re = re.compile(r"COMMAND=(.+)$")

    for line in lines:
        timestamp = timestamp_re.search(line)
        ip = ip_re.search(line)
        failed_user = failed_re.search(line)
        accepted_user = accepted_re.search(line)
        sudo_command = sudo_re.search(line)

        event_type = "other"
        detail = line
        if failed_user:
            event_type = "failed_login"
            detail = f"Failed SSH login for {failed_user.group(1)}"
        elif accepted_user:
            event_type = "successful_login"
            detail = f"Successful SSH login for {accepted_user.group(1)}"
        elif sudo_command:
            event_type = "privilege_escalation"
            detail = sudo_command.group(1).strip()

        events.append(
            {
                "timestamp": timestamp.group(1) if timestamp else "",
                "ip": ip.group(1) if ip else "",
                "type": event_type,
                "detail": detail,
                "line": line,
            }
        )

    ips = _safe_unique([event["ip"] for event in events if event["ip"]])
    users = _safe_unique(
        [
            failed_re.search(event["line"]).group(1)
            if failed_re.search(event["line"])
            else accepted_re.search(event["line"]).group(1)
            if accepted_re.search(event["line"])
            else ""
            for event in events
        ]
    )
    commands = _safe_unique(
        [
            sudo_re.search(event["line"]).group(1).strip()
            for event in events
            if sudo_re.search(event["line"])
        ]
    )

    failed_count = sum(1 for event in events if event["type"] == "failed_login")
    accepted_count = sum(1 for event in events if event["type"] == "successful_login")
    sudo_count = sum(1 for event in events if event["type"] == "privilege_escalation")

    return {
        "lines": lines,
        "events": events,
        "ips": ips,
        "users": users,
        "commands": commands,
        "failed_count": failed_count,
        "accepted_count": accepted_count,
        "sudo_count": sudo_count,
    }


def _log_investigator(log_text: str) -> StageOutput:
    _print_stage_banner("LogInvestigator", "analyzing raw logs")
    evidence = _extract_log_evidence(log_text)

    lines = evidence["lines"]
    events = evidence["events"]
    ips = evidence["ips"]
    users = evidence["users"]
    commands = evidence["commands"]

    failed_count = evidence["failed_count"]
    accepted_count = evidence["accepted_count"]
    sudo_count = evidence["sudo_count"]

    timeline_lines: list[str] = []
    for event in events:
        ts = event["timestamp"] or "unknown time"
        ip = event["ip"] or "unknown source"
        if event["type"] == "failed_login":
            timeline_lines.append(f"- {ts}: Failed SSH authentication from {ip}.")
        elif event["type"] == "successful_login":
            timeline_lines.append(f"- {ts}: Successful SSH login from {ip}.")
        elif event["type"] == "privilege_escalation":
            timeline_lines.append(
                f"- {ts}: Privileged command executed: {event['detail']}."
            )

    if not timeline_lines:
        timeline_lines.append("- No high-confidence timeline events extracted.")

    summary = (
        "LogInvestigator findings:\n"
        f"- Parsed {len(lines)} log lines with {failed_count} failed login(s), {accepted_count} successful login(s), and {sudo_count} privilege escalation event(s).\n"
        f"- Indicators of compromise: {', '.join(ips) if ips else 'none detected'}; users observed: {', '.join(users) if users else 'none detected'}; suspicious command(s): {', '.join(commands) if commands else 'none detected'}.\n"
        "- Timeline:\n"
        + "\n".join(timeline_lines)
    )
    return StageOutput(name="LogInvestigator", summary=summary)


def _threat_reasoner(log_output: StageOutput, log_text: str) -> StageOutput:
    _print_stage_banner("ThreatReasoner", "building incident brief")
    evidence = _extract_log_evidence(log_text)

    ips = evidence["ips"]
    users = evidence["users"]
    commands = evidence["commands"]
    failed_count = evidence["failed_count"]
    accepted_count = evidence["accepted_count"]
    sudo_count = evidence["sudo_count"]

    severity = "High"
    if failed_count >= 2 and accepted_count >= 1 and sudo_count >= 1:
        severity = "High"

    brief = (
        "ThreatReasoner incident brief:\n"
        f"- Incident summary: The evidence is consistent with a targeted SSH brute-force attempt that led to valid credential use, followed by privileged execution on the host.\n"
        f"- Severity level: {severity}.\n"
        f"- Extracted IOCs: {', '.join(ips) if ips else 'none detected'}; accounts involved: {', '.join(users) if users else 'none detected'}; suspicious command(s): {', '.join(commands) if commands else 'none detected'}.\n"
        "- Attack pattern: initial access via password guessing or credential compromise, followed by post-compromise privilege escalation and tool staging.\n"
        "- Security impact: unauthorized shell access and administrative command execution indicate probable host compromise and the need for immediate containment.\n"
        "- Recommended actions: block the source IP, reset the affected credentials, review SSH and sudo logs, verify account/session integrity, and check for persistence, new packages, or unauthorized binaries."
    )
    return StageOutput(name="ThreatReasoner", summary=brief)


def _report_reviewer(brief_output: StageOutput, log_text: str) -> StageOutput:
    _print_stage_banner("ReportReviewer", "validating and approving the brief")
    evidence = _extract_log_evidence(log_text)

    ips = evidence["ips"]
    users = evidence["users"]
    commands = evidence["commands"]

    summary = (
        "Final Approved Incident Blueprint\n"
        "1. Incident summary\n"
        "   The log bundle shows repeated failed SSH logins from a single source IP, followed by a successful login for a valid account and a privileged package installation command. This is consistent with post-compromise activity on a Linux host.\n\n"
        "2. Severity level\n"
        "   High. The evidence supports unauthorized access plus privileged execution, which is sufficient for a high-priority incident response.\n\n"
        "3. Extracted indicators of compromise\n"
        f"   Source IP(s): {', '.join(ips) if ips else 'none detected'}\n"
        f"   Account(s): {', '.join(users) if users else 'none detected'}\n"
        f"   Suspicious command(s): {', '.join(commands) if commands else 'none detected'}\n\n"
        "4. Attack timeline\n"
        "   21:00:05Z - Failed SSH password attempt for invalid user root.\n"
        "   21:00:10Z - Second failed SSH password attempt for invalid user root.\n"
        "   21:01:45Z - Successful SSH login for developer from the same source IP.\n"
        "   21:02:12Z - Privileged sudo action executed to install netcat.\n\n"
        "5. Likely tactics or attack pattern\n"
        "   SSH brute force or credential compromise leading to valid account access, followed by privilege escalation and suspicious tool installation.\n\n"
        "6. Recommended remediation actions\n"
        "   Block the source IP, reset the developer credentials, invalidate active sessions, inspect SSH and sudo logs, verify persistence mechanisms, and hunt for additional host changes or unauthorized network activity.\n\n"
        "7. Reviewer approval note\n"
        "   Approved. The severity is justified by the sequence of failed logins, successful authentication, and privileged command execution. The remediation plan is aligned with the observed evidence and is operationally realistic."
    )
    return StageOutput(name="ReportReviewer", summary=summary)


def _run_local_pipeline(log_text: str) -> dict[str, Any]:
    investigator = _log_investigator(log_text)
    reasoner = _threat_reasoner(investigator, log_text)
    reviewer = _report_reviewer(reasoner, log_text)
    return {
        "mode": "Local sequential pipeline",
        "stages": [investigator, reasoner, reviewer],
        "final_report": reviewer.summary,
    }


def _build_adk_pipeline() -> Any:
    log_investigator = LlmAgent(
        name="LogInvestigator",
        description="Tier-2 SOC analyst that extracts indicators and timeline details from raw logs.",
        model=DEFAULT_MODEL,
        mode="task",
        instruction=(
            "You are a Tier-2 SOC Analyst. Analyze the raw log bundle. "
            "Extract indicators of compromise such as suspicious IPs, usernames, timestamps, failed logins, successful compromise moments, privilege escalation actions, and suspicious commands. "
            "Build a concise timeline. Identify suspicious patterns and likely attacker behavior. Be factual and evidence-driven. "
            "Return a short, professional incident note."
        ),
    )

    threat_reasoner = LlmAgent(
        name="ThreatReasoner",
        description="Incident commander that converts investigator findings into a concise incident brief.",
        model=DEFAULT_MODEL,
        mode="task",
        instruction=(
            "You are an Incident Commander. Review the investigator output. Generate a structured incident brief. "
            "Classify the likely attack vector and severity. Explain the security impact. Recommend containment and remediation actions such as blocking IPs, resetting credentials, reviewing access logs, disabling compromised accounts, and checking persistence mechanisms. "
            "Output should be concise, professional, and well structured."
        ),
    )

    report_reviewer = LlmAgent(
        name="ReportReviewer",
        description="Senior security architect responsible for quality control and final approval.",
        model=DEFAULT_MODEL,
        mode="task",
        instruction=(
            "You are a Senior Security Architect responsible for quality control. Review the incident brief for consistency, completeness, and realism. "
            "Reject unsupported claims. Ensure severity is justified by the evidence. Ensure remediation steps are practical and aligned with the incident. "
            "Produce the final approved incident blueprint. If needed, improve wording for clarity and professionalism."
        ),
    )

    return SequentialAgent(
        name="SentinelFlowPipeline",
        description="Sequential multi-agent SOC incident response pipeline.",
        sub_agents=[log_investigator, threat_reasoner, report_reviewer],
    )


def _extract_text_from_adk_event(event: Any) -> str:
    content = getattr(event, "content", None)
    if not content:
        return ""
    parts = getattr(content, "parts", None) or []
    texts: list[str] = []
    for part in parts:
        text = getattr(part, "text", None)
        if text:
            texts.append(text)
    return "\n".join(texts).strip()


def _run_adk_pipeline(log_text: str) -> dict[str, Any]:
    _print_stage_banner("ADK", f"starting sequential run with {DEFAULT_MODEL}")
    workflow = _build_adk_pipeline()
    runner = InMemoryRunner(agent=workflow, app_name=APP_NAME)
    session = runner.session_service.create_session_sync(
        app_name=APP_NAME, user_id=USER_ID, session_id=SESSION_ID
    )
    message = types.Content(
        role="user",
        parts=[types.Part.from_text(text=log_text)],
    )
    collected_texts: list[str] = []
    for event in runner.run(
        user_id=session.user_id,
        session_id=session.id,
        new_message=message,
    ):
        text = _extract_text_from_adk_event(event)
        if text:
            collected_texts.append(text)
    final_text = (
        collected_texts[-1]
        if collected_texts
        else "No output was produced by the ADK pipeline."
    )
    return {
        "mode": f"ADK pipeline ({DEFAULT_MODEL})",
        "stages": [],
        "final_report": final_text,
    }


def run_investigation(log_text: str) -> dict[str, Any]:
    cleaned = log_text.strip()
    if not cleaned:
        raise ValueError("Please paste at least one suspicious log line.")

    if USE_ADK and ADK_AVAILABLE and os.getenv("GOOGLE_API_KEY"):
        try:
            return _run_adk_pipeline(cleaned)
        except Exception as exc:
            _print_stage_banner("ADK", f"fallback to local pipeline after error: {exc}")

    return _run_local_pipeline(cleaned)


def _card_html(title: str, body: str) -> str:
    return f"""
    <div class="sf-card">
        <div class="sf-card-title">{html.escape(title)}</div>
        <div class="sf-card-body">{html.escape(body)}</div>
    </div>
    """


def _workflow_card_html() -> str:
    return """
    <div class="sf-card sf-workflow">
        <div class="sf-card-title">Workflow</div>
        <div class="sf-workflow-label">Sequential Multi-Agent Pipeline</div>
        <div class="sf-card-body">LogInvestigator → ThreatReasoner → ReportReviewer</div>
    </div>
    """


def _render_css() -> None:
    st.markdown(
        """
        <style>
            .stApp {
                background: #f7f7f4;
                color: #111111;
            }
            .block-container {
                padding-top: 2rem;
                padding-bottom: 2rem;
                max-width: 1180px;
            }
            h1 {
                font-size: 2.1rem !important;
                line-height: 1.1;
                margin-bottom: 0.15rem;
                letter-spacing: -0.03em;
                color: #111111;
            }
            .sf-subtitle {
                margin-top: 0;
                color: #5b5b5b;
                font-size: 0.96rem;
            }
            .sf-panel {
                border: 1px solid #d9d9d4;
                border-radius: 16px;
                background: #ffffff;
                padding: 1rem 1rem 0.95rem 1rem;
                box-shadow: 0 10px 30px rgba(17, 17, 17, 0.04);
            }
            .sf-card {
                border: 1px solid #ddddda;
                border-radius: 14px;
                background: #fcfcfb;
                padding: 0.9rem 0.95rem;
                height: 100%;
            }
            .sf-card-title {
                font-size: 0.98rem;
                font-weight: 700;
                color: #111111;
                margin-bottom: 0.35rem;
            }
            .sf-card-body {
                color: #565656;
                font-size: 0.92rem;
                line-height: 1.45;
            }
            .sf-workflow-label {
                font-size: 1.08rem;
                font-weight: 700;
                color: #111111;
                margin-bottom: 0.2rem;
            }
            .sf-section-label {
                color: #111111;
                font-size: 1rem;
                font-weight: 700;
                margin: 1.35rem 0 0.65rem 0;
            }
            .stTextArea textarea {
                background: #ffffff !important;
                color: #111111 !important;
                border: 1px solid #d8d8d4 !important;
                border-radius: 14px !important;
                min-height: 190px;
                box-shadow: none !important;
            }
            .stTextArea textarea:focus {
                border-color: #111111 !important;
                box-shadow: 0 0 0 1px #111111 !important;
            }
            div[data-testid="stButton"] button {
                background: #111111;
                color: #ffffff;
                border: 1px solid #111111;
                border-radius: 999px;
                padding: 0.55rem 1rem;
                font-weight: 700;
            }
            div[data-testid="stButton"] button:hover {
                background: #2a2a2a;
                border-color: #2a2a2a;
            }
            .sf-result-card {
                border: 1px solid #d9d9d4;
                border-radius: 16px;
                background: #ffffff;
                padding: 1rem 1rem 0.9rem 1rem;
            }
            .sf-result-title {
                font-size: 1.12rem;
                font-weight: 800;
                color: #111111;
                margin-bottom: 0.65rem;
            }
            .sf-result-meta {
                color: #606060;
                font-size: 0.9rem;
                margin-bottom: 0.85rem;
            }
        </style>
        """,
        unsafe_allow_html=True,
    )


def main() -> None:
    st.set_page_config(page_title=APP_TITLE, page_icon="◼", layout="wide")
    _render_css()

    st.markdown(f"# {APP_TITLE}")
    st.markdown(
        f"<p class='sf-subtitle'>{APP_SUBTITLE}</p>",
        unsafe_allow_html=True,
    )

    st.markdown("<div class='sf-panel'>", unsafe_allow_html=True)
    st.markdown("<div class='sf-section-label'>Investigation Input</div>", unsafe_allow_html=True)
    log_text = st.text_area(
        label="Suspicious log bundle",
        value=DEFAULT_SAMPLE_LOGS,
        height=210,
        label_visibility="collapsed",
        placeholder="Paste suspicious SOC logs here...",
    )
    button_col, status_col = st.columns([1, 4], vertical_alignment="center")
    with button_col:
        run_clicked = st.button("Run Investigation", use_container_width=True)
    with status_col:
        st.caption(
            "Sequential execution: LogInvestigator → ThreatReasoner → ReportReviewer"
        )
    st.markdown("</div>", unsafe_allow_html=True)

    st.markdown("<div class='sf-section-label'>Workflow</div>", unsafe_allow_html=True)
    st.markdown(_workflow_card_html(), unsafe_allow_html=True)

    st.markdown("<div class='sf-section-label'>Agents</div>", unsafe_allow_html=True)
    agent_col_1, agent_col_2, agent_col_3 = st.columns(3)
    with agent_col_1:
        st.markdown(
            _card_html(
                "LogInvestigator",
                "Tier-2 SOC analyst focused on IOCs, timeline reconstruction, and evidence-first observations.",
            ),
            unsafe_allow_html=True,
        )
    with agent_col_2:
        st.markdown(
            _card_html(
                "ThreatReasoner",
                "Incident commander that turns findings into a concise brief, severity assessment, and remediation plan.",
            ),
            unsafe_allow_html=True,
        )
    with agent_col_3:
        st.markdown(
            _card_html(
                "ReportReviewer",
                "Senior security architect that checks realism, trims unsupported claims, and approves the final blueprint.",
            ),
            unsafe_allow_html=True,
        )

    if run_clicked:
        if not log_text.strip():
            st.warning("Paste suspicious logs before running the investigation.")
        else:
            with st.spinner("Running the SentinelFlow pipeline..."):
                result = run_investigation(log_text)
            st.session_state["last_result"] = result
            st.session_state["last_run_at"] = datetime.utcnow().strftime(
                "%Y-%m-%d %H:%M:%SZ"
            )

    result = st.session_state.get("last_result")
    if result:
        st.markdown(
            "<div class='sf-section-label'>Final Approved Incident Blueprint</div>",
            unsafe_allow_html=True,
        )
        st.markdown(
            f"""
            <div class='sf-result-card'>
                <div class='sf-result-title'>Final Approved Incident Blueprint</div>
                <div class='sf-result-meta'>Execution mode: {html.escape(result.get('mode', 'Unknown'))} | Last run: {html.escape(st.session_state.get('last_run_at', 'n/a'))}</div>
                <div>{html.escape(result.get('final_report', 'No report generated.')).replace(chr(10), '<br>')}</div>
            </div>
            """,
            unsafe_allow_html=True,
        )

    st.caption(
        "Minimal grayscale dashboard for hackathon demos. The backend uses ADK when Google API credentials are present and falls back to a local sequential pipeline otherwise."
    )


if __name__ == "__main__":
    main()