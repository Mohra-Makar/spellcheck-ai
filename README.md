# 🛡️ SpellCheck AI - Security Gateway & Analytics Dashboard

A security-focused LLM Proxy designed to detect and mitigate prompt injection, jailbreaks, system prompt leaking, and adversarial threats in real-time before reaching upstream LLMs.

## 🚀 Features
- **FastAPI Reverse Proxy:** Intercepts incoming LLM prompts with near-zero latency overhead.
- **OWASP LLM Top 10 Coverage:** Detects Direct Prompt Injection, System Prompt Leaking, Jailbreak/Persona Overrides, and Adversarial Roleplay.
- **Real-time Logging:** Audit logs stored locally in `security_logs.csv`.
- **Streamlit Analytics Dashboard:** Visual insights, threat level metrics, and an interactive **Prompt Tester UI**.

## 🛠️ Tech Stack
- **Backend:** Python 3.15, FastAPI, Uvicorn
- **Frontend & Analytics:** Streamlit, Pandas
- **Testing:** Requests, PowerShell `Invoke-RestMethod`

## 📦 How to Run Locally

1. **Clone the repository:**
   ```bash
   git clone [https://github.com/YOUR_USERNAME/spellcheck-ai.git](https://github.com/YOUR_USERNAME/spellcheck-ai.git)
   cd spellcheck-ai