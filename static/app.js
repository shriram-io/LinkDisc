const mode = document.getElementById("analysis-mode");
const urlInput = document.getElementById("url-input");
const urlPanel = urlInput.closest(".scanner");
const messagePanel = document.getElementById("message-input-panel");
const messageInput = document.getElementById("message-input");
const messageButton = document.getElementById("message-scan-button");
const messageStatus = document.getElementById("message-status");
const messageResults = document.getElementById("message-results");

mode.addEventListener("change", () => {
    const messageMode = mode.value === "message";

    urlPanel.hidden = messageMode;
    messagePanel.hidden = !messageMode;
});

messageButton.addEventListener("click", analyzeMessage);

messageInput.addEventListener("keydown", (event) => {
    if (event.ctrlKey && event.key === "Enter") {
        analyzeMessage();
    }
});

async function analyzeMessage() {
    const message = messageInput.value.trim();

    messageStatus.textContent = "";
    messageResults.hidden = true;

    if (!message) {
        messageStatus.textContent = "Enter a message first.";
        return;
    }

    messageButton.disabled = true;
    messageButton.textContent = "Analyzing...";

    try {
        const response = await fetch("/api/analyze-message", {
            method: "POST",
            headers: {"Content-Type": "application/json"},
            body: JSON.stringify({message})
        });

        const data = await response.json();

        if (!response.ok) {
            throw new Error(data.error || "Analysis failed.");
        }

        const findings = Array.isArray(data.findings) ? data.findings : [];
        const contextNotes = Array.isArray(data.context_notes)
            ? data.context_notes
            : [];

        messageResults.textContent = [
            `Risk level: ${data.risk_level || "Unknown"}`,
            `Risk score: ${data.risk_score ?? "Unavailable"}/100`,
            "",
            "Findings:",
            ...(findings.length
                ? findings.map(item =>
                    typeof item === "string"
                        ? `- ${item}`
                        : `- ${item.finding || "Indicator detected"}${item.points != null ? ` (${item.points} points)` : ""}`)
                : ["- No configured warning patterns detected."]),
            ...(contextNotes.length
                ? ["", "Context notes:", ...contextNotes.map(note => `- ${note}`)]
                : []),
            "",
            data.limitations || "Automated analysis can make mistakes."
        ].join("\\n");

        messageResults.hidden = false;
    } catch (error) {
        messageStatus.textContent = error.message;
    } finally {
        messageButton.disabled = false;
        messageButton.textContent = "Analyze Message →";
    }
}

// Existing URL scanner
const scanButton = document.getElementById("scan-button");
const urlStatus = document.getElementById("message");
const urlResults = document.getElementById("results");

scanButton.addEventListener("click", scanURL);

urlInput.addEventListener("keydown", (event) => {
    if (event.key === "Enter") scanURL();
});

async function scanURL() {
    const url = urlInput.value.trim();
    urlStatus.textContent = "";
    urlResults.hidden = true;

    if (!url) {
        urlStatus.textContent = "Enter a URL first.";
        return;
    }

    scanButton.disabled = true;
    scanButton.textContent = "Scanning...";

    try {
        const response = await fetch("/api/scan", {
            method: "POST",
            headers: {"Content-Type": "application/json"},
            body: JSON.stringify({url})
        });

        const data = await response.json();

        if (!response.ok) throw new Error(data.error || "Scan failed.");

        displayResults(data);
        urlResults.hidden = false;
        urlResults.scrollIntoView({behavior: "smooth", block: "start"});
    } catch (error) {
        urlStatus.textContent = error.message;
    } finally {
        scanButton.disabled = false;
        scanButton.textContent = "Scan URL →";
    }
}

function displayResults(data) {
    document.getElementById("risk-score").textContent = data.risk_score;
    document.getElementById("risk-title").textContent =
        `${data.risk_level} Risk Indicators`;
    document.getElementById("hostname").textContent = data.hostname;
    document.getElementById("recommendation").textContent =
        data.recommendation;
    document.getElementById("limitations").textContent = data.limitations;

    const threat = data.threat_intelligence;
    const threatStatus = document.getElementById("threat-status");

    if (threatStatus) {
        threatStatus.textContent = !threat
            ? "Threat-intelligence result unavailable."
            : threat.status === "threat_detected"
                ? `THREAT MATCH: ${threat.message}`
                : threat.status === "no_match"
                    ? "No threat match reported. This does not prove safety."
                    : `Check unavailable: ${threat.message}`;
    }

    const badge = document.getElementById("risk-badge");
    badge.textContent = `${data.risk_level} Risk`;
    badge.className = `risk-badge ${data.risk_level.toLowerCase()}`;

    const findings = document.getElementById("findings");
    findings.replaceChildren();

    document.getElementById("no-findings").hidden =
        data.findings.length !== 0;

    data.findings.forEach((finding) => {
        const item = document.createElement("li");
        item.textContent = finding;
        findings.appendChild(item);
    });
}
const screenshotForm = document.getElementById("screenshot-form");

if (screenshotForm) {
    screenshotForm.addEventListener("submit", async (event) => {
        event.preventDefault();

        const fileInput = document.getElementById("screenshot-file");
        const status = document.getElementById("screenshot-status");
        const results = document.getElementById("screenshot-results");
        const button = document.getElementById("screenshot-scan-button");

        results.hidden = true;
        results.textContent = "";

        if (!fileInput.files || !fileInput.files[0]) {
            status.textContent = "Please select a screenshot first.";
            return;
        }

        const formData = new FormData();
        formData.append("screenshot", fileInput.files[0]);

        button.disabled = true;
        status.textContent = "Extracting text and analyzing screenshot...";

        try {
            const response = await fetch("/api/analyze-screenshot", {
                method: "POST",
                body: formData
            });

            const data = await response.json();

            if (!response.ok) {
                throw new Error(data.error || "Screenshot analysis failed.");
            }

            const analysis = data.analysis || {};
            const findings = Array.isArray(analysis.findings)
                ? analysis.findings
                : [];

            results.textContent = [
                "EXTRACTED TEXT",
                data.extracted_text || "No text extracted.",
                "",
                "RISK LEVEL",
                analysis.risk_level || analysis.risk || "Unknown",
                "",
                "RISK SCORE",
                String(analysis.risk_score ?? analysis.score ?? "Unavailable"),
                "",
                "FINDINGS",
                ...(findings.length ? findings : ["No specific indicators found."]),
                "",
                "LIMITATIONS",
                data.limitations || "Automated analysis can make mistakes."
            ].join("\n");

            results.hidden = false;
            status.textContent = "Screenshot analysis completed.";
        } catch (error) {
            status.textContent = error.message || "Unable to analyze screenshot.";
        } finally {
            button.disabled = false;
        }
    });
}

/* ===== LinkDisc cinematic startup controller ===== */
(() => {
    const screen = document.getElementById("startup-screen");
    if (!screen) return;

    const progressLabel = screen.querySelector(".startup-percent");

    const finishStartup = () => {
        if (screen.classList.contains("startup-hidden")) return;

        if (progressLabel) {
            progressLabel.textContent = "WORKSPACE READY";
        }

        screen.classList.add("startup-hidden");

        window.setTimeout(() => {
            if (screen.isConnected) screen.remove();
        }, 800);
    };

    const reducedMotion = window.matchMedia(
        "(prefers-reduced-motion: reduce)"
    ).matches;

    window.setTimeout(finishStartup, reducedMotion ? 100 : 2400);
})();
