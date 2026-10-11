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

        messageResults.textContent = [
            `Risk level: ${data.risk_level}`,
            `Risk score: ${data.risk_score}/100`,
            "",
            "Findings:",
            ...(data.findings.length
                ? data.findings.map(item =>
                    `- ${item.finding} (${item.points} points)`)
                : ["- No configured warning patterns detected."]),
            "",
            data.limitations
        ].join("\n");

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