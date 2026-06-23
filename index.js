const inputForm = document.getElementById("ip-input-form");
const inputBox = document.getElementById("ip-input-field");
const outputBox = document.getElementById("ip-output-field");

// Local Flask server when testing on your machine, Render when live - auto detected.
const API_BASE =
    location.hostname === "localhost" || location.hostname === "127.0.0.1"
        ? "http://127.0.0.1:5000"
        : "https://test-14rh.onrender.com";

// Each result category: the field name from the API, its label, and bar colour.
const CATEGORIES = [
    { key: "malicious",  label: "Malicious",  color: "#d90429" },
    { key: "suspicious", label: "Suspicious", color: "#ff9f1c" },
    { key: "undetected", label: "Undetected", color: "#6c757d" },
    { key: "harmless",   label: "Harmless",   color: "#2e6e37" },
];

// Write to the output element, handling both <input>/<textarea> and normal tags.
function displayOutput(message, isHtml = false) {
    const isField = outputBox.tagName === "INPUT" || outputBox.tagName === "TEXTAREA";
    if (isField) {
        outputBox.value = message.replace(/<br>/g, "\n").replace(/<[^>]*>/g, "");
    } else if (isHtml) {
        outputBox.innerHTML = message;
    } else {
        outputBox.textContent = message;
    }
}

// One labelled bar. Width is the value's share of the total so bars stay meaningful
// VirusTotal returns vendor counts, not percentages.
function resultBar({ label, color }, value, total) {
    const width = total > 0 ? (value / total) * 100 : 0;
    return `
        <div style="display: flex; align-items: center; gap: 20px; margin: 6px 0;">
            <strong style="width: 90px;">${label}:</strong>
            <span style="width: 32px; text-align: right;">${value}</span>
            <div style="width: 220px; background-color: #ddd; border-radius: 10px;">
                <div style="width: ${width}%; background-color: ${color}; height: 16px; border-radius: 10px;"></div>
            </div>
        </div>`;
}

// Build the whole results panel from the category list.
function renderResults(results) {
    const total = CATEGORIES.reduce((sum, c) => sum + results[c.key], 0);
    const bars = CATEGORIES.map(c => resultBar(c, results[c.key], total)).join("");
    return `
        <strong>VirusTotal Results for: ${results.ip_address}</strong>
        <div style="display: flex; flex-direction: column; align-items: center;">
            ${bars}
        </div>`;
}

async function eventHandler(event) {
    event.preventDefault();

    const ipAddress = inputBox.value.trim();
    displayOutput("Checking IP address...");

    try {
        const response = await fetch(`${API_BASE}/api/ip-reputation`, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ ip_address: ipAddress }),
        });

        const data = await response.json();

        if (!response.ok || !data.success) {
            displayOutput("Error: " + data.error);
            return;
        }

        displayOutput(renderResults(data.results), true);
        console.log("IP check completed:", data.results);

    } catch (error) {
        // Live setup message, as redner.com server needs to wake up. 
        displayOutput("Couldn't reach the server — it may be waking up, try again in a moment.");
        console.error("Connection error:", error);
    }
}

inputForm.addEventListener("submit", eventHandler);