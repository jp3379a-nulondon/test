
const inputForm = document.getElementById("ip-input-form");
const inputBox = document.getElementById("ip-input-field");
const outputBox = document.getElementById("ip-output-field");

// Disaplay output
function displayOutput(message, isHtml = false) {
    if (outputBox.tagName === "INPUT" || outputBox.tagName === "TEXTAREA") {
        outputBox.value = message.replace(/<br>/g, "\n").replace(/<[^>]*>/g, "");
    } else {
        if (isHtml) {
            outputBox.innerHTML = message;
        } else {
            outputBox.textContent = message;
        }
    }
}

// Create percent bars
function createResultBar(label, value, className) {
    const percentage = Math.min(value, 100);

    return `
        <div class="result_bar_group">
            <div class="result_bar_label">
                <span>${label}</span>
                <span>${value}/100</span>
            </div>

            <div class="result_bar_background">
                <div class="result_bar_fill ${className}" style="width: ${percentage}%;"></div>
            </div>
        </div>
    `;
}


// Call API via python script
async function eventHandler(event) {
    event.preventDefault();

    // Creating a variable from the user input 
    const ipAddress = inputBox.value.trim();

    displayOutput("Checking IP address...");

    // Sending the user input to the API via the local python server
    try {
        const response = await fetch("http://127.0.0.1:5000/api/ip-reputation", {
            method: "POST",
            headers: {
                "Content-Type": "application/json"
            },
            body: JSON.stringify({
                ip_address: ipAddress
            })
        });

        // Creating a variable with the results from the API call
        const data = await response.json();

        // Error checking the result from the API call
        if (!response.ok || !data.success) {
            displayOutput("Error: " + data.error);
            return;
        }

        const results = data.results;

        const output = `
            <strong>VirusTotal Results for: ${results.ip_address}</strong><br>

            <div style="display: flex; flex-direction: column; align-items: center;">

            
                <div style="display: flex; align-items: center; gap: 20px; margin: 6px 0;">
                    <strong style="width: 90px;">Malicious: </strong>
                    <div style="width: 220px; background-color: #ddd; border-radius: 10px;">
                        <div style="width: ${results.malicious}%; background-color: #d90429; height: 16px; border-radius: 10px;"></div>
                    </div>
                </div>

                <div style="display: flex; align-items: center; gap: 20px; margin: 6px 0;">
                    <strong style="width: 90px;">Suspicious: </strong>
                    <div style="width: 220px; background-color: #ddd; border-radius: 10px;">
                        <div style="width: ${results.suspicious}%; background-color: #ff9f1c; height: 16px; border-radius: 10px;"></div>
                    </div>
                </div>

                <div style="display: flex; align-items: center; gap: 20px; margin: 6px 0;">
                    <strong style="width: 90px;">Undetected:</strong>
                    <div style="width: 220px; background-color: #ddd; border-radius: 10px;">
                        <div style="width: ${results.undetected}%; background-color: #6c757d; height: 16px; border-radius: 10px;"></div>
                    </div>
                </div>

                <div style="display: flex; align-items: center; gap: 20px; margin: 6px 0;">
                    <strong style="width: 90px;">Harmless:</strong>
                    <div style="width: 220px; background-color: #ddd; border-radius: 10px;">
                        <div style="width: ${results.harmless}%; background-color: #2e6e37; height: 16px; border-radius: 10px;"></div>
                    </div>
                </div>
            </div>    
    `;

        displayOutput(output, true);
        console.log("IP check completed:", results);

    } catch (error) {
        displayOutput("Error: Could not connect to the Python Flask server. Make sure app.py is running.");
        console.error("Connection error:", error);
    }
}

inputForm.addEventListener("submit", eventHandler);

