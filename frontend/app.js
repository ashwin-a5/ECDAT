/*
 * ECDAT - Enterprise Cryptographic Discovery & Analysis Tool
 * Frontend Application
 */

const API_URL = "";

let currentScanId = null;
let allFindings = [];


/* =========================================================
   Utility Functions
========================================================= */

function setText(id, value) {
    const element = document.getElementById(id);

    if (element) {
        element.textContent = value ?? 0;
    }
}


function escapeHtml(value) {
    return String(value ?? "")
        .replace(/&/g, "&amp;")
        .replace(/</g, "&lt;")
        .replace(/>/g, "&gt;")
        .replace(/"/g, "&quot;")
        .replace(/'/g, "&#039;");
}


function normalizeValue(value) {
    return String(value ?? "")
        .trim()
        .toLowerCase();
}


/* =========================================================
   Scan
========================================================= */

async function runScan() {

    const directoryInput =
        document.getElementById("directory");

    const scanButton =
        document.querySelector(".scanner button");

    const exportButton =
        document.getElementById("export-button");

    const directory =
        directoryInput.value.trim();


    if (!directory) {
        alert("Please enter a directory to scan.");
        return;
    }


    scanButton.disabled = true;
    scanButton.textContent = "Scanning...";


    if (exportButton) {
        exportButton.disabled = true;
    }


    currentScanId = null;


    try {

        const response = await fetch(
            "/scan",
            {
                method: "POST",

                headers: {
                    "Content-Type": "application/json"
                },

                body: JSON.stringify({
                    directory: directory
                })
            }
        );


        if (!response.ok) {
            throw new Error(
                `Server returned HTTP ${response.status}`
            );
        }


        const data = await response.json();


        console.log(
            "ECDAT scan response:",
            data
        );


        currentScanId =
            data.scan_id;


        allFindings =
            Array.isArray(data.findings)
                ? data.findings
                : [];


        updateDashboard(
            data.summary || {}
        );


        updateSecurityStatus(
            data.summary || {}
        );


        resetFilters();


        displayFindings(
            allFindings
        );


        if (currentScanId && exportButton) {
            exportButton.disabled = false;
        }


        await loadHistory();


    } catch (error) {

        console.error(
            "ECDAT scan error:",
            error
        );


        alert(
            "ECDAT could not complete the scan.\n\n" +
            error.message
        );


    } finally {

        scanButton.disabled = false;
        scanButton.textContent = "Scan";
    }
}


/* =========================================================
   Dashboard
========================================================= */

function updateDashboard(summary) {

    setText(
        "files-scanned",
        summary.files_scanned || 0
    );


    setText(
        "total",
        summary.total_findings || 0
    );


    setText(
        "critical",
        summary.critical || 0
    );


    setText(
        "high",
        summary.high || 0
    );


    setText(
        "medium",
        summary.medium || 0
    );


    setText(
        "low",
        summary.low || 0
    );


    setText(
        "info",
        summary.info || 0
    );


    setText(
        "risk",
        summary.total_risk_score || 0
    );
}


/* =========================================================
   Security Status
========================================================= */

function updateSecurityStatus(summary) {

    const statusBox =
        document.getElementById(
            "security-status"
        );

    const title =
        document.getElementById(
            "security-title"
        );

    const message =
        document.getElementById(
            "security-message"
        );

    const score =
        document.getElementById(
            "security-risk"
        );


    if (
        !statusBox ||
        !title ||
        !message ||
        !score
    ) {
        return;
    }


    const critical =
        Number(summary.critical || 0);

    const high =
        Number(summary.high || 0);

    const medium =
        Number(summary.medium || 0);

    const low =
        Number(summary.low || 0);

    const risk =
        Number(summary.total_risk_score || 0);


    score.textContent = risk;


    statusBox.classList.remove(
        "neutral",
        "safe",
        "warning",
        "danger"
    );


    if (critical > 0) {

        statusBox.classList.add(
            "danger"
        );

        title.textContent =
            "CRITICAL RISK";

        message.textContent =
            `${critical} critical finding${
                critical === 1 ? "" : "s"
            } detected. Immediate remediation is recommended.`;

        return;
    }


    if (high > 0) {

        statusBox.classList.add(
            "warning"
        );

        title.textContent =
            "HIGH RISK";

        message.textContent =
            `${high} high-severity finding${
                high === 1 ? "" : "s"
            } detected. Review the findings promptly.`;

        return;
    }


    if (medium > 0) {

        statusBox.classList.add(
            "warning"
        );

        title.textContent =
            "MEDIUM RISK";

        message.textContent =
            `${medium} medium-severity finding${
                medium === 1 ? "" : "s"
            } detected.`;

        return;
    }


    if (low > 0 || risk > 0) {

        statusBox.classList.add(
            "warning"
        );

        title.textContent =
            "REVIEW REQUIRED";

        message.textContent =
            "Potential cryptographic security issues were detected.";

        return;
    }


    statusBox.classList.add(
        "safe"
    );

    title.textContent =
        "LOW RISK";

    message.textContent =
        "No significant cryptographic risks were detected.";
}


/* =========================================================
   Findings
========================================================= */

function displayFindings(findings) {

    const results =
        document.getElementById(
            "results"
        );

    const count =
        document.getElementById(
            "finding-count"
        );


    if (!results) {
        return;
    }


    const total =
        Array.isArray(findings)
            ? findings.length
            : 0;


    if (count) {
        count.textContent =
            `${total} finding${
                total === 1 ? "" : "s"
            }`;
    }


    if (total === 0) {

        const hasActiveFilter =
            getActiveFilterState();


        if (hasActiveFilter) {

            results.innerHTML = `
                <div class="empty-state">

                    <h3>
                        No matching findings
                    </h3>

                    <p>
                        No findings match the selected
                        search or filters.
                    </p>

                </div>
            `;

        } else {

            results.innerHTML = `
                <div class="empty-state">

                    <h3>
                        No findings detected
                    </h3>

                    <p>
                        The scanned directory contains
                        no detected cryptographic issues.
                    </p>

                </div>
            `;
        }

        return;
    }


    results.innerHTML =
        findings.map(
            finding => {

                const severity =
                    String(
                        finding.severity || "Info"
                    ).trim();


                const severityClass =
                    normalizeValue(severity);


                const detectionType =
                    String(
                        finding.detection_type ||
                        finding.category ||
                        "Unknown"
                    ).trim();


                return `
                    <article
                        class="finding-card severity-${escapeHtml(
                            severityClass
                        )}"
                    >

                        <div
                            class="finding-header"
                        >

                            <div>

                                <div
                                    class="finding-title"
                                >
                                    ${escapeHtml(
                                        finding.title ||
                                        "Untitled finding"
                                    )}
                                </div>

                                <div
                                    class="finding-meta"
                                >
                                    ${escapeHtml(
                                        finding.file || ""
                                    )}
                                    :
                                    ${escapeHtml(
                                        finding.line || ""
                                    )}
                                </div>

                            </div>


                            <span
                                class="badge badge-${escapeHtml(
                                    severityClass
                                )}"
                            >
                                ${escapeHtml(
                                    severity
                                )}
                            </span>

                        </div>


                        <div
                            class="finding-section"
                        >

                            <strong>
                                Detection Type:
                            </strong>

                            ${escapeHtml(
                                detectionType
                            )}

                        </div>


                        <div
                            class="finding-section"
                        >

                            <strong>
                                Rule:
                            </strong>

                            ${escapeHtml(
                                finding.rule_id
                            )}

                            &nbsp;&nbsp;

                            <strong>
                                Risk:
                            </strong>

                            ${escapeHtml(
                                finding.risk_score
                            )}

                        </div>


                        <div
                            class="finding-section"
                        >

                            <strong>
                                Detected:
                            </strong>

                            <div class="code">
                                ${escapeHtml(
                                    finding.matched_text
                                )}
                            </div>

                        </div>


                        <div
                            class="finding-section"
                        >

                            <strong>
                                Description:
                            </strong>

                            <p>
                                ${escapeHtml(
                                    finding.description
                                )}
                            </p>

                        </div>


                        <div
                            class="finding-section"
                        >

                            <strong>
                                Recommendation:
                            </strong>

                            <p>
                                ${escapeHtml(
                                    finding.recommendation
                                )}
                            </p>

                        </div>


                        <div
                            class="finding-section"
                        >

                            <strong>
                                Confidence:
                            </strong>

                            ${escapeHtml(
                                finding.confidence
                            )}

                        </div>

                    </article>
                `;
            }
        ).join("");
}


/* =========================================================
   Finding Search and Filters
========================================================= */

function getActiveFilterState() {

    const searchInput =
        document.getElementById(
            "finding-search"
        );

    const severityFilter =
        document.getElementById(
            "severity-filter"
        );

    const typeFilter =
        document.getElementById(
            "type-filter"
        );


    const search =
        searchInput
            ? searchInput.value.trim()
            : "";


    const severity =
        severityFilter
            ? severityFilter.value
            : "All";


    const type =
        typeFilter
            ? typeFilter.value
            : "All";


    return (
        search !== "" ||
        severity !== "All" ||
        type !== "All"
    );
}


function filterFindings() {

    const searchInput =
        document.getElementById(
            "finding-search"
        );

    const severityFilter =
        document.getElementById(
            "severity-filter"
        );

    const typeFilter =
        document.getElementById(
            "type-filter"
        );


    const search =
        searchInput
            ? normalizeValue(
                searchInput.value
            )
            : "";


    const selectedSeverity =
        severityFilter
            ? normalizeValue(
                severityFilter.value
            )
            : "all";


    const selectedType =
        typeFilter
            ? normalizeValue(
                typeFilter.value
            )
            : "all";


    const filtered =
        allFindings.filter(
            finding => {

                const title =
                    normalizeValue(
                        finding.title
                    );


                const file =
                    normalizeValue(
                        finding.file
                    );


                const rule =
                    normalizeValue(
                        finding.rule_id
                    );


                const matchedText =
                    normalizeValue(
                        finding.matched_text
                    );


                const description =
                    normalizeValue(
                        finding.description
                    );


                const recommendation =
                    normalizeValue(
                        finding.recommendation
                    );


                const findingSeverity =
                    normalizeValue(
                        finding.severity
                    );


                const findingType =
                    normalizeValue(
                        finding.detection_type ||
                        finding.category
                    );


                const matchesSearch =
                    !search ||
                    title.includes(search) ||
                    file.includes(search) ||
                    rule.includes(search) ||
                    matchedText.includes(search) ||
                    description.includes(search) ||
                    recommendation.includes(search);


                const matchesSeverity =
                    selectedSeverity === "all" ||
                    findingSeverity === selectedSeverity;


                const matchesType =
                    selectedType === "all" ||
                    findingType === selectedType;


                return (
                    matchesSearch &&
                    matchesSeverity &&
                    matchesType
                );
            }
        );


    displayFindings(
        filtered
    );
}


function resetFilters() {

    const searchInput =
        document.getElementById(
            "finding-search"
        );

    const severityFilter =
        document.getElementById(
            "severity-filter"
        );

    const typeFilter =
        document.getElementById(
            "type-filter"
        );


    if (searchInput) {
        searchInput.value = "";
    }


    if (severityFilter) {
        severityFilter.value = "All";
    }


    if (typeFilter) {
        typeFilter.value = "All";
    }
}


/* =========================================================
   Report Export
========================================================= */

function exportReport() {

    if (!currentScanId) {

        alert(
            "Run a scan before exporting a report."
        );

        return;
    }


    window.location.href =
        `/report/${currentScanId}`;
}


/* =========================================================
   Scan History
========================================================= */

async function loadHistory() {

    const historyElement =
        document.getElementById(
            "history"
        );


    if (!historyElement) {
        return;
    }


    try {

        const response =
            await fetch(
                "/history"
            );


        if (!response.ok) {

            throw new Error(
                `History request failed: HTTP ${response.status}`
            );
        }


        const data =
            await response.json();


        displayHistory(
            data.scans || []
        );


    } catch (error) {

        console.error(
            "History error:",
            error
        );


        historyElement.innerHTML = `
            <div class="empty-state">

                <h3>
                    Unable to load history
                </h3>

                <p>
                    ${escapeHtml(
                        error.message
                    )}
                </p>

            </div>
        `;
    }
}


function displayHistory(scans) {

    const historyElement =
        document.getElementById(
            "history"
        );


    if (!historyElement) {
        return;
    }


    if (!scans.length) {

        historyElement.innerHTML = `
            <div class="empty-state">

                <h3>
                    No scan history
                </h3>

                <p>
                    Completed scans will appear here.
                </p>

            </div>
        `;

        return;
    }


    historyElement.innerHTML = `
        <div class="history-list">

            ${scans.map(
                scan => `

                    <div
                        class="history-item"
                    >

                        <div
                            class="history-id"
                        >
                            Scan #${escapeHtml(
                                scan.id
                            )}
                        </div>


                        <div
                            class="history-main"
                        >

                            <div
                                class="history-directory"
                            >
                                ${escapeHtml(
                                    scan.directory
                                )}
                            </div>


                            <div
                                class="history-time"
                            >
                                ${escapeHtml(
                                    scan.scan_time
                                )}
                            </div>

                        </div>


                        <div
                            class="history-stats"
                        >

                            <span
                                class="history-stat"
                            >
                                ${escapeHtml(
                                    scan.files_scanned
                                )}
                                files
                            </span>


                            <span
                                class="history-stat"
                            >
                                ${escapeHtml(
                                    scan.total_findings
                                )}
                                findings
                            </span>


                            <span
                                class="history-stat critical"
                            >
                                Critical:
                                ${escapeHtml(
                                    scan.critical
                                )}
                            </span>


                            <span
                                class="history-stat high"
                            >
                                High:
                                ${escapeHtml(
                                    scan.high
                                )}
                            </span>


                            <span
                                class="history-stat"
                            >
                                Info:
                                ${escapeHtml(
                                    scan.info
                                )}
                            </span>


                            <span
                                class="history-stat risk"
                            >
                                Risk:
                                ${escapeHtml(
                                    scan.risk_score
                                )}
                            </span>

                        </div>

                    </div>

                `
            ).join("")}

        </div>
    `;
}


/* =========================================================
   Initialization
========================================================= */

document.addEventListener(
    "DOMContentLoaded",
    () => {

        const directoryInput =
            document.getElementById(
                "directory"
            );


        const searchInput =
            document.getElementById(
                "finding-search"
            );


        const severityFilter =
            document.getElementById(
                "severity-filter"
            );


        const typeFilter =
            document.getElementById(
                "type-filter"
            );


        if (directoryInput) {

            directoryInput.addEventListener(
                "keydown",
                event => {

                    if (
                        event.key === "Enter"
                    ) {
                        runScan();
                    }

                }
            );
        }


        if (searchInput) {

            searchInput.addEventListener(
                "input",
                filterFindings
            );
        }


        if (severityFilter) {

            severityFilter.addEventListener(
                "change",
                filterFindings
            );
        }


        if (typeFilter) {

            typeFilter.addEventListener(
                "change",
                filterFindings
            );
        }


        loadHistory();

    }
);
