var cvssResponse, epssResponse;
var metrics, latestMetric, metricData, cvssData, cvssVersion, cvssPrintable, cvssVector, cvssScore, references, exploitAvailable = false, source, id, published, lastModified, description, cwe;

var cve = window.location.pathname.split('/')[1];



async function getApiResponse() {
    try {
        const response = await fetch('https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=' + cve);
        if (!response.ok) {
            throw new Error('API returned an unsuccessful response');
        }
        const data = await response.json();
        return data;
    } catch (error) {
        console.log('There was an error:', error);
    }
}


getApiResponse().then(data => {
    // the `data` variable contains the response from the API
    cvssResponse = data;

    if (cvssResponse["format"] == "NVD_CVE" && cvssResponse["version"].startsWith(2) && cvssResponse["vulnerabilities"].length > 0) {
        metrics = cvssResponse["vulnerabilities"][0]["cve"]["metrics"];

        latestMetric = Object.keys(metrics)[0];

        metricData = metrics[latestMetric][0];

        cvssData = metricData["cvssData"];

        cvssVersion = cvssData["version"];

        cvssPrintable = cvssData;

        cvssScore = cvssPrintable["baseScore"];
        cvssVector = cvssPrintable["vectorString"];

        delete cvssPrintable["version"];
        delete cvssPrintable["vectorString"];
        delete cvssPrintable["baseScore"];
        delete cvssPrintable["baseSeverity"];


        if (cvssVersion.startsWith(2)) {
            cvssVector = "CVSS:" + cvssVersion + "/" + cvssVector;
            cvssPrintable = convertCvssToList(cvssVector, 2);
        } else if (cvssVersion.startsWith(3)) {
            cvssPrintable = convertCvssToList(cvssVector, 3);
        }

        references = cvssResponse["vulnerabilities"][0]["cve"]["references"];
        exploitAvailable = false;


        document.getElementById("cvssVector").textContent = cvssVector;
        document.getElementById("cvssScore").textContent = "CVSS: " + cvssScore;


        source = cvssResponse["vulnerabilities"][0]["cve"]["sourceIdentifier"];
        id = cvssResponse["vulnerabilities"][0]["cve"]["id"];
        published = cvssResponse["vulnerabilities"][0]["cve"]["published"];
        lastModified = cvssResponse["vulnerabilities"][0]["cve"]["lastModified"];

        document.getElementById("source").textContent = source;
        document.getElementById("published").textContent = convertDate(published);
        document.getElementById("lastModified").textContent = convertDate(lastModified);

        description = cvssResponse["vulnerabilities"][0]["cve"]["descriptions"][0]["value"];
        document.getElementById("description").textContent = description;


        document.getElementById("references").innerHTML = renderReferences(references);

        cwe = cvssResponse["vulnerabilities"][0]["cve"]["weaknesses"][0]["description"][0]["value"];

        var metaDesc = document.querySelector('meta[name="description"]');
        var cweName;
        var title;

        try {
            cweName = cwes.find(obj => Object.keys(obj)[0] === cwe)[cwe];
        } catch {
            cweName;
        }
        
        if (cwe.startsWith("CWE-") && cweName) {

            if (exploitAvailable) {
                title = id + " Exploit | " + cweName + " | CVEReview";
            } else {
                title = id + " | " + cweName + " | CVEReview";
            }

            document.getElementById("pageTitle").textContent = id + " | " + cweName;
        } else {
            if (exploitAvailable) {
                title = id + " Exploit | CVEReview";
            } else {
                title = id + " | CVEReview";
            }

            document.getElementById("pageTitle").textContent = id;
        }
        
        if (exploitAvailable) {
            metaDesc.setAttribute("content", id + " Public Exploit! Vulnerability name: " + cweName + " : " + description);
        } else {
            metaDesc.setAttribute("content", id + " Review | Vulnerability name:  " + cweName + " : " + description);
        }

        document.title = title;


        populateCvssTextTable(cvssPrintable);

        updateCvssChartJS();

        async function getEpssResponse() {
            try {
                const response = await fetch('/EPSS/' + cve);
                if (!response.ok) {
                    throw new Error('EPSS API returned an unsuccessful response');
                }
                const epssData = await response.json();
                return epssData;
            } catch (error) {
                console.log('There was an error:', error);
            }
        }

        getEpssResponse().then(epssData => {
            epssResponse = epssData;
            try {
                if (epssResponse["status"] == "OK" && epssResponse["data"].length > 0) {
                    epssScore = epssResponse["data"][0].epss * 100;
                    document.getElementById("epssScore").textContent = "EPSS: " + epssScore;
                } else {
                    document.getElementById("epssScore").textContent = "EPSS: N/A";
                    epssScore = 0;
                    console.log("EPSS API returned an unsuccessful response - 2!")
                }
            } catch {
                document.getElementById("epssScore").textContent = "EPSS: N/A";
                epssScore = 0;
                console.log("EPSS API returned an unsuccessful response - 3!")
            }
            
            updateEpssChartJS(epssScore);

        });


    } else {
        document.getElementById("pageTitle").textContent = "UNKNOWN CVE: " + cve;
        document.getElementById("description").textContent = "THERE IS NO INFORMATION REGARDING TO THAT CVE!";
    }


});


cvssV2 = [
    ["AV", "L", "Access Vector", "Local", "success"],
    ["AV", "A", "Access Vector", "Adjacent", "warning"],
    ["AV", "N", "Access Vector", "Network", "danger"],
    ["AC", "L", "Access Complexity", "Low", "danger"],
    ["AC", "M", "Access Complexity", "Medium", "warning"],
    ["AC", "H", "Access Complexity", "High", "success"],
    ["Au", "N", "Authentication", "None", "danger"],
    ["Au", "S", "Authentication", "Single", "warning"],
    ["Au", "M", "Authentication", "Multiple", "success"],
    ["C", "N", "Confidentiality Impact", "None", "success"],
    ["C", "P", "Confidentiality Impact", "Partial", "warning"],
    ["C", "C", "Confidentiality Impact", "Complete", "danger"],
    ["I", "N", "Integrity Impact", "None", "success"],
    ["I", "P", "Integrity Impact", "Partial", "warning"],
    ["I", "C", "Integrity Impact", "Complete", "danger"],
    ["A", "N", "Availability Impact", "None", "success"],
    ["A", "P", "Availability Impact", "Partial", "warning"],
    ["A", "C", "Availability Impact", "Complete", "danger"]
];

cvssV3 = [
    ["AV", "P", "Attack Vector", "Physical", "success"],
    ["AV", "L", "Attack Vector", "Local", "success"],
    ["AV", "A", "Attack Vector", "Adjacent", "success"],
    ["AV", "N", "Attack Vector", "Network", "danger"],
    ["AC", "L", "Attack Complexity", "Low", "danger"],
    ["AC", "H", "Attack Complexity", "High", "warning"],
    ["PR", "N", "Privileges Required", "None", "danger"],
    ["PR", "L", "Privileges Required", "Low", "warning"],
    ["PR", "H", "Privileges Required", "High", "success"],
    ["UI", "N", "User Interaction", "None", "danger"],
    ["UI", "R", "User Interaction", "Required", "success"],
    ["S", "U", "Scope", "Unchanged", "success"],
    ["S", "C", "Scope", "Changed", "danger"],
    ["C", "N", "Confidentiality Impact", "None", "success"],
    ["C", "L", "Confidentiality Impact", "Low", "warning"],
    ["C", "H", "Confidentiality Impact", "High", "danger"],
    ["I", "N", "Integrity Impact", "None", "success"],
    ["I", "L", "Integrity Impact", "Low", "warning"],
    ["I", "H", "Integrity Impact", "High", "danger"],
    ["A", "N", "Availability Impact", "None", "success"],
    ["A", "L", "Availability Impact", "Low", "warning"],
    ["A", "H", "Availability Impact", "High", "danger"]
];


function convertCvssToList(vector) {

    const version = parseInt(vector.split(":")[1], 10);

    const cvssList = version === 2 ? cvssV2 : cvssV3;
    const result = [];

    // Parse the CVSS vector into a key-value object
    const obj = {};
    const parts = vector.split("/");
    for (const part of parts) {
        if (part.startsWith("CVSS")) {
            continue;
        }
        const [key, value] = part.split(":");
        obj[key] = value;
    }

    // Convert object keys to desired format
    for (const key in obj) {
        for (const cvss of cvssList) {
            if (cvss[0] === key && cvss[1] === obj[key]) {
                result.push([cvss[2], cvss[3], cvss[4]]);
            }
        }
    }
    return result;
}




function populateCvssTextTable(data) {
    const table = document.getElementById("cvssTable");
    for (const [key, value, color] of data) {
        const row = document.createElement("tr");
        const keyCell = document.createElement("td");
        keyCell.textContent = key;
        row.appendChild(keyCell);
        keyCell.style.marginRight = "3px";

        const valueCell = document.createElement("td");
        const valueDiv = document.createElement("div");
        valueDiv.textContent = value;
        valueDiv.classList.add(`bg-opacity-10`, `bg-${color}`, `text-${color}`, `border`, `border-${color}`, `border-opacity-10`);
        valueCell.appendChild(valueDiv);
        row.appendChild(valueCell);

        table.appendChild(row);
    }
}

function getNextPrevCVE(currentCVE, direction) {
    var regex = /^(?<prefix>CVE-)(?<year>\d{4})-(?<number>\d+)$/;
    var match = currentCVE.match(regex);
    if (!match) {
        console.log("Invalid format for current CVE ID. Please use the format 'CVE-YYYY-NNNN'.")
        return;
    }

    var prefix = match.groups.prefix;
    var year = parseInt(match.groups.year);
    var number = parseInt(match.groups.number);
    var numberLength = match.groups.number.length;

    // Check the direction of the calculation
    if (direction === "next") {
        number++;
    } else if (direction === "prev") {
        number--;
    } else {
        console.log("Invalid direction input. Please use 'next' or 'prev'.")
        return;
    }

    // Check if the number overflows or underflows
    if (number < 0) {
        year--;
        number = Math.pow(10, numberLength) - 1;
    } else if (number >= Math.pow(10, numberLength)) {
        year++;
        number = 0;
    }

    // Reassemble the prefix, year, and number into the new CVE ID
    var nextPrevCVE = prefix + year.toString() + "-" + number.toString().padStart(numberLength, "0");

    return nextPrevCVE;
}
            


function updateCvssChartJS() {
    if (cvssVersion.startsWith(2)) {
        if (cvssPrintable[3][1] == "None")
            confidentialityScore = 3;
        else if (cvssPrintable[3][1] == "Partial")
            confidentialityScore = 6;
        else
            confidentialityScore = 9;

        if (cvssPrintable[4][1] == "None")
            integrityScore = 3;
        else if (cvssPrintable[4][1] == "Partial")
            integrityScore = 6;
        else
            integrityScore = 9;

        if (cvssPrintable[5][1] == "None")
            availabilityScore = 3;
        else if (cvssPrintable[5][1] == "Partial")
            availabilityScore = 6;
        else
            availabilityScore = 9;
    } else if (cvssVersion.startsWith(3)) {
        if (cvssPrintable[5][1] == "None")
            confidentialityScore = 3;
        else if (cvssPrintable[5][1] == "Low")
            confidentialityScore = 6;
        else
            confidentialityScore = 9;

        if (cvssPrintable[6][1] == "None")
            integrityScore = 3;
        else if (cvssPrintable[6][1] == "Low")
            integrityScore = 6;
        else
            integrityScore = 9;

        if (cvssPrintable[7][1] == "None")
            availabilityScore = 3;
        else if (cvssPrintable[7][1] == "Low")
            availabilityScore = 6;
        else
            availabilityScore = 9;

    }

    cvssChartJs.data.datasets[0].data = [confidentialityScore, integrityScore, availabilityScore];
    cvssChartJs.update();
};

function updateEpssChartJS(epss) {

    epssChartJs.data.datasets[0].data = [{ x: cvssScore, y: epss, r: 7 }];
    epssChartJs.update();
};

//epssChartJs.data.datasets[0].data[]
const referenceTags = [
    { "VDB Entry": "danger" },
    { "VDB": "danger" },
    { "Exploit": "danger" },
    { "Other References": "danger" },
    { "Advisory": "warning" },
    { "Third Party Advisory": "warning" },
    { "Issue Tracking": "primary" },
    { "Bugtraq ID": "primary" },
    { "Mitigation": "primary" },
    { "Patch": "primary" },
    { "Solution": "primary" },
    { "Mailing": "primary" },
];

function getClassification(input) {

    const classifications = [];

    if (input.tags) {
        for (let i = 0; i < input.tags.length; i++) {
            let tag = input.tags[i];
            tag = tag.toLowerCase();  // convert tag to lowercase for comparison
            let foundMatch = false;

            for (let j = 0; j < referenceTags.length; j++) {
                let referenceTag = Object.keys(referenceTags[j])[0];
                let classification = referenceTags[j][referenceTag];
                referenceTag = referenceTag.toLowerCase();  // convert reference tag to lowercase for comparison
                if (tag.includes(referenceTag)) {  // check for partial match in context
                    classifications.push(classification);
                    foundMatch = true;
                    break;
                }
            }
            if (!foundMatch) {
                classifications.push("primary");  // add "primary" classification if no match is found
            }
        }
    }

    return classifications;
}
const referenceNames = [{ "securitytracker.com": "Security Tracker" }, { "microsoft.com": "Microsoft" }, { "nvd.nist.gov": "NVD" }, { "cisco.com": "Cisco" }, { "oracle.com": "Oracle" }, { "gentoo.org": "Gentoo" }, { "debian.org": "Debian" }, { "ubuntu.com": "Ubuntu" }, { "vmware.com": "VMware" }, { "redhat.com": "Red Hat" }, { "mandriva.com": "Mandriva" }, { "suse.com": "SuSE" }, { "mageia.org": "Mageia" }, { "centos.org": "CentOS" }, { "fedoraproject.org": "Fedora" }, { "opensuse.org": "openSUSE" }, { "mandrivasecurity.com": "Mandriva Security" }, { "dhs.gov": "DHS" }, { "mandrakesoft.com": "MandrakeSoft" }, { "freebsd.org": "FreeBSD" }, { "slackware.com": "Slackware" }, { "turbolinux.com": "TurboLinux" }, { "caldera.com": "Caldera" }, { "conectiva.com": "Conectiva" }, { "apple.com": "Apple" }, { "sgi.com": "SGI" }, { "sun.com": "Sun" }, { "ibm.com": "IBM" }, { "hp.com": "HP" }, { "dell.com": "Dell" }, { "tivoli.com": "Tivoli" }, { "symantec.com": "Symantec" }, { "mcafee.com": "McAfee" }, { "trendmicro.com": "Trend Micro" }, { "sophos.com": "Sophos" }, { "github.com": "GitHub" }, { "packetstormsecurity.com": "Packet Storm Security" }, { "exploit-db.com": "Exploit-DB" }, { "securityfocus.com": "Security Focus" }, { "0day.today": "0day.today" }, { "exchange.xforce.ibmcloud.com": "X-Force Exchange" }, { "zerodayinitiative.com": "The ZDI" }, { "securiteam.com": "SecuriTeam" }, { "cxsecurity.com": "CXSecurity" }];


function getWebsiteName(url) {
    const mainDomain = new URL(url).hostname.split('.').slice(-2).join('.');
    for (let referenceName of referenceNames) {
        if (referenceName[mainDomain]) {
            return referenceName[mainDomain];
        }
    }
    return 'External';
}




function renderReferences(references) {
    let referenceHTML = '';
    var i = 0;
    for (let reference of references) {
        let name = getWebsiteName(reference.url);
        let referenceColor = getClassification(reference);
        if (!referenceColor) {
            referenceColor = primary;
        }
        referenceHTML += `
        <div class="col mb-1">
          <a href="${reference.url}" target="_blank">
            <div class="card h-100 reference">
              <div class="card-body">
                <div>
                  <h6 class="card-title ">${name}
                    <span><i class="bi bi-box-arrow-up-right float-end"></i></span>
                  </h6>
                </div>
                <span>${reference.url}</span>
              </div>
              <div class="card-footer">
      `;
        if (reference.tags) {
            for (let tag of reference.tags) {
                if (referenceColor[i] == "danger") {
                    exploitAvailable = true;
                }
                referenceHTML += `
          <span class="badge bg-opacity-10 bg-${referenceColor[i]} text-${referenceColor[i]} border border-${referenceColor[i]} border-opacity-10">${tag}</span>
        `;
                i++;
            }
        }
        referenceHTML += `
              </div>
            </div>
          </a>
        </div>
      `;

        i = 0;
    }

    return referenceHTML;
}

//thx to https://stackoverflow.com/questions/12409299/how-to-get-current-formatted-date-dd-mm-yyyy-in-javascript-and-append-it-to-an-i
function convertDate(inputFormat) {
    function pad(s) { return (s < 10) ? '0' + s : s; }
    var d = new Date(inputFormat)
    return [pad(d.getDate()), pad(d.getMonth() + 1), d.getFullYear()].join('/')
}
