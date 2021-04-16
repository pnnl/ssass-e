const canvasVendor = document.getElementById("canvasVendor");
var chartVendor = null;
const canvasDevice = document.getElementById("canvasDevice");
var chartDevice = null;
const tableChildren = document.getElementById("tableChildren");
const tableVulnerabilities = document.getElementById("tableVulnerabilities");
const tableIdentificationTimeline = document.getElementById("tableIdentificationTimeline");
const tableVulnerabilityTimeline = document.getElementById("tableVulnerabilityTimeline");
var vendorsVar = localStorage.getItem("vendorsVar");
var vendorsDict = JSON.parse(vendorsVar);
var devicesVar = localStorage.getItem("devicesVar");
var devicesDict = JSON.parse(devicesVar);
var rainbow = new Rainbow();
rainbow.setNumberRange(0, 100);
rainbow.setSpectrum("red", "yellow", "green");

// remove, insert or update page data
function refreshPage()
{
    var ipaddr = new URL(window.location.href).searchParams.get("ipaddr");
    var detailsData = getLiveData("details="+ipaddr);
    //var detailsData = getDummyData("data/exampleDetails.json");
    var detailsJSON = JSON.parse(detailsData)["details"];
    document.getElementById("lblTitleIP").innerHTML = ipaddr;

    vendorKeyWordStr = ""
    modelKeyWordStr = ""
    for (var keyWord in detailsJSON["DEVICE_PROFILE"]["CVE_KEYWORDS"])
    {
        kw = detailsJSON["DEVICE_PROFILE"]["CVE_KEYWORDS"][keyWord];
        modelKeyWordStr = modelKeyWordStr + kw + "<br/>";
    }
    for (var keyWord in detailsJSON["VENDOR_PROFILE"]["CVE_KEYWORDS"])
    {
        kw = detailsJSON["VENDOR_PROFILE"]["CVE_KEYWORDS"][keyWord];
        vendorKeyWordStr = vendorKeyWordStr + kw + "<br/>";
    }

    combinedKeyWordStr = ""
    if (vendorKeyWordStr != "")
    {
        combinedKeyWordStr = combinedKeyWordStr + "VENDOR: <br/>" + vendorKeyWordStr;
    }
    if (modelKeyWordStr != "")
    {
        combinedKeyWordStr = combinedKeyWordStr + "MODEL: <br/>" + modelKeyWordStr;
    }

    document.getElementById("CVEs").innerHTML = "Keyword Search<br/>" + combinedKeyWordStr;


    // remove existing rows not found in data
    var rowCount = tableChildren.rows.length;
    for (var i = 1; i < rowCount; i++)
    {
        if (!detailsJSON["CHILDREN"].hasOwnProperty(tableChildren.rows[i].id.slice(4)))
            {
                tableChildren.deleteRow(i);
                rowCount--;
                i--;
            }
    }
    rowCount = tableVulnerabilities.rows.length;
    for (var i = 1; i < rowCount; i++) 
    {
        if (!detailsJSON["VULNERABILITIES"].hasOwnProperty(tableVulnerabilities.rows[i].id.slice(4)))
            {
                tableVulnerabilities.deleteRow(i);
                rowCount--;
                i--;
            }
    }
    rowCount = tableIdentificationTimeline.rows.length;
    for (var i = 1; i < rowCount; i++) 
    {
        if (!(detailsJSON["TIMELINES"]["IDENTIFICATION"].hasOwnProperty(tableIdentificationTimeline.rows[i].id.slice(4)) ||
        detailsJSON["TIMELINES"]["IDENTIFICATION"].hasOwnProperty(tableIdentificationTimeline.rows[i].id.slice(10))))
        {
            tableIdentificationTimeline.deleteRow(i);
            rowCount--;
            i--;
        }
    }
    rowCount = tableVulnerabilityTimeline.rows.length;
    for (var i = 1; i < rowCount; i++) 
    {
        if (!(detailsJSON["TIMELINES"]["VULNERABILITY"].hasOwnProperty(tableVulnerabilityTimeline.rows[i].id.slice(4)) ||
        detailsJSON["TIMELINES"]["VULNERABILITY"].hasOwnProperty(tableVulnerabilityTimeline.rows[i].id.slice(10))))
        {
            tableVulnerabilityTimeline.deleteRow(i);
            rowCount--;
            i--;
        }       
    }

    // insert or update tableChildren
    for(var cID in detailsJSON["CHILDREN"])
    {
        var cDict = detailsJSON["CHILDREN"][cID];
        console.log(cDict);
        row = document.getElementById("row_"+cID)

        // insert row
        if(row == null)
        {
            row = tableChildren.insertRow();
            row.id = "row_"+cID;
            row.className = "tableRow";

            let childID = row.insertCell();
            let vendor = row.insertCell();
            let model = row.insertCell();
            let serial_protocol = row.insertCell(); 

            childID.innerHTML = cID;
            vendor.innerHTML = cDict["VENDOR"];
            model.innerHTML = cDict["MODEL"]+"/"+cDict["NAME"];
            serial_protocol.innerHTML = cDict["PROTOCOL"];

        }
        // update existing
        else
        {
            row.cells[0].innerHTML = cID
            row.cells[1].innerHTML = cDict["VENDOR"]
            row.cells[2].innerHTML = cDict["MODEL"]+"/"+cDict["NAME"];
            row.cells[3].innerHTML = cDict["PROTOCOL"]
        }
    }

    // insert or update tableVulnerabilities
    var vulnCount = 1;
    for(var vID in detailsJSON["VULNERABILITIES"]) 
    {
        var vDict = detailsJSON["VULNERABILITIES"][vID];
        row = document.getElementById("row_"+vID)

        // insert new
        if(row == null)
        {
            row = tableVulnerabilities.insertRow();
            row.id = "row_"+vID;
            row.className = "tableRow";

            let vulnID = row.insertCell();
            let description = row.insertCell();
            let severity = row.insertCell();
            let suggestions = row.insertCell(); 

            vulnID.innerHTML = vulnCount;
            description.innerHTML = vDict["DESCRIPTION"];
            severity.innerHTML = vDict["SEVERITY"];
            suggestions.innerHTML = vDict["SUGGESTIONS"];
        }
        // update existing
        else
        {
            row.cells[0].innerHTML = vulnCount;
            row.cells[1].innerHTML = vDict["DESCRIPTION"];
            row.cells[2].innerHTML = vDict["SEVERITY"];
            row.cells[3].innerHTML = vDict["SUGGESTIONS"];
        }
        vulnCount = vulnCount + 1;
    }

    // chartVendor
    chartVendor = drawChart(canvasVendor, chartVendor, "Vendor", detailsJSON["CHARTS"]["VENDOR"]);

    // chartDevice
    chartDevice = drawChart(canvasDevice, chartDevice, "Device", detailsJSON["CHARTS"]["DEVICE"]);    

    // tableIdentificationTimeline
    fillTimeline(tableIdentificationTimeline, detailsJSON["TIMELINES"]["IDENTIFICATION"]);

    // tableVulnerabilityTimeline
    fillTimeline(tableVulnerabilityTimeline, detailsJSON["TIMELINES"]["VULNERABILITY"]);
}

// fills or updates a timeline
function fillTimeline(table, tableDict)
{
    for(var dt in tableDict) 
    {
        var dtDict = tableDict[dt];
        var row = document.getElementById("row_"+dt);
        var hiddenrow = document.getElementById("hiddenrow_"+dt);

        // insert new
        if (row == null)
        {
            row = table.insertRow();
            row.id = "row_"+dt;
            row.className = "tableRow";

            let datetimeStamp = row.insertCell();
            let signature = row.insertCell();
            let status = row.insertCell();
            let info = row.insertCell(); 
            hiddenrow = table.insertRow();
            hiddenrow.id = "hiddenrow_"+dt;
            let hiddenInfo = hiddenrow.insertCell();
            hiddenInfo.id = "hidden_"+dt;
            hiddenInfo.style.display = "none";

            dateString = dt.substring(0, 4) + "/" + dt.substring(4,6) + "/" + dt.substring(6,8) + " " + dt.substring(8,10) + ":" + dt.substring(10,12) + ":" + dt.substring(12,14) // + "." + dt.substring(14,20)
            datetimeStamp.innerHTML = dateString;
            signature.innerHTML = dtDict["SIGNATURE"];
            status.innerHTML = dtDict["STATUS"];
            hiddenInfo.innerHTML = dtDict["INFO"];
            hiddenInfo.colSpan = "4";

            var btn = document.createElement("button");
            btn.value = dt;
            btn.className = "button";
            btn.innerHTML = "Show";
            btn.setAttribute("onclick", "infoClick(this.value)");
            info.appendChild(btn);
        }
        // update existing
        else
        {
            row.cells[1].innerHTML = dtDict["SIGNATURE"];
            row.cells[2].innerHTML = dtDict["STATUS"];
            hiddenrow.cells[0].innerHTML = dtDict["INFO"];
        }
    }
}

// displays hidden row for event info
function infoClick(dt)
{
    if (document.getElementById("hidden_" + dt).style.display == "none")
        document.getElementById("hidden_" + dt).style.display = "table-cell";
    else 
        document.getElementById("hidden_" + dt).style.display = "none";
}

// draws a chart in a canvas
function drawChart(canvas, chart, xLabel, chartDict)
{
    var xLabels = [];
    var yValues = [];
    var yColors = [];
    
    for (var name in chartDict)
    {
        xLabels.push(name);
        yValues.push(chartDict[name]["SIMILARITY"]);
        yColors.push("#"+rainbow.colourAt(Math.round(100.0*chartDict[name]["SIMILARITY"])));
    }
    var yLabel = "Similarity Score"

    // first draw
    if (chart == null)
    {
        chart = new Chart(canvas, {
            type: "bar",
            data: {labels: xLabels, datasets: [{label: yLabel, data: yValues, backgroundColor: yColors}]},
            options: {
                responsive: true, maintainAspectRatio: false,
                scales: {
                    yAxes: [{
                        ticks: {beginAtZero: true, suggestedMax: 1.0},
                        scaleLabel: {display: true, labelString: yLabel}
                    }],
                    xAxes: [{scaleLabel: {display: true, labelString: xLabel}}]
                }
            }
        });
    }
    // updating
    else
    {
        chart.data.labels = xLabels;
        chart.data.datasets = [{label: yLabel, data: yValues, backgroundColor: yColors}];
        chart.update();
    }

    return chart;
}

// start
refreshPage();
window.setInterval(function(){refreshPage();}, 15000);
