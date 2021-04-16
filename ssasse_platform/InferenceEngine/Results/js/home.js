const tableSummary = document.getElementById("tableSummary");
const btnStart = document.getElementById("btnStart");
btnStart.onclick = start;
const btnStop = document.getElementById("btnStop");
btnStop.onclick = stop;
const btnRestart = document.getElementById("btnRestart");
btnRestart.onclick = restart;
const aNotifications = document.getElementById("aNotifications");
const lblStatus = document.getElementById("lblStatus");
const lblRuntime = document.getElementById("lblRuntime");

// remove, insert or update page data
function refreshPage()
{
    var controlData = getLiveData("control");
    //var controlData = '{"control": {"Status": "some status", "Runtime": "some time"}}';
    var controlJSON = JSON.parse(controlData)["control"];
    lblStatus.innerHTML = controlJSON["Status"];
    lblRuntime.innerHTML = controlJSON["Runtime"];

    var summaryData = getLiveData("summary");
    //var summaryData = getDummyData("data/exampleSummary.json");
    var summaryJSON = JSON.parse(summaryData)["summary"];

    if (Object.keys(summaryJSON["REQUESTS"]).length > 0)
    {
        aNotifications.style.backgroundColor = "red";
    }
    else
    {
        aNotifications.style.backgroundColor = "#343a40";
    }

    var countTotal = summaryJSON["AGGREGATE"]["TOTAL_DEVICES"];
    var countIdentified = summaryJSON["AGGREGATE"]["IDENTIFIED"];
    var countUnidentified = countTotal - countIdentified;
    var countTotalVulns = summaryJSON["AGGREGATE"]["TOTAL_VULNERABILITIES"];
    var countHigh = summaryJSON["AGGREGATE"]["HIGH_VULNS"];
    var countMed = summaryJSON["AGGREGATE"]["MED_VULNS"];
    var countLow = summaryJSON["AGGREGATE"]["LOW_VULNS"];
    document.getElementById("lblTotalDevices").innerHTML = countTotal;
    document.getElementById("lblIdentifiedDevices").innerHTML = countIdentified;
    document.getElementById("lblUnidentifiedDevices").innerHTML = countUnidentified;
    document.getElementById("lblTotalVulnerabilities").innerHTML = countHigh+countMed+countLow;
    document.getElementById("lblHighVulnerabilities").innerHTML = countHigh;
    document.getElementById("lblMediumVulnerabilities").innerHTML = countMed;
    document.getElementById("lblLowVulnerabilities").innerHTML = countLow;
    //var idBar = document.getElementById("idBar");
    //var unidentifiedPercentage = (countUnidentified/countTotal)*100 + "%";
    //idBar.style.backgroundSize = unidentifiedPercentage+" 100%,100% 100%;";
    //var vulnBar = document.getElementById("vulnBar");
    //var lowPercentage = (countLow/countTotalVulns)*100 + "%";
    //var medPercentage = ((countLow+countMed)/countTotalVulns)*100 + "%";
    //vulnBar.style.backgroundSize = lowPercentage+" 100%,"+medPercentage+" 100%,100% 100%;";

    // remove existing rows not in data
    var rowCount = tableSummary.rows.length;
    for (var i = 1; i < rowCount; i++) 
    {
        if (!summaryJSON["TABLE"].hasOwnProperty(tableSummary.rows[i].id.slice(4)))
        {
            tableSummary.deleteRow(i);
            rowCount--;
            i--;
        }
    }

    // insert or update
    for(var ip in summaryJSON["TABLE"])
    {
        var ipDict = summaryJSON["TABLE"][ip];
        var row = document.getElementById("row_"+ip);
        // insert new
        if (row == null)
        {
            row = tableSummary.insertRow();
            row.className = "tableRow";
            row.id = "row_"+ip;
    
            let ipaddr = row.insertCell();
            let vendor = row.insertCell();
            let model = row.insertCell();
            let firmware = row.insertCell();
            let device_type = row.insertCell();
            let high_vulns = row.insertCell();
            let med_vulns = row.insertCell();
            let low_vulns = row.insertCell();
            let link = row.insertCell();
            
            ipaddr.innerHTML = ip;
            vendor.innerHTML = ipDict["VENDOR"];
            model.innerHTML = ipDict["MODEL"];
            firmware.innerHTML = ipDict["FIRMWARE_ID"];
            device_type.innerHTML = ipDict["DEVICE_TYPE"];
            high_vulns.innerHTML = ipDict["HIGH_VULNS"];
            med_vulns.innerHTML = ipDict["MED_VULNS"];
            low_vulns.innerHTML = ipDict["LOW_VULNS"];
            
            if(!ip.includes(":"))
            {
                var btn = document.createElement("button");
                btn.value = ip;
                btn.className = "button";
                btn.innerHTML = "Open";
                btn.setAttribute("onclick", "detailsClick(this.value)");
                link.appendChild(btn);
            }
            else
            {
                row.className = "tableSubRow";
            }
        }
        // update existing
        else
        {
            //row.cells[0].innerHTML = ip
            row.cells[1].innerHTML = ipDict["VENDOR"];
            row.cells[2].innerHTML = ipDict["MODEL"];
            row.cells[3].innerHTML = ipDict["FIRMWARE_ID"];
            row.cells[4].innerHTML = ipDict["DEVICE_TYPE"];
            row.cells[5].innerHTML = ipDict["HIGH_VULNS"];
            row.cells[6].innerHTML = ipDict["MED_VULNS"];
            row.cells[7].innerHTML = ipDict["LOW_VULNS"];
        }
    }
}

// opens new tab to details page for IP
function detailsClick(ipaddr)
{
    window.open("details.html?ipaddr="+ipaddr, '_blank').focus();
}

function start()
{
    putLiveData("start");
}

function stop()
{
    putLiveData("stop");
}

function restart()
{
    stop();
    start();
}

// start
refreshPage();
window.setInterval(function(){refreshPage();}, 5000);
