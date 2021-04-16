const tablePolicy = document.getElementById("tablePolicy");
const btnAdd = document.getElementById("btnAdd");
btnAdd.onclick = add;
const btnSave = document.getElementById("btnSave");
btnSave.onclick = save;

// remove, insert or update page data
function refreshPage()
{
    var policyData = getLiveData("policy");
    //var policyData = getDummyData("data/examplePolicy.json");
    var policyJSON = JSON.parse(policyData)["policy"];

    // remove existing rows not in data
    var rowCount = tablePolicy.rows.length;
    for (var i = 1; i < rowCount; i++) 
    {
        if (!policyJSON.hasOwnProperty(tablePolicy.rows[i].id.slice(4)))
        {
            tablePolicy.deleteRow(i);
            rowCount--;
            i--;
        }
    }

    // insert or update
    for(var ip in policyJSON)
    {
        var scans = policyJSON[ip]["scans"];
        var row = document.getElementById("row_"+ip);

        // insert
        if(row == null)
        {
            insertRow(row, ip, scans)
        }
        // update
        else
        {
            row.cells[0].childNodes[0].value = ip;
            if (scans.indexOf("config_scan") >= 0)
                row.cells[1].childNodes[0].checked = true;
            else
                row.cells[1].childNodes[0].checked = false;
            if (scans.indexOf("network_scan") >= 0)
                row.cells[2].childNodes[0].checked = true;
            else
                row.cells[2].childNodes[0].checked = false;
            if (scans.indexOf("tcp_scan") >= 0)
                row.cells[3].childNodes[0].checked = true;
            else
                row.cells[3].childNodes[0].checked = false;
            if (scans.indexOf("scada_scan") >= 0)
                row.cells[4].childNodes[0].checked = true;
            else
                row.cells[4].childNodes[0].checked = false;
        }
    }
}

function insertRow(row, ip, scans)
{
    row = tablePolicy.insertRow();
    row.id = "row_"+ip;
    row.className = "tableRow";

    let ipaddr = row.insertCell();
    let ipaddrText = document.createElement("INPUT");
    ipaddrText.type = "text";
    ipaddr.appendChild(ipaddrText);

    let config_scan = row.insertCell();
    let config_scan_checkBox = document.createElement("INPUT");
    config_scan_checkBox.type = "checkbox";
    config_scan.appendChild(config_scan_checkBox);

    let network_scan = row.insertCell();
    let network_scan_checkBox = document.createElement("INPUT");
    network_scan_checkBox.type = "checkbox";
    network_scan.appendChild(network_scan_checkBox);

    let tcp_scan = row.insertCell();
    let tcp_scan_checkBox = document.createElement("INPUT");
    tcp_scan_checkBox.type = "checkbox";
    tcp_scan.appendChild(tcp_scan_checkBox);

    let scada_scan = row.insertCell();
    let scada_scan_checkBox = document.createElement("INPUT");
    scada_scan_checkBox.type = "checkbox";
    scada_scan.appendChild(scada_scan_checkBox);

    let remove = row.insertCell();
    let removeButton = document.createElement("button");
    removeButton.className="button";
    removeButton.value = ip;
    removeButton.innerHTML = "-";
    removeButton.setAttribute("onclick", "removeClick(this.value)");
    remove.appendChild(removeButton);

    ipaddrText.value = ip;

    if (ip != "0.0.0.0")
    {
        if (scans.indexOf("config_scan") >= 0)
            config_scan_checkBox.checked = true;
        if (scans.indexOf("network_scan") >= 0)
            network_scan_checkBox.checked = true;
        if (scans.indexOf("tcp_scan") >= 0)
            tcp_scan_checkBox.checked = true;
        if (scans.indexOf("scada_scan") >= 0)
            scada_scan_checkBox.checked = true;
    }
}

function add()
{
    let row = null;
    let ip = "0.0.0.0";
    let scans = {};
    insertRow(row, ip, scans);
}

function removeClick(ip)
{
    var rowCount = tablePolicy.rows.length;
    for (var i = 1; i < rowCount; i++)
    {
        if (ip == tablePolicy.rows[i].id.slice(4))
        {
            tablePolicy.deleteRow(i);
            rowCount--;
            i--;
        }
    }
}

function save()
{
    var policyDict = {}
    var rowCount = tablePolicy.rows.length;
    for (var i = 1; i < rowCount; i++)
    {
        ip = tablePolicy.rows[i].cells[0].childNodes[0].value;
        console.log(ip)
        policyDict[ip] = {"scans": []}
        if (tablePolicy.rows[i].cells[1].childNodes[0].checked == true)
            policyDict[ip]["scans"].push("config_scan");
        if (tablePolicy.rows[i].cells[2].childNodes[0].checked == true)
            policyDict[ip]["scans"].push("network_scan");
        if (tablePolicy.rows[i].cells[3].childNodes[0].checked == true)
            policyDict[ip]["scans"].push("tcp_scan");
        if (tablePolicy.rows[i].cells[4].childNodes[0].checked == true)
            policyDict[ip]["scans"].push("scada_scan");
    }
    console.log(policyDict)
    console.log(JSON.stringify(policyDict))
    putLiveData("setpolicy="+JSON.stringify(policyDict))
}

// start
refreshPage();
//window.setInterval(function(){refreshPage();}, 5000);
