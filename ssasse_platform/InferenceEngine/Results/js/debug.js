
// remove, insert or update page data

function refreshPage()
{
    var debugData = getLiveData("debug");

    console.log(debugData);
   // var debugData = getDummyData("data/exampleDebug.json");
    var debugJSON = JSON.parse(debugData)["debug"];
    for (ip in debugJSON) {
        console.log("information1");

        var secBody = document.getElementsByClassName("SectionBody");
        document.getElementById("lblDevice").innerHTML = ip;

        var model = debugJSON[ip]["EVIDENCE"]["MODEL"];
        document.getElementById("lblModel").innerHTML = model;
        var vendor = debugJSON[ip]["EVIDENCE"]["VENDOR"];
        document.getElementById("lblVendor").innerHTML = vendor;
        var protocols = debugJSON[ip]["EVIDENCE"]["PROTOCOLS"];
        document.getElementById("lblProtocols").innerHTML = protocols;

        for (decision in debugJSON[ip]["DECISIONS"])
        {

            var id = decision;
            document.getElementById("lblDecisionID").innerHTML = id;
            var outcome = debugJSON[ip]["DECISIONS"][id];
            document.getElementById("lblDecisionOutcome").innerHTML = outcome;
        }

        for (error in debugJSON[ip]["ERRORS"])
        {
            var id = error;
            document.getElementById("lblErrorsID").innerHTML = id;
            var outcome = debugJSON[ip]["ERRORS"][id];
            document.getElementById("lblErrorsOutcome").innerHTML = outcome;
        }

       for (scan in debugJSON[ip]["SCANS"])
        {
            var name = scan;
            document.getElementById("lblScanName").innerHTML = name;
            var scanResults = debugJSON[ip]["SCANS"][name]["SCAN_RESULT"];
            document.getElementById("lblScanResult").innerHTML = scanResults;
            var scanResultsDesc = debugJSON[ip]["SCANS"][name]["SCAN_RESULT"];
            document.getElementById("lblScanDescription").innerHTML = scanResultsDesc;
        }

        var elmnt = document.getElementsByTagName("DIV")[3];
        var cln = elmnt.cloneNode(true);
        document.body.appendChild(cln);
    }
}

// start
refreshPage();
//window.setInterval(function(){refreshPage();}, 1000);
