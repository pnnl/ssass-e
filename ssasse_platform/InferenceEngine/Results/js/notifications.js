const selectNotification = document.getElementById("selectNotification");
selectNotification.onchange = selectChange;
const lblMessage = document.getElementById("lblMessage");
const inputAction = document.getElementById("inputAction");
const inputIP = document.getElementById("inputIP");
const inputSite = document.getElementById("inputSite");
const btnSubmit = document.getElementById("btnSubmit");
btnSubmit.onclick = submit;

requestsData = null;
requestsJSON = null;

// remove, insert or update page data
function refreshPage()
{
    lblMessage.innerHTML = "";
    inputAction.value = "";
    inputIP.value = "";
    inputSite.value = "";

    requestsData = getLiveData("requests");
    requestsJSON = JSON.parse(requestsData)["requests"];

    var i, L = selectNotification.options.length - 1;
    for(i = L; i >= 0; i--)
    {
        selectNotification.remove(i);
    }

    for (var timestamp in requestsJSON)
    {
        var opt = document.createElement("option");
        opt.value = timestamp;
        opt.innerHTML = timestamp;
        selectNotification.appendChild(opt);
    }

    selectNotification.value = "";
}

function selectChange()
{
    var selection = selectNotification[selectNotification.selectedIndex].value;
    lblMessage.innerHTML = requestsJSON[selection]["MESSAGE"][0];
    inputAction.value = "pingsweep";
    inputIP.value = "172.17.0.0/24";
    inputSite.value = "pacific";
}

function submit()
{
    var selection = selectNotification[selectNotification.selectedIndex].value;

    var inputDict = {};
    inputDict["TIMESTAMP"] = selection;
    inputDict["ACTION"] = inputAction.value;
    inputDict["RESPONSE"] = {};
    inputDict["RESPONSE"][inputIP.value] = inputSite.value;

    var inputText = JSON.stringify(inputDict);
    //console.log(inputText);
    putLiveData("request="+inputText)

    selectNotification.value = "";
    lblMessage.innerHTML = "";
    inputAction.value = "";
    inputIP.value = "";
    inputSite.value = "";
}

// start
refreshPage();
//window.setInterval(function(){refreshPage();}, 1000);
