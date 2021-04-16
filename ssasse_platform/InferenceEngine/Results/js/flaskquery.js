var httpRequest = new XMLHttpRequest();
var flaskURL = "https://127.0.0.1:8444/api/";
var httpResponse = null
httpRequest.onreadystatechange = function() {httpResponse = httpRequest.responseText}

function getLiveData(options)
{
    httpRequest.open("GET", flaskURL+"?"+options, false);
    httpRequest.send();
    return httpResponse;
}

function putLiveData(options)
{
    httpRequest.open("GET", flaskURL+"?"+options, false);
    httpRequest.send();
    return httpResponse;
}

function getDummyData(fileName)
{
    httpRequest.open("GET", fileName, false);
    httpRequest.send();
    return httpResponse;
}
