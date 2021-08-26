"use strict";

var connection = new signalR.HubConnectionBuilder().withUrl("/chatHub").build();

//Disable send button until connection is established
document.getElementById("sendButton").disabled = true;

connection.on("ReceiveMessage", function (user, message) {
    var li = document.createElement("li");
    document.getElementById("messagesList").appendChild(li);
    // We can assign user-supplied strings to an element's textContent because it
    // is not interpreted as markup. If you're assigning in any other way, you 
    // should be aware of possible script injection concerns.
    li.textContent = `${user} says ${message}`;
});

connection.start().then(function () {
    document.getElementById("sendButton").disabled = true;
}).catch(function (err) {
    return console.error(err.toString());
});

document.getElementById("messageInput").addEventListener("keyup", function (event) {
    if (document.getElementById("messageInput").value == "") {
        document.getElementById("sendButton").disabled = true;
    }
    else
    {
        document.getElementById("sendButton").disabled = false;
    }
});

document.getElementById("sendButton").addEventListener("click", function (event) {
    var message = document.getElementById("messageInput").value;
    if (message != "") {
        var user = document.getElementById("userInput").value;
        connection.invoke("SendMessage", user, message).catch(function (err) {
            return console.error(err.toString());
        });
        event.preventDefault();
        document.getElementById("messageInput").value = "";
    }
});