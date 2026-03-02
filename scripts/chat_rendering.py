# coding: utf-8
import os
import pandas as pd
import json
from scripts.html_security import escape_attr, escape_text, sanitize_html_fragment, sanitize_url

"""
This helper renders chat conversations passed as a json dump of a dictionary:
    --conversation contact id/name
        --num message (start from 0 each time is fine)
            --data-name = correspondant (phone or ID)
            --data-time = time of message (formatted as str)
            --from_me = (boolean - 0 = received / 1 = sent)
            --message = message content

example:
    {
        "Vincent":{
            "0":{
                "data-name": "Vincent",
                "data-time": "2020-11-10 08:00:00",
                "from_me" : 0,
                "Message": "What is your favorite tool?"
            },
            "1":{
                "data-name": "Vincent",
                "data-time": "2020-11-10 08:01:00",
                "from_me" : 1,
                "Message": "iLEAPP !"
            },
        },
        "Mike,Vincent":{
            "0":{
                "data-name": "Mike",
                "data-time": "2020-11-10 08:08:00",
                "from_me" : 0,
                "Message": "Who like apples ?"
            },
            "1":{
                "data-name": "Vincent",
                "data-time": "2020-11-10 08:09:00",
                "from_me" : 1,
                "Message": "I do!"
            }
    }

"""

chat_HTML= """
<div class="container clearfix">
    <div class="people-list" id="people-list">
      <ul class="list" id="list">

      </ul>
    </div>
    <div class="chat">
      <div class="chat-header clearfix">


        <div class="chat-about">
          <div class="chat-with" id="chat-with">Click on the left to view messages</div>
          <div class="chat-num-messages" id="chat-num-messages"></div>
        </div>
        </div> <!-- end chat-header -->
        <div id="chat-history" class="chat-history">
        </div>
    </div>
</div>
<br />
<br />
"""

js = """
<script>
function sanitizeUrl(url, allowDataMedia){
    if (!url) return "#";
    const value = String(url).trim();
    if (!value) return "#";
    const lowered = value.toLowerCase();
    if (lowered.startsWith("javascript:") || lowered.startsWith("vbscript:")) return "#";
    if (lowered.startsWith("data:")) {
        if (allowDataMedia && (lowered.startsWith("data:image/") || lowered.startsWith("data:audio/") || lowered.startsWith("data:video/"))) {
            return value;
        }
        return "#";
    }
    return value;
}

function sanitizeFragment(htmlText){
    const template = document.createElement("template");
    template.innerHTML = htmlText || "";
    const blockedTags = ["SCRIPT", "STYLE", "IFRAME", "OBJECT", "EMBED"];
    const nodes = template.content.querySelectorAll("*");
    for (const node of nodes) {
        if (blockedTags.includes(node.tagName)) {
            node.remove();
            continue;
        }
        const attrs = Array.from(node.attributes);
        for (const attr of attrs) {
            const name = attr.name.toLowerCase();
            if (name.startsWith("on")) {
                node.removeAttribute(attr.name);
                continue;
            }
            if (name === "href" || name === "src") {
                const allowDataMedia = name === "src" && ["IMG", "AUDIO", "VIDEO", "SOURCE"].includes(node.tagName);
                node.setAttribute(attr.name, sanitizeUrl(attr.value, allowDataMedia));
            }
        }
    }
    return template.content;
}

function createDivMessages (m){

    const li = document.createElement("li");
    const messageData = document.createElement("div");
    messageData.className = "message-data";
    const messageBlock = document.createElement("div");
    messageBlock.className = "message my-message";
    let name = m["data-name"] || "";

    if (m["from_me"] == 1) {
        messageBlock.className = "message other-message float-right";
        li.className = "clearfix";
        messageData.className = "message-data align-right";
        name = "Local User";
    }

    const ts = document.createElement("span");
    ts.className = "message-data-time";
    ts.textContent = m["data-time"] || "";
    const spacer = document.createTextNode(" \u00a0 \u00a0 ");
    const nameNode = document.createElement("span");
    nameNode.className = "message-data-name";
    nameNode.textContent = name;
    messageData.appendChild(ts);
    messageData.appendChild(spacer);
    messageData.appendChild(nameNode);

    const safeBody = sanitizeFragment(m["body_to_render"] || "");
    messageBlock.appendChild(safeBody);

    li.appendChild(messageData);
    li.appendChild(messageBlock);
    return li;
}

function showHistory (messages, name){

    const container = document.getElementById("chat-history");
    container.textContent = "";
    const ul = document.createElement("ul");
    for (let m in messages){
      ul.appendChild(createDivMessages(messages[m], name));
    }
    container.appendChild(ul);
    return false;
}

function createPeopleList(list){

    const listNode = document.getElementById("list");
    listNode.textContent = "";
    for (let p in list){
        const li = document.createElement("li");
        li.className = "clearfix";
        li.dataset.contact = list[p];
        const about = document.createElement("div");
        about.className = "about";
        const name = document.createElement("div");
        name.className = "name";
        name.textContent = list[p];
        about.appendChild(name);
        li.appendChild(about);
        listNode.appendChild(li);
    }
}

function updateHeader(name, num){
    document.getElementById("chat-with").textContent = name;
    document.getElementById("chat-num-messages").textContent = "Total: " + num;
    return false;
}

$(document).ready(function() {
    var messages = json;

    createPeopleList(Object.keys(messages));

    $('#list').on('click', 'li', function(){
        $('.people-list li').removeClass('active');
        $(this).addClass('active');
        var id = this.dataset.contact;
        showHistory(messages[id], id);
        updateHeader(id, Object.keys(messages[id]).length);
        return false;
    })
});
</script>
"""

mimeTypeIcon = {
    "image":"📷",
    "audio":"🎧",
    "video":"🎥",
    "animated":"🎡",
    "application":"📎",
    "text":"Ŧ"
}

"""
format JS to include in report html
"""
def render_js_chat(chat_json):
    safe_chat_json = (
        chat_json.replace('<', '\\u003c')
        .replace('>', '\\u003e')
        .replace('&', '\\u0026')
        .replace('\u2028', '\\u2028')
        .replace('\u2029', '\\u2029')
    )
    json_js = """
    <script>
     var json = {0};
    </script>
    """.format(safe_chat_json)
    return '\n'.join([json_js,js])

"""
helper to render body with attachments
"""
def integrateAtt(rec):
    if rec["file-path"]:
        att_type = rec["content-type"].split('/')[0] if rec["content-type"] else 'application'
        filename = os.path.basename(rec["file-path"])
        body = escape_text(rec["message"] if rec["message"] else '')
        safe_path = escape_attr(sanitize_url(rec["file-path"]))
        safe_content_type = escape_attr(rec["content-type"]) if rec["content-type"] else ""
        safe_filename = escape_text(filename)
        if att_type == 'image':               
            source = '<img src="{}" width="256" height="256"/>'.format(safe_path)
        
        elif att_type == 'audio':
            source = """
            <audio controls>
              <source src="{0}" type="{1}">
              <p><a href="{0}"></a> </p>
            </audio>
            """.format(safe_path, safe_content_type)
        elif att_type == 'video':
            source = """
            <video controls width="256">
              <source src="{0}" type="{1}">
              <p><a href="{0}"></a> </p>
            </video>
            """.format(safe_path, safe_content_type)
        else:
            source = '<a href="{}">{}</a>'.format(safe_path, safe_filename)
        
        return sanitize_html_fragment("\n".join([body, mimeTypeIcon[att_type] + ' ' + source]))
    else:
        return escape_text(rec["message"]) if rec["message"] else ""


"""
transform a chat df to be rendered to js
input : df with following columns:
    - data-name str : contact name / number
    - data-time dt : time of message (needs to be datetime format)
    - message str : text message
    - content-type str : mime type of atachement or None (ex : 'image/jpeg')
    - file-path str : path of attachment to render
    - from_me bool : 0 if received, 1 if sent
output : 
    str including script and data to include in report html

"""
def render_chat(df):
    df["body_to_render"] = df.apply(lambda rec: integrateAtt(rec),axis=1)
    latest_mess = df.groupby("data-name", as_index=False)["data-time"].max()
    df = df.merge(latest_mess, on=["data-name"], how='right', suffixes=["","_latest"]).sort_values(by=['data-time_latest','data-name'], ascending=[False, True])
    df["data-time"] = df["data-time"].dt.strftime('%Y-%m-%d %H:%M:%S')
    chats = {}
    for c in df["data-name"].unique():
        chats[c]=df[df["data-name"] == c][["data-name","from_me","body_to_render","data-time"]].reset_index(drop=True).to_dict(orient='index')

    json_chat = json.dumps(chats)
    return render_js_chat(json_chat)






