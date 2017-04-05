import urllib,re,sys,json,hashlib,ipaddress
import requests
import socket
import yara
from bs4 import BeautifulSoup

PASSIVE_DNS_API_URL = 'https://www.virustotal.com/vtapi/v2/ip-address/report'
PASSIVE_DNS_API_KEY = '#'

def get_host_names(ip):

  host_names = []

  parameters = {'ip': ip, 'apikey': PASSIVE_DNS_API_KEY}
  response = urllib.urlopen('%s?%s' % (PASSIVE_DNS_API_URL, urllib.urlencode(parameters))).read()

  response_dict = json.loads(response)
  for r in response_dict['resolutions']:
    host_names.append(r['hostname'])
  return host_names


hashes = {"Magento": {
    "js/lib/flex.js": {
        "054d2e143c970eb7bd06fd8018365a9d": "CE 1.1.0", 
        "1d12e583109a611dff2dfb01f6454ff6": "CE 1.9.3.2", 
        "4040182326f3836f98acabfe1d507960": "CE 1.4.0.1", 
        "8502efe74970465a64079318115b8c0c": "CE 1.0", 
        "9713d594894d117ef6a454463dc5ede0": "EE 1.14.3.0", 
        "9fe92ce6c54deba24c2cd0d484d848cd": "EE 1.14.2.0", 
        "e37eeca21ff013a52085fc4f7bbe3299": "CE 1.9.1.0", 
        "eb84fc6c93a9d27823dde31946be8767": "CE 1.4.0.0", 
        "f1312acc7a5314daf5b2f3e1c4f1ef37": "EE 1.14.1.0"
    },
    "js/mage/adminhtml/product.js": {
        "0c2776e2f98445c0f325cd0b42196e67": "EE 1.14.2.0", 
        "12770f4009de359028116ee948f664f9": "EE 1.11.0.2", 
        "356497d3819ccdd9df7e4811bc376dca": "CE 1.9.3.2", 
        "5290e61c41b2d880a93954a579e5ab36": "EE 1.14.1.0", 
        "71ab5165873c747ec18ac28616d43693": "CE 1.0", 
        "7941874630e6f7d6fa1c7b040cd00157": "CE 1.9.1.0", 
        "81d8065e9cee57a5e30ef2622f3a4506": "CE 1.6.0.0", 
        "b67826d2dee4f706dbfa3bbf97208868": "EE 1.11.2.0", 
        "bd85168aa12ea9816488a1fa55e32dce": "EE 1.14.3.0", 
        "d50a6470367a63f6ad50eb84120dffa5": "CE 1.1.0", 
        "e887acfc2f7af09e04f8e99ac6f7180d": "CE 1.3.0"
    }, 
    "js/mage/adminhtml/sales.js": {
        "0e400488c83e63110da75534f49f23f3": "CE 1.3.2", 
        "17da0470950e8dd4b30ccb787b1605f5": "CE 1.1.x", 
        "1cb6e72078c384df2d62745e34060fed": "CE 1.9.0.x", 
        "26c8fd113b4e51aeffe200ce7880b67a": "CE 1.8.0.0", 
        "2adfdc52c344f286283a7ca488ccfcab": "CE 1.9.2.x", 
        "3fe31e1608e6d4f525d5db227373c5a0": "EE 1.13.0.x", 
        "40417cf4bee0e99ffc3930b1465c74ae": "EE 1.11.2.0", 
        "40c6203f5316caec1e10ac3f2bbb23db": "EE 1.14.2.0", 
        "4422dffc16da547c671b086938656397": "CE 1.4.2.0", 
        "48d609bb2958b93d7254c13957b704c4": "CE 1.6.x", 
        "4b4cc67bdb0c87ec0545c23d9afc0df0": "CE 1.9.3.2", 
        "5112f328e291234a943684928ebd3d33": "CE 1.1.x", 
        "5656a8c1c646afaaf260a130fe405691": "CE 1.8.1.0", 
        "720409ee3dec64a678117c488f6b3f47": "CE 1.9.3.x", 
        "7ca2e7e0080061d2edd1e5368915c267": "EE 1.10.1.1", 
        "839ead52e82a2041f937389445b8db04": "CE 1.3.3.0", 
        "86e8bca8057d2dd65ae3379adca0afff": "EE 1.14.0.x", 
        "95e730c4316669f2df71031d5439df21": "CE 1.1.0", 
        "9a5d40b3f07f8bb904241828c5babf80": "EE 1.13.1.0", 
        "a0436f1eee62dded68e0ec860baeb699": "CE 1.9.1.0", 
        "a4296235ba7ad200dd042fa5200c11b0": "CE 1.6.0.0", 
        "a86ad3ba7ab64bf9b3d7d2b9861d93dc": "CE 1.0", 
        "aeb47c8dfc1e0b5264d341c99ff12ef0": "EE 1.11.0.2", 
        "ba43d3af7ee4cb6f26190fc9d8fba751": "EE 1.14.1.0", 
        "bdacf81a3cf7121d7a20eaa266a684ec": "CE 1.5.1.0", 
        "d1bfb9f8d4c83e4a6a826d2356a97fd7": "CE 1.3.1", 
        "d80c40eeef3ca62eb4243443fe41705e": "CE 1.5.0.1", 
        "ebc8928fe532d05a7d485f577eadf31f": "EE 1.14.3.0", 
        "ec6a34776b4d34b5b5549aea01c47b57": "EE 1.10.0.2"
    }, 
    "js/mage/adminhtml/tools.js": {
        "2848e06105eddf6bc6b4fcb2d892f569": "EE 1.12.0.0", 
        "4f3160ebb108403f8ad4f9e9efe0d087": "EE 1.11.2.0", 
        "524dc6afe12816cdcde21677b6cb6e26": "EE 1.11.0.2", 
        "6047e09534fd4fb028fc10b0d3da8cfe": "EE 1.14.2.0", 
        "6cf85d9068a84007202411ca06ed6b7b": "CE 1.9.1.0", 
        "762127f705c80c9bb6351fe756fa7c00": "EE 1.14.3.0", 
        "86bbebe2745581cd8f613ceb5ef82269": "CE 1.7.0.x", 
        "cb453762423578b0e32c8eb94e10a62d": "CE 1.9.3.2", 
        "d594237950932b9a3948288a020df1ba": "CE 1.3.x", 
        "d7f5a1c048db67c081d94ee27e53b8bb": "CE 1.6.0.0", 
        "df365e6f1093cad5afc5652c2a87de9a": "EE 1.14.1.0", 
        "ea81bcf8d9b8fcddb27fb9ec7f801172": "CE 1.3.2.2", 
        "ee9bda25c8f08856ce6002dea7d90e16": "CE 1.7.0.0", 
        "f38b0f0c05e7d62782609f80dc50ad7c": "CE 1.4.2.0"
    }, 
    "js/mage/translate_inline.js": {
        "13775c527cd39bced651050d072b0021": "CE 1.0", 
        "219437ece6900633563e3cdee1f9d147": "CE 1.6.0.0", 
        "55941704b38897be5673d3dca46bd78d": "CE 1.9.3.2", 
        "5fec45f215952f4e3becd5df3655ee44": "EE 1.14.2.0", 
        "653bc4fd337c63092234f0deedbfea37": "EE 1.14.1.0", 
        "66cec7e9959fa77a8c472e7c251686e0": "EE 1.14.3.0", 
        "69fc9a8fa89a5805f89c89e79c5b7a38": "EE 1.11.0.2", 
        "6dd58e1132b1fcb09f5f20eb3c5f2e91": "CE 1.9.1.0", 
        "90137353d55d43a253bea307cafa263e": "CE 1.1.0", 
        "913b5412af26c3bb060b93a478beadc8": "CE 1.9.1.1", 
        "bcc32eeec4a656ee3370827bfd0585b5": "EE 1.11.2.0"
    }, 
    "js/prototype/validation.js": {
        "1342ac8a049bb9fcd7e3c5a911822f08": "CE 1.0", 
        "295494d0966637bdd03e4ec17c2f338c": "CE 1.4.1.0", 
        "594c40f2438b06dcc07079786d5c38c1": "CE 1.4.2.0", 
        "60943708791871a6964745805a1c60a9": "CE 1.1.0", 
        "d3252becf15108532d21d45dced96d53": "CE 1.4.1.1"
    }, 
    "skin/adminhtml/default/default/boxes.css": {
        "05c27c288ade60aa2c4a8b02c1bddf64": "CE 1.9.3.2", 
        "0902e89fb50b22d44f8242954a89300c": "EE 1.12.0.0", 
        "0e8a85aee65699c9cfaed8166d2ee678": "CE 1.0", 
        "1cbeca223c2e15dcaf500caa5d05b4ed": "CE 1.7.0.0", 
        "29651cb812ad5a4b916d1da525df09ff": "CE 1.1.0", 
        "30a39f4046f3daba55cfbe0e1ca44b4c": "CE 1.5.0.1", 
        "3c92a14ac461a1314291d4ad91f1f858": "EE 1.13.1.0", 
        "5b537e36cb7b2670500a384f290bcaf8": "CE 1.4.2.0", 
        "61e47784d7254e531bb6ce3991d68487": "CE 1.9.2.x", 
        "6aefb246b1bb817077e8fca6ae53bf2c": "CE 1.2.0", 
        "6b5b0372fbeb93675bfabe24d594bd02": "EE 1.10.1.1", 
        "76a565d95fa10e5449bf63549bc5c76b": "CE 1.3.3.0", 
        "84b67457247969a206456565111c456b": "CE 1.1.x", 
        "89c7b659d4e60aabd705af87f0014524": "EE 1.14.1.0", 
        "89e986c50a1efe2e0f1a5f688ca21914": "EE 1.14.2.0", 
        "8a5c088b435dbcf1bbaac9755d4ed45f": "EE 1.12.0.x", 
        "a2c7f9ddda846ba76220d7bcbe85c985": "CE 1.2.1", 
        "adca1795a4c58ce6a6332ceb2a6c5335": "CE 1.5.1.0", 
        "b497d3538b1c18012455527f267bef53": "EE 1.11.0.2", 
        "ba8dd746c8468bfd1cff5c77eadc71a4": "CE 1.9.x", 
        "c89fac64edb359d899aa7ae792ec5809": "EE 1.14.3.0", 
        "d0511b190cdddf865cca7873917f9a69": "CE 1.1.1", 
        "dd6fbd6cc6376045b3a62a823af9a361": "EE 1.10.0.2", 
        "e895117cde7ba3305769bc1317a47818": "EE 1.11.2.0"
    }
  }
}


def yara_scan():

  rules = yara.compile('yara/rules.yar')

  for l in host_links:

    print "[+] Scanning %s" % (l)

    try:
      result = s.get(l, allow_redirects=False, timeout=3.0)

      content = result.text.encode('utf-8')

      matches = rules.match(data=content)

      for m in matches:

        host_yara_matches.append("[+] YARA: Match at %s for %s" % (l,m.rule))

    except:

      print "[+] Could not connect to %s" % (l)


def get_app_ver(host_name,host_app):

  version_identified = []

  for a_key, a_value in hashes.iteritems():
    if a_key==host_app:

      for f_key, f_value in a_value.iteritems():

        url = "%s%s" % (host_name,f_key)
        result = s.get("%s%s" % (host_name,f_key))
        filehash = hashlib.md5(result.text).hexdigest()
        print url,filehash


        for h_key, h_value in f_value.iteritems():
          if h_key == filehash and not h_value in version_identified:
            version_identified.append(h_value)

      if len(version_identified)>0:
        print "[+] Magento Version %s Identified" % (",".join(version_identified))
      else:
        print "[+] Magento Version NOT Identified"


app = [
{"app" : "Magento", "string" : "Mage.Cookies.path"},
{"app" : "Magento", "string" : "mage/cookies.js"}
]

conditions = [
{"app" : "Magento", "url" : "admin/", "allow_redirect" : "true", "condition" : {200,401}, "status" : "Magento Admin Default Location"},
{"app" : "Magento", "url" : "downloader/", "allow_redirect" : "true", "condition" : {200,401}, "status" : "Magento Downloader Open"},
{"app" : "Magento", "url" : "rss/order/new/", "allow_redirect" : "true", "condition" : {401}, "status" : "Magento RSS Order New Open"},
{"app" : "Magento", "url" : "rss/catalog/review/", "allow_redirect" : "true", "condition" : {401}, "status" : "Magento RSS Catalog Review"},
{"app" : "Magento", "url" : "rss/catalog/notifystock/", "allow_redirect" : "true", "condition" : {401}, "status" : "Magento RSS Catalog NotifyStock"},
{"app" : "Magento", "url" : "checkout/onepage/", "allow_redirect" : "false", "condition" : {200,302}, "status" : "Magento OnePage Checkout"},
{"app" : "Magento", "url" : "errors/", "allow_redirect" : "true", "condition" : {200}, "status" : "Magento Errors"},
{"app" : "Magento", "url" : "var/", "allow_redirect" : "true", "condition" : {200}, "status" : "Magento Var"},
{"app" : "Magento", "url" : "var/cache/", "allow_redirect" : "true", "condition" : {200}, "status" : "Magento Var Cache"},
{"app" : "Magento", "url" : "var/session/", "allow_redirect" : "true", "condition" : {200}, "status" : "Magento Var Session"},
{"app" : "Magento", "url" : "var/backups/", "allow_redirect" : "false", "condition" : {200}, "status" : "Magento Var Backups"}
]


def get_app(host_content):
  host_app = "Unknown"
  for a in app:
    if (host_content.find(a["string"]) >= 0):
      host_app=a["app"]
      break
  print "[+] %s Application Detected" % (host_app)
  return host_app


def get_links_process(bso,host_name,tag,element):

  for link in bso.find_all(tag):

    link_result=""

    if link.get(element):
      if link.get(element)[0:4]=="http":
        link_result = link.get(element)
      elif link.get(element)[0:2]=="//":
        link_result = host_name+link.get(element)[2:]
      elif link.get(element)[0:1]=="/":
        link_result = host_name+link.get(element)[1:]

      if link_result!="" and link_result not in host_links:
        host_links.append(link_result)



def get_links(host_name,host_content):

  bso = BeautifulSoup(host_content, 'html.parser')

  get_links_process(bso,host_name,'a','href')
  get_links_process(bso,host_name,'script','src')


def get_conditions(host,host_app):

  for c in conditions:

    if c['app'] == host_app:

      try:
        if c['allow_redirect']=="true":
          result = s.get("%s%s" % (host_name,c['url']), allow_redirects=True)

        else:
          result = s.get("%s%s" % (host_name,c['url']), allow_redirects=False)

        if result.status_code in c['condition']:
          print "[+] %s - %s - %s" % (host_app,c['status'],result.status_code)

      except:
        "[+] Could not connect for condition %s" % (c['url'])




host = sys.argv[1]
hostc = sys.argv[2]
s = requests.Session()

scheme="http"
host = host.replace("http://","").replace("https://","")
print "[+] Check for", host

hosts_done = []

if ipaddress.IPv4Address(unicode(host)).is_global:
  host_names = get_host_names(host)
else:
  host_names = [host]


scheme="http"


#get_app_ver("http://bouton.co.uk/","Magento")


for host in host_names:
  print "[+] Host %s found" % (host)




for host in host_names:

  if hostc:
    if hostc!=host:
      continue

  try:

    #get index
    result = s.get("%s://%s/" % (scheme,host), allow_redirects=True)

    host_name=result.url
    host_status=result.status_code

    if host_name not in hosts_done:

      print "[+] Processing %s (%s)" % (host_name,host_status)

      #determine app
      host_app = get_app(result.text)

      if host_app!="Unknown":
        get_app_ver(host_name,host_app)
        get_conditions(host_name,host_app)

      host_links = []

      #add root to links array
      host_links.append(host_name)
      get_links(host_name,result.text)

      #yara scanning
      host_yara_matches = []
      yara_scan()

      for y in host_yara_matches:
        print y

      hosts_done.append(host_name)


    else:
      print "[+] Duplicate host %s found. Skipping" % (host)

  except:
    print "Unexpected error:", sys.exc_info()[0]
    print "[+] Cannot connect to %s" % (host)
    continue
