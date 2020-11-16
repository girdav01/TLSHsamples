# This sample show how to get TLSH of a sample via VirusTotal VT API V3
# Note that V2 scan reports does not include TLSH since it is a new VT feature.
# Note that VT got the T1 prefix on all TLSH while Malware Bazaar does not.
import json
import virustotal3.core
import tmconfig  #tmconfig.py with your api keys

API_KEY = tmconfig.vt_api_key # or just copy your API key here
# file_hash = '9351483aad526b5fc5838afa012701790bb93ee9' #test1 sha1
file_hash = '6fb5af0a4381411ff1d9c9041583069b83a0e94ff454cba6fba60e9cd8c6e648' #test2 with a sha256
#file_hash = '965b76f9ea006ff87e31b287638ae81674f0692100bdb0b0c7ded278803fb61f' #test3
try:
    vtcore = virustotal3.core.Files(API_KEY)
    report = vtcore.info_file(file_hash, timeout=None)
    pretty_data = json.dumps(report, indent=4)
    print(pretty_data)
    json2 = json.loads(pretty_data)
    if "tlsh" in json2['data']['attributes']:
        for key in json2['data']['attributes']:
            value = json2['data']['attributes'][key]
            print("The key and value are ({}) = ({})".format(key, value))
        print("                               ")
        print("==============================")
        print("tlsh Key exist and it is ")
        tlsh = json2['data']['attributes']['tlsh']
        print(tlsh)
    else:
        print("no TLSH for this sample. Too old for having one")

except Exception as e:
  print("An exception occurred: "+ str(e))
