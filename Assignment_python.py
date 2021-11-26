"Antivirus is generating system logs with the following format.SAC:0|Sacumen|CAAS|2021.2.0|3|MALICIOUS|High|cat=C2 cs1Label=subcat cs1=DNS_TUNNELING cs2Label=vueUrls cs2=https://aws-dev.sacdev.io/alerts?filter=alertId%3D%3D81650 cs3Label=Tags cs3=USA,Finance cs4Label=Url cs4=https://aws-dev.sacdev.io/settings/tir?rules.sort=4%3A1&filter=state%3D%3D2&selected=9739323 cn1Label=severityScore cn1=900 msg=Malicious activity was reported in CAAS\= A threat intelligence rule has been automatically created in DAAS. dhost=bad.com dst=1.1.1.1"

str = "cat=C2 cs1Label=subcat cs1=DNS_TUNNELING cs2Label=vueUrls cs2=https://aws-dev.sacdev.io/alerts?filter=alertId%3D%3D81650 cs3Label=Tags cs3=USA,Finance cs4Label=Url cs4=https://aws-dev.sacdev.io/settings/tir?rules.sort=4%3A1&filter=state%3D%3D2&selected=9739323 cn1Label=severityScore cn1=900 msg=Malicious activity was reported in CAAS\= A threat intelligence rule has been automatically created in DAAS. dhost=bad.com dst=1.1.1.1"


splt_str = str.split(" ")

f_splt = []
print("First splt: ",splt_str)
d = {}
for substr in splt_str:
	splt_str2 = []
	if substr.find("="):
		spl_str2 = substr.split("=",1)
		f_splt.append(spl_str2)
print(f_splt)	

for pair in f_splt:
	if len(pair) >= 2:
		d[pair[0]] = pair[1]
print("--------------------------------------------------------------------------------")
for key,value in d.items():
	print(key+": "+value)


# output:

# cat: C2
# cs1Label: subcat
# cs1: DNS_TUNNELING
# cs2Label: vueUrls
# cs2: https://aws-dev.sacdev.io/alerts?filter=alertId%3D%3D81650
# cs3Label: Tags
# cs3: USA,Finance
# cs4Label: Url
# cs4: https://aws-dev.sacdev.io/settings/tir?rules.sort=4%3A1&filter=state%3D%3D2&selected=9739323
# cn1Label: severityScore
# cn1: 900
# msg: Malicious
# CAAS\:
# dhost: bad.com
# dst: 1.1.1.1
# ---------------------------------------------------------------------------------------------------

