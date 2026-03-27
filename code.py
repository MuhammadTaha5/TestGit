# -----------------------Task 1--------------------------
# Logs data from the dataset
    
login_logs = [
("ali","192.168.1.2","failed"),
("sara","192.168.1.3","success"),
("ali","192.168.1.2","failed"),
("john","10.0.0.5","failed"),
("ali","192.168.1.2","failed"),
("sara","192.168.1.4","failed"),
("john","10.0.0.5","success"),
("mike","172.16.0.2","failed"),
("mike","172.16.0.2","failed"),
("mike","172.16.0.2","failed"),
("sara","192.168.1.4","success"),
]



print()
print("---------------------------Task1----------------------------")

def getLogDetails():
    # Dictionary: user -> {success, failed}
    user_stats = {}
    totalSuccess = 0
    totalFailed  = 0

    for log in login_logs:
        user = log[0]
        status = log[2]

        # Initialize user if not present
        if user not in user_stats:
            user_stats[user] = {"success": 0, "failed": 0}

        # Update counts
        if status == "success":
            user_stats[user]["success"] += 1
            totalSuccess += 1
        else:
            user_stats[user]["failed"] += 1
            totalFailed += 1
    return totalSuccess, totalFailed, user_stats

def suspectDetector():
    userSpamRecord = {}
    for log in login_logs:
        user, ip, status = log
        if user not in userSpamRecord:
            userSpamRecord[user] = {
                'ips':[],
                'failedAttempts': 0,
                'successAttempts': 0,
                'userRiskScore': -3
            }
        if ip not in userSpamRecord[user]["ips"]:
            userSpamRecord[user]['ips'].append(ip)
            userSpamRecord[user]['userRiskScore'] += 3
        if status == 'failed':
            userSpamRecord[user]['failedAttempts'] += 1
            userSpamRecord[user]['userRiskScore'] += 2
        elif status == 'success':
            userSpamRecord[user]['successAttempts'] += 1
            userSpamRecord[user]['userRiskScore'] += 1
    return userSpamRecord


# -------------------------Task1--------------------------
totalSuccess, totalFailed,  user_stats = getLogDetails()
# Output
print("Login Summary Per User:")
print ("Total Success Logins:",totalSuccess)
print("Total Failed Logins:", totalFailed)
for user, stats in user_stats.items():
    print(user, "-> Success:", stats["success"], ", Failed:", stats["failed"])


print()
print("---------------------------Task2----------------------------")
userSpamRecord = suspectDetector()
for user, stats in userSpamRecord.items():
    if len(stats['ips']) > 1:
        print(f"{user} → IP Hopping Suspect")
    elif stats['failedAttempts']>=3:
        print(f"{user} → Brute Force Suspect")
    
         
print()
print("---------------------------Task3----------------------------")

for user, stats in userSpamRecord.items():
    print(f"{user} : {stats['userRiskScore']}")
    #print(f"Success : {stats['successAttempts']}")
    #print(f"Failed : {stats['failedAttempts']}")
    #print(f"Ip changed : {len(stats['ips'])-1}")

print()
print("---------------------------Task4----------------------------")
sorted_data = sorted(userSpamRecord.items(), key=lambda x: x[1]['userRiskScore'], reverse=True)

for user, info in sorted_data:
    print(user, info['userRiskScore'])

print()
print("TOP RISKED USERS")
for top, info in sorted_data[:2]:
    print(top, info['userRiskScore'])