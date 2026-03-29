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
    '''Nested Dictionary created for storing the user records and and each user 
    record is also the distionary storing success and failed login'''
    user_stats = {}
    totalSuccess = 0
    totalFailed  = 0
    #initializing the total success and fail login in log file to 0

    for log in login_logs:
        #iterating through the log file and getting record from entry
        user = log[0]
        status = log[2]
        #getting the user name, and login status from log file

        # Initialize user if not present
        if user not in user_stats:
            user_stats[user] = {"success": 0, "failed": 0}


        # Update counts
        if status == "success":
            user_stats[user]["success"] += 1 #updating the attribute of successful login in user dictionary
            totalSuccess += 1 #incrementing the total success login detail to total success variable

        else:
            user_stats[user]["failed"] += 1 #updating the attribute of failed login in user dictionary
            totalFailed += 1 #incrementing the total failed login detail to total success variable
    return totalSuccess, totalFailed, user_stats 
#returing the totalSuccess, anf failed, each user detail in dictionary format.

def suspectDetector():
    #function defined for suspect detection
    userSpamRecord = {}
    #initializing the empty record dictionary to store each user record
    for log in login_logs:
        #iterating through the log file
        user, ip, status = log
        #storing the username, ip, and status from each entry in log file.
        if user not in userSpamRecord:
            #initializing the user dictionary inside main dictionary to store each user record
            userSpamRecord[user] = {
                #using the list to store the ips that user used.
                'ips':[],
                #to count the number of failed and successful attempts
                'failedAttempts': 0,
                'successAttempts': 0,
                'userRiskScore': 0 #initializing the risk score to zero
            }
        if ip not in userSpamRecord[user]["ips"]:
            if len(userSpamRecord[user]["ips"]) > 0:
                #checking if user logged in from more than one ip
                userSpamRecord[user]['userRiskScore'] += 3
                #increasing the risk by 3 if ip is changed.
                # appending the list to each user record dictionary
            userSpamRecord[user]['ips'].append(ip)
        if status == 'failed':
            #checking if user fails to login increase the risk score by 2
            userSpamRecord[user]['failedAttempts'] += 1
            userSpamRecord[user]['userRiskScore'] += 2
        elif status == 'success':
            #inceasing the risk score by 1 on successful login. this used to get how many times user logged in
            userSpamRecord[user]['successAttempts'] += 1
            userSpamRecord[user]['userRiskScore'] += 1
    return userSpamRecord
#function to get the security requirement
def getSecurityRequirements():
    recommendations = [
        'Lock accounts after 3 failed attempts',
        'Implement Multi-Factor Authentication',
        'Monitor suspicious IP addresses'
    ]
    return recommendations  #returing the recommendation to main function

    


# -------------------------Task1--------------------------
totalSuccess, totalFailed,  user_stats = getLogDetails()
#storing the data from getLogDetail function
# Output
#login summary against each user 
print("Login Summary Per User:")
print ("Total Success Logins:",totalSuccess)
print("Total Failed Logins:", totalFailed)
for user, stats in user_stats.items():
    #printing the total success and failed logins from each user
    print(user, "-> Success:", stats["success"], ", Failed:", stats["failed"])


print()
print("---------------------------Task2----------------------------")
userSpamRecord = suspectDetector()
for user, stats in userSpamRecord.items():
    if len(stats['ips']) > 1:
        '''checking if the length of Ip list is greater than 1 means
        user logged in from multiple ips so it is suspected''' 

        print(f"{user} → IP Hopping Suspect")
    if stats['failedAttempts']>=3:
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
print("---- SECURITY REPORT ----")
print("HIGH RISKED USERS")
for top, info in sorted_data[:2]:
    print(top)

securityRecommendations = getSecurityRequirements()
print("Recommendations")
for index, value in enumerate(securityRecommendations, start=1):
    print(f"{index}. {value}")