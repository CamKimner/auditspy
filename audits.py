import os
import pyinputplus
import re
import signal
import subprocess

def main():
    print("Launching")

    if not check_auditd_status():
        response = pyinputplus.inputYesNo("Audit service is not running, run setup? ")
        if response == 'yes':
            setup()
   
    menu_options = ["Search", "Report", "Inspect", "Kill","Keys", "Live", "Quit"]
    while True:
        choice = pyinputplus.inputMenu(menu_options, numbered=True)

        match choice:
            case "Report":
                audit_report()
            case "Search":
                search_logs()
            case "Inspect":
                inspect_process()
            case "Kill":
                kill_process()
            case "Keys":
                get_audit_keys()
            case "Live":
                live_logs()
            case "Quit":
                return

#return true if running, false otherwise
def check_auditd_status():
    check = subprocess.run(["systemctl", "is-active", "auditd"], stdout=subprocess.PIPE, stderr=subprocess.PIPE)

    return check.stdout == b'active\n'

def setup():
    audit_rules = "https://raw.githubusercontent.com/Neo23x0/auditd/master/audit.rules"
    #install auditd 
    subprocess.run(["apt-get","install", "auditd"])
    #replace auditd rules with suggested configuration
    subprocess.run(["wget", "-O","/etc/audit/rules.d/audit.rules",audit_rules])
    #using service instread of systemctl to have auid correctly set
    subprocess.run(["service", "auditd", "start"])

    print("Setup complete")

#Allow user to search logs for available keys
#Would be nice to allow user input, but unsanitized input could spawn shells
def search_logs():
    search_prompt = "Please select attribute to query by\n"
    search_options = ["Key", "Time", "AuditID"]
    search_method = pyinputplus.inputMenu(search_options, numbered=True, prompt=search_prompt)

    match search_method:
        case "Key":
            key_choice = pyinputplus.inputMenu(sorted(list(get_audit_keys())), numbered=True)
            subprocess.run(["ausearch", "-i", "-k", key_choice])
        case "Time":
            subprocess.run(["ausearch", "-i", "-ts", get_audit_ts()])
        case "AuditID":
            aid = pyinputplus.inputInt("Enter audit log id: ")
            subprocess.run(["ausearch", "-i", "-a", str(aid)])


def get_audit_keys():
    rules_file = open("/etc/audit/rules.d/audit.rules", "r")
    #use set to avoid duplicates
    found_keys = set()

    for line in rules_file:
        # regex to search strings with "-k" preceding
        m = re.search('(?<=-k )(\w+)', line)
        if m is not None:
            found_keys.add(m.group(1))

    rules_file.close()

    return found_keys

def inspect_process():
    pid = pyinputplus.inputInt("Enter process id: ")
    print("Process Info: ")
    subprocess.run(["ps", "-up", str(pid)])
    print()
    print("Process Tree: ")
    subprocess.run(["pstree", "-aups", str(pid)])
    print()
    print("Associated Files: ")
    subprocess.run(["lsof", "-p", str(pid)])


def kill_process():
    pid = pyinputplus.inputInt("Enter process id: ")
    subprocess.run(["kill", "-9", str(pid)])

def audit_report():
    ts = get_audit_ts()
    subprocess.run(["aureport", "-ts", ts])

def get_audit_ts():
    options = ["now", "recent","today","this-week","this-month","this-year"]

    return pyinputplus.inputMenu(options, numbered=True)

#Ideally would be monitoring changes to the file in the program and not using tail
def live_logs():
    try:
        #cmd = "tail -f /var/log/audit/audit.log | less"
        #subprocess.run(cmd, shell=True)

        old_action = signal.signal(signal.SIGINT, signal.SIG_IGN)
        os.spawnlpe(os.P_WAIT, 'less', 'less', '+F', "/var/log/audit/audit.log", os.environ)
        signal.signal(signal.SIGINT, old_action)
    except KeyboardInterrupt:
        pass

if __name__ == "__main__":
    main()
