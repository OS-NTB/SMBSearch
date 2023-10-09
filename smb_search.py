from smb.SMBConnection import SMBConnection
import os
import tempfile
import re
import sys
import datetime
from optparse import OptionParser

class SmbSearch:
    def __init__(self, server, username, password):
        self.server = server
        self.port = 445
        self.conn = SMBConnection(username, password, "name", server, use_ntlm_v2=True, sign_options=SMBConnection.SIGN_WHEN_SUPPORTED, is_direct_tcp=True)
        self.time = datetime.datetime.now()
        self.credentials = {
            "Cloudinary"  : "cloudinary://.*",
            "Firebase URL": ".*firebaseio\.com",
            "Slack Token": "(xox[p|b|o|a]-[0-9]{12}-[0-9]{12}-[0-9]{12}-[a-z0-9]{32})",
            "RSA private key": "-----BEGIN RSA PRIVATE KEY-----",
            "SSH (DSA) private key": "-----BEGIN DSA PRIVATE KEY-----",
            "SSH (EC) private key": "-----BEGIN EC PRIVATE KEY-----",
            "OPENSSH private key": "-----BEGIN OPENSSH PRIVATE KEY-----",
            "PGP private key block": "-----BEGIN PGP PRIVATE KEY BLOCK-----",
            "Amazon AWS Access Key ID": "AKIA[0-9A-Z]{16}",
            "Amazon MWS Auth Token": "amzn\\.mws\\.[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}",
            "AWS API Key": "AKIA[0-9A-Z]{16}",
            "Facebook Access Token": "EAACEdEose0cBA[0-9A-Za-z]+",
            "Facebook OAuth": "[f|F][a|A][c|C][e|E][b|B][o|O][o|O][k|K].*['|\"][0-9a-f]{32}['|\"]",
            "GitHub": "[g|G][i|I][t|T][h|H][u|U][b|B].*['|\"][0-9a-zA-Z]{35,40}['|\"]",
            "Generic API Key": "[a|A][p|P][i|I][_]?[k|K][e|E][y|Y].*['|\"][0-9a-zA-Z]{32,45}['|\"]",
            "Generic Secret": "[s|S][e|E][c|C][r|R][e|E][t|T].*['|\"][0-9a-zA-Z]{32,45}['|\"]",
            "Google API Key": "AIza[0-9A-Za-z\\-_]{35}",
            "Google Cloud Platform API Key": "AIza[0-9A-Za-z\\-_]{35}",
            "Google Cloud Platform OAuth": "[0-9]+-[0-9A-Za-z_]{32}\\.apps\\.googleusercontent\\.com",
            "Google Drive API Key": "AIza[0-9A-Za-z\\-_]{35}",
            "Google Drive OAuth": "[0-9]+-[0-9A-Za-z_]{32}\\.apps\\.googleusercontent\\.com",
            "Google (GCP) Service-account": "\"type\": \"service_account\"",
            "Google Gmail API Key": "AIza[0-9A-Za-z\\-_]{35}",
            "Google Gmail OAuth": "[0-9]+-[0-9A-Za-z_]{32}\\.apps\\.googleusercontent\\.com",
            "Google OAuth Access Token": "ya29\\.[0-9A-Za-z\\-_]+",
            "Google YouTube API Key": "AIza[0-9A-Za-z\\-_]{35}",
            "Google YouTube OAuth": "[0-9]+-[0-9A-Za-z_]{32}\\.apps\\.googleusercontent\\.com",
            "Heroku API Key": "[h|H][e|E][r|R][o|O][k|K][u|U].*[0-9A-F]{8}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{12}",
            "MailChimp API Key": "[0-9a-f]{32}-us[0-9]{1,2}",
            "Mailgun API Key": "key-[0-9a-zA-Z]{32}",
            "Password in URL": "[a-zA-Z]{3,10}://[^/\\s:@]{3,20}:[^/\\s:@]{3,20}@.{1,100}[\"'\\s]",
            "PayPal Braintree Access Token": "access_token\\$production\\$[0-9a-z]{16}\\$[0-9a-f]{32}",
            "Picatic API Key": "sk_live_[0-9a-z]{32}",
            "Slack Webhook": "https://hooks.slack.com/services/T[a-zA-Z0-9_]{8}/B[a-zA-Z0-9_]{8}/[a-zA-Z0-9_]{24}",
            "Stripe API Key": "sk_live_[0-9a-zA-Z]{24}",
            "Stripe Restricted API Key": "rk_live_[0-9a-zA-Z]{24}",
            "Square Access Token": "sq0atp-[0-9A-Za-z\\-_]{22}",
            "Square OAuth Secret": "sq0csp-[0-9A-Za-z\\-_]{43}",
            "Twilio API Key": "SK[0-9a-fA-F]{32}",
            "Twitter Access Token": "[t|T][w|W][i|I][t|T][t|T][e|E][r|R].*[1-9][0-9]+-[0-9a-zA-Z]{40}",
            "Twitter OAuth": "[t|T][w|W][i|I][t|T][t|T][e|E][r|R].*['|\"][0-9a-zA-Z]{35,44}['|\"]",
            "password": "(password|passwd|pass|pwd):(\S+)",
            "password":"(password|passwd|pass|pwd)=(\S+)",
            "MD5 Key":"/^[a-f0-9]{32}$/i"
        }
        self.suspicious = {
            "Password Document":"^.*(password|passwords).*\.(txt|rtf|docx|xlsx|pdf|xls|doc)$",
            "Keepass Database": "^.*\.(kbdx|kbd)$",
            "Configuration File": "^.*\.(config|conf|cfg|ini)$",
            "Database": "^.*\.(sqlite|db3|db)$",
            "Archive": "^.*\.(zip|rar|7z|tar|gz)$",
            "Script":"^.*\.(pl|py|rb|sh|bat|ps1)$",
            "Document":"^.*\.(docx|doc|rtf|pdf)$",
            "Log File":"^.*\.log$",
            "Spreadsheet":"^.*\.(xlsx|xls)$",
            "Backup":"^.*\.bak$",
            "CSV File":"^.*\.csv$",
            "Text File":"^.*\.txt$",
            "Putty Format SSH Key":"^.*\.ppk$",
            "Private Key":"^.*\.pem$",
            "Certificate":"^.*\.(pfx|cer|der)",
            "Apache Configuration File":"^.*\.htaccess$",
            "Apache Basic Authentication File":"^.*\.htpasswd$",
            "WordPress Configuration File":"^.*wp-config.*$"
        }
        self.search_through = {
            "Text File":"^.*\.txt$",
            "Log File":"^.*\.log$",
            "Configuration File": "^.*\.(config|conf|cfg|ini)$",
            "Script":"^.*\.(pl|py|rb|sh|bat|ps1)$",
            "Apache Configuration File":"^.*\.htaccess$",
            "Apache Basic Authentication File":"^.*\.htpasswd$"
        }   

    def scan_shares(self):
        try:
            self.conn.connect(self.server, self.port)
            shares = self.conn.listShares()

            for share in shares:
                share_name = share.name
                print(f'[{self.time.strftime("%c")}] Scanning \\\{self.server}\{share_name}')
                self.find_suspicious(self.conn, share_name, self.server)
                self.search_files(self.conn, share_name, self.server)
            print(f'[{self.time.strftime("%c")}] Scan completed.')
            self.conn.close()
        except Exception as e:
            print(f'Error: {e}')

    
    def search_files(self, conn, share_name, server, remote_path = "/", local_path =""):
        try:
            contents = conn.listPath(share_name, remote_path)
            for entry in contents:
                remote_file  = os.path.join(remote_path, entry.filename)
                local_file = os.path.join(local_path, entry.filename)

                if not entry.isDirectory:
                    for key, value in self.search_through.items():
                        if re.match(value, entry.filename):
                            with tempfile.NamedTemporaryFile() as file:
                                filepath = remote_file.replace("/","\\")
                                conn.retrieveFile(share_name, remote_file, file)
                                file.seek(0)
                                content = file.read().decode('utf-8', 'ignore').translate({ord('\u0000'): None})
                                self.find_creds(content, remote_file, share_name, server)
                elif entry.filename not in ['.', '..']:
                    self.search_files(conn, share_name, server, remote_file, local_file)

        except:
            print("",end="")
    
    def find_suspicious(self,conn,share_name, server, remote_path="/", local_path=""):
        try:
            contents = conn.listPath(share_name, remote_path)
            for entry in contents:
                remote_file  = os.path.join(remote_path, entry.filename)
                local_file = os.path.join(local_path, entry.filename)

                if not entry.isDirectory:
                    for key,value in self.suspicious.items():
                        if re.match(value, entry.filename):
                            filepath = remote_file.replace("/","\\")
                            print(f'[{self.time.strftime("%c")}] Found suspicious {key}: \\\{server}\{share_name}{filepath}')
                elif entry.filename not in ['.', '..']:
                    self.find_suspicious(conn, share_name, server, remote_file, local_file)

        except:
            print(f'[{self.time.strftime("%c")}] No access to \\\{server}\{share_name}')

    def find_creds(self, content:str, filename:str, share_name, server):
        for key, value in self.credentials.items():
            if re.findall(value, content):
                found = re.findall(value,content)
                filepath = filename.replace("/","\\")
                print(f'[{self.time.strftime("%c")}] Found possible {key} in \\\{server}\{share_name}{filepath}: {found[0]}')

def main(argv):
    parser = OptionParser()
    parser.add_option('-u', '--username', help="Username that will be used for authentication. Leave blank for anonymous authentication", default="", dest="username")
    parser.add_option('-p', '--password', help="Password that will be used for authentication. Leave Blank for anonymous authentication.", default="", dest="password")
    parser.add_option('-i', '--ip', help="Target IP address", dest="ip")
    (options, args) = parser.parse_args()

    smb = SmbSearch(options.ip, options.username, options.password)
    smb.scan_shares()

if __name__ == "__main__":
    main(sys.argv[1:])