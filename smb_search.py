from smb.SMBConnection import SMBConnection
import os
import tempfile
import pathlib
import re
import sys
import datetime
import argparse

class SMBSearch:
    def __init__(self, server, username, password, domain=''):
        self.server = server
        self.port = 445
        self.conn = SMBConnection(username, password, "name", server, domain, use_ntlm_v2=True, sign_options=SMBConnection.SIGN_WHEN_SUPPORTED, is_direct_tcp=True)
        self.suspicious_filetypes = {
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
            "Google Cloud Platform OAuth": '[0-9]+-[0-9A-Za-z_]{32}\\.apps\\.googleusercontent\\.com',
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
        }
        self.searchable_filetypes = {
            "Text File":"^.*\.txt$",
            "Log File":"^.*\.log$",
            "Configuration File": "^.*\.(config|conf|cfg|ini)$",
            "Script":"^.*\.(pl|py|rb|sh|bat|ps1)$",
            "Apache Configuration File":"^.*\.htaccess$",
            "Apache Basic Authentication File":"^.*\.htpasswd$"
        }  
    
    @property
    def time(self):
        time = datetime.datetime.now()
        return(f'[{time.strftime("%m")}-{time.strftime("%d")}-{time.strftime("%Y")} {time.strftime("%X")}]')

    def scan(self, download:bool):
        print(f'{self.time} Trying to connect to {self.server}')
        try:
            #Connect to server using SMB protocol
            self.conn.connect(self.server, self.port)
            
            #List shares
            shares = self.conn.listShares()

            #For loop that finds suspicious files in each share
            for share in shares:
                share_name = share.name
                print(f'{self.time} Scanning \\\{self.server}\{share_name}')
                try:
                    self.locate_suspicious(self.conn, share_name, self.server)
                except:
                    print(f'{self.time} Cannot connect to share: \\\\{self.server}\{share_name}')
                self.cred_hunt(self.conn, share_name, self.server)
                if download == True:
                    self.download_files(self.conn, share_name, self.server)

            #Close the connection
            self.conn.close()  

        except Exception:
            print(f'[{self.time.strftime("%m")}-{self.time.strftime("%d")}-{self.time.strftime("%Y")} {self.time.strftime("%X")}] Cannot connect to {self.server}')
    
    def locate_suspicious(self, connection, share_name, server, remote_path="/", local_path=""):        
        directory_contents = connection.listPath(share_name, remote_path)
        for entry in directory_contents:
            remote_file = os.path.join(remote_path, entry.filename)
            local_file = os.path.join(local_path, entry.filename)

            if not entry.isDirectory:
                try:                                   
                    for key,value in self.suspicious_filetypes.items():
                        if re.match(value, entry.filename, re.IGNORECASE):
                            filepath = remote_file.replace('/','\\')
                            print(f'{self.time} Found suspicious {key}: \\\{server}\{share_name}{filepath}')
                except:
                    print(f'{self.time} Cannot access: \\\{server}\{share_name}\{entry.filename}')
            elif entry.isDirectory and entry.filename not in ['.','..']:
                try:
                    self.locate_suspicious(connection, share_name, server, remote_file, local_file)
                except:
                    path = remote_file.replace('/','\\')
                    print(f"{self.time} Cannot access: \\\{server}\{share_name}{path}")


    def cred_hunt(self, connection, share_name, server, remote_path = "/", local_path=""):
        try:
            directory_contents = connection.listPath(share_name, remote_path)
            for entry in directory_contents:
                remote_file = os.path.join(remote_path, entry.filename)
                local_file = os.path.join(local_path, entry.filename)
            
                if not entry.isDirectory:
                    for value in self.searchable_filetypes.values():
                        if re.match(value, entry.filename):
                            with tempfile.NamedTemporaryFile() as file:
                                connection.retrieveFile(share_name, remote_file, file)
                                file.seek(0)
                                content = file.read().decode('utf-8', 'ignore').translate({ord('\u0000'): None})
                                
                                for key, value in self.credentials.items():
                                    if re.findall(value, content):
                                        found = re.findall(value,content)
                                        filepath = remote_file.replace('/','\\')
                                        print(f'{self.time} Found possible {key} in \\\{server}\{share_name}{filepath}: {found[0]}')
                elif entry.filename not in ['.','..']:
                    self.cred_hunt(connection, share_name, server, remote_file, local_file)

        except:
            print('',end='')

    def download_files(self, connection, share_name, server, remote_path="/", local_path=""):
        try:
            directory_contents = connection.listPath(share_name, remote_path)
            for entry in directory_contents:
                remote_file = os.path.join(remote_path, entry.filename)
                local_file = os.path.join(local_path, entry.filename)
            
                if not entry.isDirectory:
                    for value in self.suspicious_filetypes.values():
                        if re.match(value, entry.filename):
                            pathlib.Path(local_path).mkdir(parents=True, exist_ok=True)
                            filepath = remote_file.replace("/", "\\")
                            with open(local_file, 'wb') as file:
                                connection.retrieveFile(share_name, remote_file, file)
                            print(f'{self.time} Downloaded: \\\{server}\{share_name}{filepath}')
                elif entry.filename not in ['.', '..']:
                    self.download_files(connection, remote_file, local_file, share_name)
        except:
            print('', end='')

def main(argv):
    parser = argparse.ArgumentParser(formatter_class=lambda prog: argparse.HelpFormatter(prog, max_help_position=52))
    parser.add_argument('-u', '--user', help="Set the username", default="", metavar='USER', dest="username")
    parser.add_argument('-p', '--pass', help="Set the password", default="", metavar='PASS', dest="password")
    parser.add_argument('-i', '--ip', help="Use this IP to connect to", default="", dest="ip")
    parser.add_argument('-l', '--list', help="Use this list of IPs to connect to", default="", dest="list")
    parser.add_argument('-d', '--domain', help="Set the domain", default="", dest="domain")
    parser.add_argument('-g', '--get', help="Use this option to download suspicious files", dest="download", action="store_true", default=False)
    args = parser.parse_args()

    if args.list != '':
        with open(args.list, 'r') as file:
            lines = file.readlines()
            for entry in lines:
                entry = entry.strip()
                if args.domain != '':
                    smb = SMBSearch(entry, args.username, args.password, args.domain)
                    smb.scan(args.download)
                else:
                    smb = SMBSearch(entry, args.username, args.password)
                    smb.scan(args.download)
    else:
        if args.domain != '':
            smb = SMBSearch(args.ip, args.username, args.password, args.domain)
            smb.scan(args.download)
        else:
            smb = SMBSearch(args.ip, args.username, args.password)
            smb.scan(args.download)
    
    print(f'{smb.time} Scan completed.')

if __name__ == '__main__':
    main(sys.argv[1:])