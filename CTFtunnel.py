
import os
import subprocess
import sys
import re
from termcolor import colored

# Define colors for output1
HEADER = '\033[95m'
OKBLUE = '\033[94m'
OKCYAN = '\033[96m'
OKGREEN = '\033[92m'
WARNING = '\033[93m'
FAIL = '\033[91m'
ENDC = '\033[0m'
BOLD = '\033[1m'
UNDERLINE = '\033[4m'

def print_colored(text, color):
    print(colored(text, color))

def clear_screen():
    os.system('cls' if os.name == 'nt' else 'clear')

def run_command(command, input_text=None, show_output=True):
    try:
        if input_text:
            # For commands that require input
            process = subprocess.Popen(
                command,
                shell=True,
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True
            )
            stdout, stderr = process.communicate(input=input_text)
            return_code = process.returncode
        else:
            # For commands that don't require input
            result = subprocess.run(
                command,
                shell=True,
                check=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True
            )
            stdout = result.stdout
            stderr = result.stderr
            return_code = 0

        if show_output:
            if stdout:
                print_colored(stdout, "green")
            if stderr:
                print_colored(stderr, "yellow")
        
        return return_code == 0
    except subprocess.CalledProcessError as e:
        if show_output:
            print_colored(f"Error executing command: {e}", "red")
            if e.stderr:
                print_colored(e.stderr, "red")
        return False

def is_openvpn_installed():
    return os.path.exists("/etc/openvpn")

def validate_ip(ip):
    parts = ip.split('.')
    if len(parts) != 4:
        return False
    for item in parts:
        if not item.isdigit():
            return False
        if int(item) < 0 or int(item) > 255:
            return False
    return True


def get_next_available_ip():
    """Find the next available IP in the machine subnet"""
    # Load saved configuration (falls back to defaults if not found)
    config = load_configuration()
    machine_subnet = config['machine_subnet']
    subnet_base = '.'.join(machine_subnet.split('.')[:3]) + '.'
    
    # Get list of used IPs
    used_ips = set()
    if os.path.exists("/etc/openvpn/ctf_ccd"):
        for client in os.listdir("/etc/openvpn/ctf_ccd"):
            if os.path.isfile(f"/etc/openvpn/ctf_ccd/{client}"):
                with open(f"/etc/openvpn/ctf_ccd/{client}", "r") as f:
                    content = f.read()
                    # Match IPs in the format "ifconfig-push 10.0.1.1 10.0.1.2"
                    ip_match = re.search(r'ifconfig-push\s+([0-9\.]+)', content)
                    if ip_match:
                        used_ips.add(ip_match.group(1))
    
    # Find next available IP in subnet
    for i in range(2, 254, 4):  # Skip .0 (network) and use net30 topology (4 IPs per client)
        candidate_ip = f"{subnet_base}{i}"
        if candidate_ip not in used_ips:
            return candidate_ip
    
    # If all IPs are used, return a default
    return f"{subnet_base}100"

def get_default_values():
    """Get default configuration values based on environment"""
    import socket
    default_server_ip = ""
    try:
        # Try to get the primary IP address
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        default_server_ip = s.getsockname()[0]
        s.close()
    except:
        default_server_ip = "10.0.0.1"
    
    return {
        "country": "US",
        "province": "California",
        "city": "San Francisco",
        "org": "My Organization",
        "email": "admin@example.com",
        "ou": "CTF VPN",
        "server_name": socket.gethostname(),
        "server_ip": default_server_ip,
        "player_subnet": "10.0.0.0",
        "machine_subnet": "10.0.1.0",
        "subnet_mask": "255.255.255.0",
        "port": "1194",
        "proto": "udp",
        "dev": "tun0",
    }

def save_configuration(config):
    """Save the user's configuration to a file"""
    config_dir = "/etc/openvpn/manager-config"
    os.makedirs(config_dir, exist_ok=True)
    
    with open(f"{config_dir}/config.txt", "w") as f:
        for key, value in config.items():
            f.write(f"{key}={value}\n")
    
    print_colored("Configuration saved successfully", "green")
    return True

def load_configuration():
    """Load the user's configuration from file"""
    config_dir = "/etc/openvpn/manager-config"
    config_file = f"{config_dir}/config.txt"
    
    # Default values as fallback
    config = get_default_values()
    
    if os.path.exists(config_file):
        with open(config_file, "r") as f:
            for line in f:
                if "=" in line:
                    key, value = line.strip().split("=", 1)
                    config[key] = value
    
    return config

def get_user_input(prompt, default_value, use_defaults):
    """Get user input with option to use default value"""
    if use_defaults:
        return default_value
    return input(f"{prompt} [{default_value}]: ") or default_value

def initialize_pki():
    """Initialize the PKI structure but don't create the CRL yet (that comes after CA)"""
    os.chdir("/etc/openvpn/easy-rsa")
    if run_command("./easyrsa --batch init-pki"):
        return True
    return False

def ensure_client_template_exists():
    """Ensure client template file exists using saved configuration"""
    if not os.path.exists("/etc/openvpn/client-template.txt"):
        # Load saved configuration, falls back to defaults if not found
        config = load_configuration()
        
        client_template = f"""client
dev tun
proto {config['proto']}
remote {config['server_ip']} {config['port']}
resolv-retry infinite
nobind
persist-key
persist-tun
remote-cert-tls server
cipher AES-256-CBC
verb 3
key-direction 1
"""
        os.makedirs("/etc/openvpn", exist_ok=True)
        with open("/etc/openvpn/client-template.txt", "w") as f:
            f.write(client_template)
        return True
    return False

def install_openvpn():
    print_colored("Installing OpenVPN and Easy-RSA...", "blue")
    if run_command("sudo apt update"):
        if run_command("sudo apt install -y openvpn easy-rsa"):
            if run_command("sudo make-cadir /etc/openvpn/easy-rsa"):
                print_colored("OpenVPN and Easy-RSA installed successfully.", "green")
                # Create necessary directories
                os.makedirs("/etc/openvpn/ctf_ccd", exist_ok=True)
                os.makedirs("/etc/openvpn/client-configs", exist_ok=True)
                os.makedirs("/etc/openvpn/client-configs/players", exist_ok=True)
                os.makedirs("/etc/openvpn/client-configs/machines", exist_ok=True)
                os.makedirs("/var/log/openvpn", exist_ok=True)
                
                # Ensure client template exists
                ensure_client_template_exists()
                return True
    return False

def ensure_crl_exists():
    """Ensure the CRL file exists and is properly placed"""
    if not os.path.exists("/etc/openvpn/crl.pem"):
        print_colored("CRL file not found, generating a new one...", "yellow")
        os.chdir("/etc/openvpn/easy-rsa")
        
        # Check if CA has been built already
        if os.path.exists("/etc/openvpn/easy-rsa/pki/ca.crt"):
            # CA exists, we can generate a CRL
            if run_command("./easyrsa --batch gen-crl", show_output=False):
                run_command("cp -f pki/crl.pem /etc/openvpn/ 2>/dev/null || true")
                run_command("chmod 644 /etc/openvpn/crl.pem 2>/dev/null || true")
                print_colored("CRL file generated successfully", "green")
                return True
            else:
                # Create an empty CRL file as fallback
                print_colored("Failed to generate CRL, creating empty file as fallback", "yellow")
                run_command("touch /etc/openvpn/crl.pem")
                run_command("chmod 644 /etc/openvpn/crl.pem")
                return True
        else:
            # CA doesn't exist yet, just create empty file
            print_colored("CA not found, creating empty CRL file as fallback", "yellow")
            run_command("touch /etc/openvpn/crl.pem")
            run_command("chmod 644 /etc/openvpn/crl.pem")
            return True
    return True

def configure_openvpn():
    print_colored("Configuring OpenVPN...", "blue")
    os.chdir("/etc/openvpn/easy-rsa")
    
    # Get default values
    defaults = get_default_values()
    
    # Ask user if they want to use all defaults
    use_defaults = input("Do you want to use all default values? (y/n): ").lower() == 'y'
    if not use_defaults:
        print_colored("\nYou will be prompted for each setting. Press Enter to use the default value.", "cyan")
    
    # Create a new configuration dictionary to store user inputs
    config = {}
    
    # Prompt user for CA and server details with defaults
    print_colored("\nCA and Server Details:", "cyan")
    config["ca_name"] = get_user_input("Enter CA name", "My CA", use_defaults)
    config["country"] = get_user_input("Enter country code", defaults['country'], use_defaults)
    config["province"] = get_user_input("Enter province/state", defaults['province'], use_defaults)
    config["city"] = get_user_input("Enter city", defaults['city'], use_defaults)
    config["org"] = get_user_input("Enter organization", defaults['org'], use_defaults)
    config["email"] = get_user_input("Enter email", defaults['email'], use_defaults)
    config["ou"] = get_user_input("Enter organizational unit", defaults['ou'], use_defaults)
    config["server_name"] = get_user_input("Enter server name", defaults['server_name'], use_defaults)
    
    # Network configuration
    print_colored("\nVPN Network Configuration:", "cyan")
    print_colored("Setting up separate subnets for players and machines", "yellow")
    config["player_subnet"] = get_user_input("Enter player subnet", defaults['player_subnet'], use_defaults)
    config["machine_subnet"] = get_user_input("Enter machine subnet", defaults['machine_subnet'], use_defaults)
    config["subnet_mask"] = get_user_input("Enter subnet mask", defaults['subnet_mask'], use_defaults)
    
    # OpenVPN connection settings
    print_colored("\nOpenVPN Connection Settings:", "cyan")
    config["port"] = get_user_input("Enter OpenVPN port", defaults['port'], use_defaults)
    config["proto"] = get_user_input("Enter protocol (udp/tcp)", defaults['proto'], use_defaults)
    config["dev"] = get_user_input("Enter TUN device", defaults['dev'], use_defaults)
    
    # Get server IP - simply use the server_name
    config["server_ip"] = config["server_name"]

    # Save the configuration for future use
    save_configuration(config)
    
    # Confirm route all traffic through VPN
    route_all_traffic = False
    if not use_defaults:
        route_all_traffic = input("Route all internet traffic through VPN? (not recommended for CTF) [y/N]: ").lower() == 'y'
    
    # Create vars file with user-provided details
    with open("vars", "w") as f:
        f.write(f"set_var EASYRSA_REQ_COUNTRY\t'{config['country']}'\n")
        f.write(f"set_var EASYRSA_REQ_PROVINCE\t'{config['province']}'\n")
        f.write(f"set_var EASYRSA_REQ_CITY\t'{config['city']}'\n")
        f.write(f"set_var EASYRSA_REQ_ORG\t'{config['org']}'\n")
        f.write(f"set_var EASYRSA_REQ_EMAIL\t'{config['email']}'\n")
        f.write(f"set_var EASYRSA_REQ_OU\t'{config['ou']}'\n")
        f.write(f"set_var EASYRSA_REQ_CN\t'{config['server_name']}'\n")
        f.write(f"set_var EASYRSA_BATCH\t'yes'\n")  # Add batch mode to avoid prompts
    
    # Initialize the PKI
    if initialize_pki():
        # Build CA with --batch to avoid interactive prompts
        if run_command("./easyrsa --batch build-ca nopass"):
            # NOW we can generate the CRL after the CA exists
            run_command("./easyrsa --batch gen-crl")
            run_command("cp -f pki/crl.pem /etc/openvpn/ 2>/dev/null || true")
            run_command("chmod 644 /etc/openvpn/crl.pem 2>/dev/null || true")
            
            # Generate server certificate and key non-interactively
            if run_command("./easyrsa --batch gen-req server nopass"):
                # Sign the server certificate non-interactively
                if run_command("./easyrsa --batch sign-req server server"):
                    # Generate Diffie-Hellman parameters
                    if run_command("./easyrsa --batch gen-dh"):
                        # Ensure CRL exists
                        ensure_crl_exists()
                        
                        # Generate TLS Auth key - handling different OpenVPN versions
                        if run_command("openvpn --genkey --secret /etc/openvpn/ta.key") or run_command("openvpn --genkey secret /etc/openvpn/ta.key") or run_command("openssl genrsa -out /etc/openvpn/ta.key 2048"):
                            # Create a custom server.conf file based on the working configuration
                            player_net = config["player_subnet"].split('.')
                            machine_net = config["machine_subnet"].split('.')
                            
                            server_config = f"""port {config["port"]}
proto {config["proto"]}
dev {config["dev"]}

ca /etc/openvpn/easy-rsa/pki/ca.crt
cert /etc/openvpn/easy-rsa/pki/issued/server.crt
key /etc/openvpn/easy-rsa/pki/private/server.key
dh /etc/openvpn/easy-rsa/pki/dh.pem

# Player subnet (primary VPN subnet)
server {player_net[0]}.{player_net[1]}.{player_net[2]}.0 {config["subnet_mask"]}
ifconfig-pool-persist ipp.txt

# Client-specific configurations directory
client-config-dir /etc/openvpn/ctf_ccd

# Route for machines subnet
route {machine_net[0]}.{machine_net[1]}.{machine_net[2]}.0 {config["subnet_mask"]}

# Push routes to clients
push "route {machine_net[0]}.{machine_net[1]}.{machine_net[2]}.0 {config["subnet_mask"]}"

# Allow client-to-client communication
client-to-client

keepalive 10 120
tls-auth /etc/openvpn/ta.key 0
cipher AES-256-CBC

persist-key
persist-tun

status /var/log/openvpn/openvpn-status.log
log-append /var/log/openvpn/openvpn.log
verb 4

crl-verify /etc/openvpn/crl.pem
explicit-exit-notify 1
topology net30
"""
                            
                            # Handle redirect-gateway based on user choice
                            if route_all_traffic:
                                server_config += "push \"redirect-gateway def1 bypass-dhcp\"\n"
                            
                            # Write the server configuration file
                            with open("/etc/openvpn/server.conf", "w") as f:
                                f.write(server_config)
                            
                            # Enable IP forwarding
                            with open("/etc/sysctl.conf", "r") as f:
                                sysctl_conf = f.read()
                            
                            if "#net.ipv4.ip_forward=1" in sysctl_conf:
                                sysctl_conf = sysctl_conf.replace("#net.ipv4.ip_forward=1", "net.ipv4.ip_forward=1")
                                with open("/etc/sysctl.conf", "w") as f:
                                    f.write(sysctl_conf)
                            elif "net.ipv4.ip_forward=1" not in sysctl_conf:
                                with open("/etc/sysctl.conf", "a") as f:
                                    f.write("\n# Added by OpenVPN Manager\nnet.ipv4.ip_forward=1\n")
                            
                            run_command("sysctl -p")
                            
                            # Update client template with the user-configured values
                            client_template = f"""client
dev tun
proto {config["proto"]}
remote {config["server_ip"]} {config["port"]}
resolv-retry infinite
nobind
persist-key
persist-tun
remote-cert-tls server
cipher AES-256-CBC
verb 3
key-direction 1
"""
                            with open("/etc/openvpn/client-template.txt", "w") as f:
                                f.write(client_template)
                            
                            # Enable and start OpenVPN
                            if run_command("systemctl enable openvpn@server"):
                                if run_command("systemctl restart openvpn@server"):
                                    print_colored("OpenVPN configured successfully!", "green")
                                    print_colored(f"Player subnet: {config['player_subnet']}/24", "cyan")
                                    print_colored(f"Machine subnet: {config['machine_subnet']}/24", "cyan")
                                    print_colored("Client-to-client communication enabled", "cyan")
                                    return True
    return False

def add_client(client_name, output_dir=None, is_machine=False):
    if not client_name:
        print_colored("Error: Client name cannot be empty", "red")
        return False
    
    # Ensure client template exists
    ensure_client_template_exists()
    
    print_colored(f"Adding {'machine' if is_machine else 'player'}: {client_name}", "blue")
    os.chdir("/etc/openvpn/easy-rsa")
    
    # Temporarily modify the vars file to set the correct CN
    vars_path = "/etc/openvpn/easy-rsa/vars"
    vars_backup = None
    
    if os.path.exists(vars_path):
        # Create backup of the vars file
        with open(vars_path, "r") as f:
            vars_backup = f.read()
        
        # Add or replace the CN setting
        import re
        if re.search(r'set_var\s+EASYRSA_REQ_CN', vars_backup):
            # Replace existing CN setting
            vars_modified = re.sub(
                r'set_var\s+EASYRSA_REQ_CN.*',
                f"set_var EASYRSA_REQ_CN\t'{client_name}'",
                vars_backup
            )
        else:
            # Add CN setting if it doesn't exist
            vars_modified = vars_backup + f"\nset_var EASYRSA_REQ_CN\t'{client_name}'\n"
        
        # Write the modified vars file
        with open(vars_path, "w") as f:
            f.write(vars_modified)
    
    # Generate client keys non-interactively with the correct CN
    success = False
    try:
        # Generate request and key
        if run_command(f"./easyrsa --batch gen-req {client_name} nopass"):
            # Sign client certificate non-interactively
            if run_command(f"./easyrsa --batch sign-req client {client_name}"):
                print_colored(f"Client {client_name} certificates generated successfully", "green")
                
                # Create client configuration file
                if output_dir is None:
                    if is_machine:
                        output_dir = f"/etc/openvpn/client-configs/machines"
                    else:
                        output_dir = f"/etc/openvpn/client-configs/players"
                
                client_config_file = f"{output_dir}/{client_name}.ovpn"
                
                # Create directory if it doesn't exist
                os.makedirs(output_dir, exist_ok=True)
                
                # Copy client template
                with open("/etc/openvpn/client-template.txt", "r") as f:
                    client_config = f.read()
                
                # Append certificates and keys
                with open("/etc/openvpn/easy-rsa/pki/ca.crt", "r") as f:
                    ca_cert = f.read()
                
                with open(f"/etc/openvpn/easy-rsa/pki/issued/{client_name}.crt", "r") as f:
                    # Extract the certificate part only
                    cert_text = f.read()
                    cert_begin = cert_text.find("-----BEGIN CERTIFICATE-----")
                    client_cert = cert_text[cert_begin:]
                
                with open(f"/etc/openvpn/easy-rsa/pki/private/{client_name}.key", "r") as f:
                    client_key = f.read()
                
                with open("/etc/openvpn/ta.key", "r") as f:
                    ta_key = f.read()
                
                # Write the complete client config
                with open(client_config_file, "w") as f:
                    f.write(client_config)
                    f.write("<ca>\n")
                    f.write(ca_cert)
                    f.write("</ca>\n")
                    f.write("<cert>\n")
                    f.write(client_cert)
                    f.write("</cert>\n")
                    f.write("<key>\n")
                    f.write(client_key)
                    f.write("</key>\n")
                    f.write("<tls-auth>\n")
                    f.write(ta_key)
                    f.write("</tls-auth>\n")
                
                print_colored(f"Client configuration created at: {client_config_file}", "green")
                success = True
    finally:
        # Restore the original vars file
        if vars_backup is not None:
            with open(vars_path, "w") as f:
                f.write(vars_backup)
    
    return success

def get_next_available_ip():
    """Find the next available IP in the machine subnet"""
    defaults = get_default_values()
    machine_subnet = defaults['machine_subnet']
    subnet_base = '.'.join(machine_subnet.split('.')[:3]) + '.'
    
    # Get list of used IPs
    used_ips = set()
    if os.path.exists("/etc/openvpn/ctf_ccd"):
        for client in os.listdir("/etc/openvpn/ctf_ccd"):
            if os.path.isfile(f"/etc/openvpn/ctf_ccd/{client}"):
                with open(f"/etc/openvpn/ctf_ccd/{client}", "r") as f:
                    content = f.read()
                    # Match IPs in the format "ifconfig-push 10.0.1.1 10.0.1.2"
                    ip_match = re.search(r'ifconfig-push\s+([0-9\.]+)', content)
                    if ip_match:
                        used_ips.add(ip_match.group(1))
    
    # Find next available IP in subnet
    for i in range(2, 254, 4):  # Skip .0 (network) and use net30 topology (4 IPs per client)
        candidate_ip = f"{subnet_base}{i}"
        if candidate_ip not in used_ips:
            return candidate_ip
    
    # If all IPs are used, return a default
    return f"{subnet_base}100"

def get_paired_ip(ip):
    """Get the paired IP for net30 topology (IP+1)"""
    parts = ip.split('.')
    last_octet = int(parts[3])
    paired_octet = last_octet + 1
    return f"{parts[0]}.{parts[1]}.{parts[2]}.{paired_octet}"

def add_ctf_machine(machine_name=None, ip_address=None):
    if not machine_name:
        machine_name = input("Enter CTF machine name: ")
        if not machine_name:
            print_colored("Error: Machine name cannot be empty", "red")
            return False
    
    # Suggest next available IP if not provided
    if not ip_address:
        suggested_ip = get_next_available_ip()
        ip_address = input(f"Enter IP address for the CTF machine [{suggested_ip}]: ") or suggested_ip
    
    if not ip_address or not validate_ip(ip_address):
        print_colored("Error: Invalid IP address format", "red")
        return False
    
    print_colored(f"Adding CTF machine: {machine_name} with IP: {ip_address}", "blue")
    
    # Create client config directory if it doesn't exist
    if not os.path.exists("/etc/openvpn/ctf_ccd"):
        os.makedirs("/etc/openvpn/ctf_ccd", exist_ok=True)
        
        # Ensure client-config-dir is properly set in server.conf
        if os.path.exists("/etc/openvpn/server.conf"):
            with open("/etc/openvpn/server.conf", "r") as f:
                config = f.read()
            
            if "client-config-dir" not in config:
                with open("/etc/openvpn/server.conf", "a") as f:
                    f.write("\n# Client-specific configurations directory\nclient-config-dir /etc/openvpn/ctf_ccd\n")
                
                # Restart OpenVPN to apply changes
                run_command("systemctl restart openvpn@server")
    
    # Generate client certificates as a machine
    if add_client(machine_name, output_dir="/etc/openvpn/client-configs/machines", is_machine=True):
        # Create static IP configuration using net30 topology
        paired_ip = get_paired_ip(ip_address)
        
        # Load saved configuration
        config = load_configuration()
        
        with open(f"/etc/openvpn/ctf_ccd/{machine_name}", "w") as f:
            # Get player subnet from saved configuration
            machine_net = config['machine_subnet'].split('.')
            
            # Define the client's static IP using net30 topology
            f.write(f"# Assign static IP from machine subnet\n")
            f.write(f"ifconfig-push {ip_address} {paired_ip}\n\n")
            
            # Add route back to player subnet
            f.write(f"# This machine is responsible for the machine subnet\n")
            f.write(f"iroute {machine_net[0]}.{machine_net[1]}.{machine_net[2]}.0 {config['subnet_mask']}\n")
        
        print_colored(f"CTF machine {machine_name} added successfully with static IP {ip_address}", "green")
        print_colored(f"Configuration file created at: /etc/openvpn/ctf_ccd/{machine_name}", "cyan")
        return True
    return False

def get_available_clients():
    """Get list of available clients"""
    clients = []
    if os.path.exists("/etc/openvpn/easy-rsa/pki/issued"):
        clients = [f.replace(".crt", "") for f in os.listdir("/etc/openvpn/easy-rsa/pki/issued") if f.endswith(".crt")]
        if "server" in clients:
            clients.remove("server")
    return clients

def delete_client(client_name=None):
    available_clients = get_available_clients()
    
    if not available_clients:
        print_colored("No clients found to delete", "yellow")
        return False
    
    # If client_name not provided, let user choose from list
    if not client_name:
        print_colored("\nAvailable clients:", "cyan")
        for i, client in enumerate(available_clients):
            # Check if client is a machine or player
            is_machine = os.path.exists(f"/etc/openvpn/ctf_ccd/{client}")
            client_type = "machine" if is_machine else "player"
            print_colored(f"{i+1}. {client} ({client_type})", "green")
        
        choice = input("\nEnter number to delete or 'q' to cancel: ")
        if choice.lower() == 'q':
            return False
        
        try:
            index = int(choice) - 1
            if 0 <= index < len(available_clients):
                client_name = available_clients[index]
            else:
                print_colored("Invalid selection", "red")
                return False
        except ValueError:
            print_colored("Invalid input", "red")
            return False
    
    # Check if client exists
    if client_name not in available_clients:
        print_colored(f"Client {client_name} not found", "red")
        return False
    
    # Ask for confirmation
    confirmation = input(f"Are you sure you want to delete {client_name}? (y/n): ")
    if confirmation.lower() != 'y':
        print_colored("Deletion cancelled", "yellow")
        return False
        
    print_colored(f"Deleting client: {client_name}", "blue")
    os.chdir("/etc/openvpn/easy-rsa")
    
    # Revoke client certificate non-interactively
    if run_command(f"./easyrsa --batch revoke {client_name}"):
        # Generate new CRL
        if run_command("./easyrsa --batch gen-crl"):
            # Copy CRL to OpenVPN directory with proper permissions
            run_command("cp -f /etc/openvpn/easy-rsa/pki/crl.pem /etc/openvpn/")
            run_command("chmod 644 /etc/openvpn/crl.pem")
            
            # Remove client specific files
            run_command(f"rm -f /etc/openvpn/ctf_ccd/{client_name}")
            run_command(f"rm -f /etc/openvpn/client-configs/players/{client_name}.ovpn")
            run_command(f"rm -f /etc/openvpn/client-configs/machines/{client_name}.ovpn")
            
            print_colored(f"Client {client_name} deleted successfully", "green")
            
            # Update CRL configuration in server.conf if needed
            with open("/etc/openvpn/server.conf", "r") as f:
                config = f.read()
            
            if "crl-verify" not in config:
                with open("/etc/openvpn/server.conf", "a") as f:
                    f.write("\n# Certificate Revocation List\ncrl-verify /etc/openvpn/crl.pem\n")
            
            # Verify CRL exists before restarting
            ensure_crl_exists()
            
            # Restart OpenVPN to apply changes
            run_command("systemctl restart openvpn@server")
            
            return True
        else:
            print_colored("Failed to generate CRL. Creating an empty one as fallback...", "yellow")
            # Create empty CRL as fallback
            run_command("touch /etc/openvpn/crl.pem")
            run_command("chmod 644 /etc/openvpn/crl.pem")
            # Still try to restart service
            run_command("systemctl restart openvpn@server")
            return True
    return False

def regenerate_crl():
    """Regenerate the CRL file"""
    print_colored("Regenerating CRL file...", "blue")
    os.chdir("/etc/openvpn/easy-rsa")
    
    if os.path.exists("/etc/openvpn/easy-rsa/pki"):
        if run_command("./easyrsa --batch gen-crl"):
            run_command("cp -f pki/crl.pem /etc/openvpn/")
            run_command("chmod 644 /etc/openvpn/crl.pem")
            print_colored("CRL file regenerated successfully", "green")
            return True
        else:
            print_colored("Failed to regenerate CRL file", "red")
            # Create empty CRL as fallback
            run_command("touch /etc/openvpn/crl.pem")
            run_command("chmod 644 /etc/openvpn/crl.pem")
            print_colored("Created empty CRL file as fallback", "yellow")
            return False
    else:
        print_colored("PKI structure not found", "red")
        # Create empty CRL as fallback
        run_command("touch /etc/openvpn/crl.pem")
        run_command("chmod 644 /etc/openvpn/crl.pem")
        print_colored("Created empty CRL file as fallback", "yellow")
        return False

def restart_openvpn():
    """Restart the OpenVPN server"""
    print_colored("Restarting OpenVPN server...", "blue")
    
    # First ensure CRL exists to prevent startup failure
    ensure_crl_exists()
    
    # Try to restart the service
    if run_command("systemctl restart openvpn@server"):
        print_colored("OpenVPN server restarted successfully", "green")
        return True
    else:
        # If restart fails, check for specific errors
        print_colored("Failed to restart OpenVPN server, checking for issues...", "yellow")
        
        # Check for common issues
        result = subprocess.run(
            "systemctl status openvpn@server | grep -i 'error\\|fail'",
            shell=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True
        )
        
        if "crl-verify" in result.stdout:
            print_colored("CRL verification issue detected, regenerating CRL...", "yellow")
            regenerate_crl()
            # Try restarting again
            if run_command("systemctl restart openvpn@server"):
                print_colored("OpenVPN server restarted successfully after CRL regeneration", "green")
                return True
        
        print_colored("Failed to restart OpenVPN server", "red")
        print_colored("Check logs with: journalctl -xe", "yellow")
        return False

def stop_openvpn():
    """Stop the OpenVPN server"""
    print_colored("Stopping OpenVPN server...", "blue")
    confirmation = input("This will disconnect all clients. Are you sure? (y/n): ")
    if confirmation.lower() != 'y':
        print_colored("Operation cancelled", "yellow")
        return False
        
    if run_command("systemctl stop openvpn@server"):
        print_colored("OpenVPN server stopped successfully", "green")
        print_colored("All VPN connections have been terminated", "yellow")
        print_colored("To start the server again, use the 'Restart OpenVPN' option", "cyan")
        return True
    else:
        print_colored("Failed to stop OpenVPN server", "red")
        return False

def delete_openvpn():
    print_colored("Deleting OpenVPN and configurations...", "blue")
    
    # Double confirmation for such a destructive action
    print_colored("\nWARNING: This will remove OpenVPN, all client configurations, certificates and keys.", "red")
    print_colored("All VPN connections will be terminated and cannot be recovered without reconfiguration.", "red")
    
    confirmation = input("\nType 'DELETE' to confirm deletion: ")
    if confirmation != 'DELETE':
        print_colored("Operation cancelled", "yellow")
        return False
    
    confirmation2 = input("Are you absolutely sure? This cannot be undone. (yes/no): ")
    if confirmation2.lower() != 'yes':
        print_colored("Operation cancelled", "yellow")
        return False
        
    if run_command("systemctl stop openvpn@server"):
        if run_command("systemctl disable openvpn@server"):
            if run_command("apt purge -y openvpn easy-rsa"):
                if run_command("rm -rf /etc/openvpn"):
                    # Reset IP forwarding
                    with open("/etc/sysctl.conf", "r") as f:
                        sysctl_conf = f.read()
                    
                    if "net.ipv4.ip_forward=1" in sysctl_conf:
                        sysctl_conf = sysctl_conf.replace("net.ipv4.ip_forward=1", "#net.ipv4.ip_forward=1")
                        with open("/etc/sysctl.conf", "w") as f:
                            f.write(sysctl_conf)
                    
                    run_command("sysctl -p")
                    
                    print_colored("OpenVPN and configurations deleted successfully", "green")
                    return True
    return False

def print_current_config():
    print_colored("\nCurrent OpenVPN Configuration:", "blue")
    
    if not is_openvpn_installed():
        print_colored("OpenVPN is not installed", "red")
        return
    
    # Server status
    print_colored("\nServer Status:", "cyan")
    run_command("systemctl status openvpn@server | grep Active")
    
    # Network configuration
    print_colored("\nNetwork Configuration:", "cyan")
    run_command("ip addr show tun0 2>/dev/null || echo 'TUN interface not active'")
    
    # Server config
    print_colored("\nServer Configuration:", "cyan")
    
    # Get default network configuration values as fallbacks
    defaults = get_default_values()
    
    if os.path.exists("/etc/openvpn/server.conf"):
        # Extract key configuration settings
        with open("/etc/openvpn/server.conf", "r") as f:
            config = f.read()
            
        # Find the server directive (player subnet)
        server_match = re.search(r'server\s+([0-9\.]+)\s+([0-9\.]+)', config)
        if server_match:
            player_subnet = server_match.group(1)
            print_colored(f"Player subnet: {player_subnet}/24", "green")
        else:
            print_colored("Player subnet: Not found in configuration", "yellow")
        
        # Find all route directives for potential machine subnets
        route_matches = re.findall(r'route\s+([0-9\.]+)\s+([0-9\.]+)', config)
        
        if route_matches:
            print_colored("Additional routed networks:", "green")
            for match in route_matches:
                network = match[0]
                mask = match[1]
                # Convert mask to CIDR notation
                cidr = sum(bin(int(x)).count('1') for x in mask.split('.'))
                print_colored(f"- {network}/{cidr}", "green")
        else:
            print_colored("No additional routed networks found", "yellow")
            
        # Check if client-to-client is enabled
        if "client-to-client" in config and not ";client-to-client" in config:
            print_colored("Client-to-client communication: Enabled", "green")
        else:
            print_colored("Client-to-client communication: Disabled", "yellow")
            
        # Check if CCD is properly configured
        if "client-config-dir /etc/openvpn/ctf_ccd" in config:
            print_colored("Client Config Directory: Configured", "green")
        else:
            ccd_match = re.search(r'client-config-dir\s+(\S+)', config)
            if ccd_match:
                print_colored(f"Client Config Directory: {ccd_match.group(1)}", "yellow")
            else:
                print_colored("Client Config Directory: Not configured", "red")
    else:
        print_colored("Server configuration not found", "red")
    
    # Players
    print_colored("\nConfigured Players:", "cyan")
    if os.path.exists("/etc/openvpn/client-configs/players"):
        players = [f.replace(".ovpn", "") for f in os.listdir("/etc/openvpn/client-configs/players") if f.endswith(".ovpn")]
        if players:
            for player in players:
                print_colored(f"- {player}", "green")
        else:
            print_colored("No players configured", "yellow")
    else:
        print_colored("Player configurations directory not found", "red")
    
    # CTF Machines
    print_colored("\nCTF Machines (Static IPs):", "cyan")
    if os.path.exists("/etc/openvpn/ctf_ccd"):
        ctf_machines = os.listdir("/etc/openvpn/ctf_ccd")
        if ctf_machines:
            for machine in ctf_machines:
                if os.path.isfile(f"/etc/openvpn/ctf_ccd/{machine}"):
                    with open(f"/etc/openvpn/ctf_ccd/{machine}", "r") as f:
                        config = f.read()
                    # Updated regex to match net30 topology format (10.0.1.1 10.0.1.2)
                    ip_match = re.search(r'ifconfig-push\s+([0-9\.]+)\s+([0-9\.]+)', config)
                    ip = ip_match.group(1) if ip_match else "Unknown"
                    print_colored(f"- {machine} (IP: {ip})", "green")
        else:
            print_colored("No CTF machines configured", "yellow")
    else:
        print_colored("CTF configuration directory not found", "red")
    
    input("\nPress Enter to continue...")

def export_client_configs():
    print_colored("\nExport Client Configurations", "blue")
    
    if not os.path.exists("/etc/openvpn/client-configs"):
        print_colored("No client configurations found to export", "red")
        return False
    
    export_dir = input("Enter export directory (default: /root/openvpn-clients): ") or "/root/openvpn-clients"
    os.makedirs(export_dir, exist_ok=True)
    
    # Copy player configs
    players_dir = os.path.join(export_dir, "players")
    os.makedirs(players_dir, exist_ok=True)
    run_command(f"cp -R /etc/openvpn/client-configs/players/* {players_dir}/ 2>/dev/null || true")
    
    # Copy machine configs
    machines_dir = os.path.join(export_dir, "machines")
    os.makedirs(machines_dir, exist_ok=True)
    run_command(f"cp -R /etc/openvpn/client-configs/machines/* {machines_dir}/ 2>/dev/null || true")
    
    print_colored(f"Client configurations exported to {export_dir}", "green")
    print_colored(f"Players: {players_dir}", "cyan")
    print_colored(f"Machines: {machines_dir}", "cyan")
    return True

def import_client_configs():
    print_colored("\nImport Client Configurations", "blue")
    
    import_dir = input("Enter import directory: ")
    if not os.path.exists(import_dir):
        print_colored(f"Directory {import_dir} not found", "red")
        return False
    
    # Create target directories if they don't exist
    os.makedirs("/etc/openvpn/client-configs/players", exist_ok=True)
    os.makedirs("/etc/openvpn/client-configs/machines", exist_ok=True)
    
    # Import players
    players_dir = os.path.join(import_dir, "players")
    if os.path.exists(players_dir):
        run_command(f"cp -R {players_dir}/* /etc/openvpn/client-configs/players/ 2>/dev/null || true")
        print_colored("Player configurations imported", "green")
    
    # Import machines
    machines_dir = os.path.join(import_dir, "machines")
    if os.path.exists(machines_dir):
        run_command(f"cp -R {machines_dir}/* /etc/openvpn/client-configs/machines/ 2>/dev/null || true")
        print_colored("Machine configurations imported", "green")
    
    # If no subdirectories, try to import from the main directory
    if not os.path.exists(players_dir) and not os.path.exists(machines_dir):
        run_command(f"cp -R {import_dir}/*.ovpn /etc/openvpn/client-configs/players/ 2>/dev/null || true")
        print_colored("Configurations imported as players", "yellow")
    
    print_colored("Client configurations imported successfully", "green")
    return True

def check_existing_ips():
    """Check for duplicate IPs in CTF machines"""
    print_colored("\nChecking for duplicate IPs in CTF machines...", "blue")
    
    if not os.path.exists("/etc/openvpn/ctf_ccd"):
        print_colored("No CTF machines found", "yellow")
        return
    
    # Collect all IPs
    ip_map = {}
    for machine in os.listdir("/etc/openvpn/ctf_ccd"):
        if os.path.isfile(f"/etc/openvpn/ctf_ccd/{machine}"):
            with open(f"/etc/openvpn/ctf_ccd/{machine}", "r") as f:
                config = f.read()
            # Updated regex to match net30 topology format (10.0.1.1 10.0.1.2)
            ip_match = re.search(r'ifconfig-push\s+([0-9\.]+)', config)
            if ip_match:
                ip = ip_match.group(1)
                if ip in ip_map:
                    ip_map[ip].append(machine)
                else:
                    ip_map[ip] = [machine]
    
    # Check for duplicates
    duplicates_found = False
    for ip, machines in ip_map.items():
        if len(machines) > 1:
            duplicates_found = True
            print_colored(f"IP {ip} is used by multiple machines:", "red")
            for machine in machines:
                print_colored(f"  - {machine}", "red")
    
    if not duplicates_found:
        print_colored("No duplicate IPs found", "green")
    
    input("\nPress Enter to continue...")

def main_menu():
    while True:
        clear_screen()
        print_colored("\n" + "="*60, "cyan")
        print_colored("           CTF OpenVPN Management Tool", "cyan")
        print_colored("="*60, "cyan")
        
        # Always show installation/configuration option
        if not is_openvpn_installed():
            print_colored("1. Install and Configure OpenVPN", "green")
        else:
            print_colored("1. Reconfigure OpenVPN", "yellow")
        
        # Only show client management options if OpenVPN is installed
        if is_openvpn_installed():
            print_colored("2. Add Client (Player)", "green")
            print_colored("3. Add CTF Machine (Static IP)", "green")
            print_colored("4. Delete Client/Machine", "red")
            print_colored("5. Export Client Configurations", "blue")
            print_colored("6. Import Client Configurations", "blue")
            print_colored("7. Print Status and Configuration", "blue")
            print_colored("8. Check for Duplicate IPs", "blue")
            print_colored("9. Regenerate CRL", "blue")
            print_colored("10. Restart OpenVPN", "green")
            print_colored("11. Stop OpenVPN", "yellow")
            print_colored("12. Delete OpenVPN and Configs", "red")
        
        print_colored("q. Exit", "magenta")
        print_colored("="*60, "cyan")
        
        choice = input("Enter your choice: ")

        if choice == "1":
            if not is_openvpn_installed():
                if install_openvpn():
                    if not configure_openvpn():
                        input("Press Enter to continue...")
            else:
                if not configure_openvpn():
                    input("Press Enter to continue...")
        elif choice == "2" and is_openvpn_installed():
            client_name = input("Enter client name: ")
            if not add_client(client_name):
                input("Press Enter to continue...")
            else:
                input("Client added successfully. Press Enter to continue...")
        elif choice == "3" and is_openvpn_installed():
            if not add_ctf_machine():
                input("Press Enter to continue...")
            else:
                input("CTF machine added successfully. Press Enter to continue...")
        elif choice == "4" and is_openvpn_installed():
            if not delete_client():
                input("Press Enter to continue...")
            else:
                input("Client/machine deleted successfully. Press Enter to continue...")
        elif choice == "5" and is_openvpn_installed():
            if not export_client_configs():
                input("Press Enter to continue...")
            else:
                input("Press Enter to continue...")
        elif choice == "6" and is_openvpn_installed():
            if not import_client_configs():
                input("Press Enter to continue...")
            else:
                input("Press Enter to continue...")
        elif choice == "7" and is_openvpn_installed():
            print_current_config()
        elif choice == "8" and is_openvpn_installed():
            check_existing_ips()
        elif choice == "9" and is_openvpn_installed():
            if not regenerate_crl():
                input("Press Enter to continue...")
            else:
                input("CRL regenerated successfully. Press Enter to continue...")
        elif choice == "10" and is_openvpn_installed():
            if not restart_openvpn():
                input("Press Enter to continue...")
            else:
                input("OpenVPN restarted successfully. Press Enter to continue...")
        elif choice == "11" and is_openvpn_installed():
            if not stop_openvpn():
                input("Press Enter to continue...")
            else:
                input("OpenVPN stopped successfully. Press Enter to continue...")
        elif choice == "12" and is_openvpn_installed():
            if not delete_openvpn():
                input("Press Enter to continue...")
            else:
                input("OpenVPN deleted successfully. Press Enter to continue...")
        elif choice == "q":
            print_colored("Exiting...", "yellow")
            break
        else:
            if choice in ["2", "3", "4", "5", "6", "7", "8", "9", "10", "11", "12"] and not is_openvpn_installed():
                print_colored("OpenVPN is not installed. Please install it first (Option 1).", "red")
            else:
                print_colored("Invalid choice. Please try again.", "red")
            input("Press Enter to continue...")

if __name__ == "__main__":
    # Check if running as root
    if os.geteuid() != 0:
        print_colored("This script must be run as root!", "red")
        sys.exit(1)
    
    main_menu()
