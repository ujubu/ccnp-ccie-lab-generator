import random
from tabulate import tabulate
import re
import os
import yaml
import itertools
import xml.etree.ElementTree as ET

# Files
base_dir = os.path.dirname(os.path.abspath(__file__))
files_dir = os.path.join(base_dir, "files")
os.makedirs(files_dir, exist_ok=True)

# Constants
INPUT_FILENAME = "input.txt"
MAC_IP_FILENAME = os.path.join(base_dir, "files", "vagrant-libvirt-vnet.xml")
VAGRANTFILE_NAME = "Vagrantfile"
SSH_CONFIG_FILENAME = "sshconfig"

def read_input_file(filename: str) -> list:
    """
    Reads input data from a given file and returns it as a list of lists.
    Each line is split into separate elements.
    """
    data = []
    try:
        with open(filename, 'r') as file:
            lines = file.readlines()
            for line in lines[1:]:  # Skip header
                row = line.strip().split()
                if len(row) >= 4:  # Ensure there are at least 4 elements per line
                    data.append(row)
        return data
    except FileNotFoundError:
        print(f"Error: File '{filename}' not found.")
        return []
    except Exception as e:
        print(f"Error reading '{filename}': {e}")
        return []

def load_mac_and_management_ips(filename: str) -> dict:
    """
    Loads MAC addresses and management IPs from the specified XML file.
    Returns a dictionary with IP addresses as keys and MAC addresses as values.
    """
    mac_ip_data = {}
    first_entry_skipped = False  # İlk girişi atlamak için bayrak

    try:
        tree = ET.parse(filename)
        root = tree.getroot()

        # Host etiketleri arasında gezin
        for host in root.findall(".//host"):
            mac_address = host.get('mac')
            management_ip = host.get('ip')
            
            if mac_address and management_ip:
                if not first_entry_skipped:
                    first_entry_skipped = True  # İlk giriş alındı, bayrağı güncelle
                    continue  # İlk girişi atla
                
                mac_ip_data[management_ip] = mac_address  # Sözlüğe ekle
    except FileNotFoundError:
        print(f"Error: File '{filename}' not found.")
    except ET.ParseError:
        print(f"Error parsing XML file '{filename}'.")
    except Exception as e:
        print(f"Error reading '{filename}': {e}")

    return mac_ip_data

def generate_ip_address(device_number: int, interface_number: int) -> str:
    """Generates an IP address based on device and interface numbers."""
    return f"127.1.{device_number}.{interface_number}"


def extract_devices(data: list) -> list:
    """Extracts unique device names from the provided data."""
    devices = set(row[0] for row in data if row[0])  # Only non-empty device names
    devices.update(row[2] for row in data if row[2])  # Add remote device names
    return sorted(devices)


def generate_router_config(device: str, port_info: list, mac_address: str, management_ip: str) -> list:
    """Generates configuration output for a given device."""
    output = [f'\nconfig.vm.define "{device}" do |node|']

    # Set box type based on device type
    box_type = "cisco-iosv" if device.startswith('r') else "cisco-iosvl2"
    output.append(f'  node.vm.box = "{box_type}"')
    output.append(f'  node.vm.provider :libvirt do |domain|')
    output.append(f'    domain.management_network_mac = "{mac_address}"')
    output.append(f'  end')

    # Sort and add port information
    port_info.sort(key=lambda x: x[0])  # Sort by port name
    for port, local_ip, remote_ip in port_info:
        output.append(f'  node.vm.network :private_network,')
        output.append(f'      :libvirt__iface_name => "{port}",')
        output.append(f'      :libvirt__tunnel_type => "udp",')
        output.append(f'      :libvirt__tunnel_local_ip => "{local_ip}",')
        output.append(f'      :libvirt__tunnel_local_port => "10001",')
        output.append(f'      :libvirt__tunnel_ip => "{remote_ip}",')
        output.append(f'      :libvirt__tunnel_port => "10001",')
        output.append(f'      auto_config: false')

    output.append('end\n')  # End of device config
    return output

def create_config_file(filename: str, content_lines: list):
    """Creates a configuration file with the given content lines."""
    if os.path.exists(filename):
        overwrite = input(f"{filename} already exists. Overwrite? (y/n): ").lower()
        if overwrite != 'y':
            return

    with open(filename, "w") as file:
        file.write('\n'.join(content_lines) + '\n')
    print(f"{filename} created.")

def read_mac_ip(file_path):
    mac_ip = {}
    
    # XML dosyasını analiz et
    tree = ET.parse(file_path)
    root = tree.getroot()
    
    # İlk IP'yi atlamak için bir bayrak (flag) tanımlayın
    first_ip_skipped = False

    for host in root.findall('.//host'):
        mac = host.get('mac')  # MAC adresini al
        ip = host.get('ip')     # IP adresini al

        if not first_ip_skipped:
            first_ip_skipped = True  # İlk IP'yi atla
            continue

        # Cihaz adını MAC adresinden türet
        device_name = f"r{len(mac_ip) + 1}"  # Örnek: r1, r2, r3...
        mac_ip[device_name] = ip  # Sözlüğe ekle

    return mac_ip

def generate_ip_pairs(router_connections):
    ip_assignments = []  # Output table for IP assignments
    used_ips = set()  # To track used IPs and avoid conflicts

    for connection in router_connections:
        r1, r1_interface, r2, r2_interface = connection

        # Ensure r1 is always the smaller router ID, for consistency
        if r1 > r2:
            r1, r1_interface, r2, r2_interface = r2, r2_interface, r1, r1_interface

        # Find an available /30 IP block that hasn't been used
        ip_base = 1
        while True:
            ip1 = f"10.{r2[1:]}.{r1[1:]}.{ip_base}"
            ip2 = f"10.{r2[1:]}.{r1[1:]}.{ip_base + 1}"

            if (ip1, ip2) not in used_ips and (ip2, ip1) not in used_ips:
                used_ips.add((ip1, ip2))
                break

            ip_base += 4  # Move to the next /30 block (increments by 2)

        # Append the IP assignment for the pair (r1, r2)
        ip_assignments.append({
            "Router 1": r1,
            "Router 1 Interface": r1_interface,
            "Router 2": r2,
            "Router 2 Interface": r2_interface,
            "Router 1 IP": ip1,
            "Router 2 IP": ip2
        })

    return ip_assignments

# Read the router connections from input.txt
router_connections = []
with open("input.txt") as f:
    next(f)  # Skip header
    for line in f:
        fields = line.strip().split()
        router_connections.append((fields[0], fields[1], fields[2], fields[3]))

# Generate IP pairs and print them as a table
ip_table = generate_ip_pairs(router_connections)
print("Router A  Interface  Router B  Interface  Router A IP  Router B IP")
print("------------------------------------------------------------------------")
for entry in ip_table:
    print(f"{entry['Router 1']: <9} {entry['Router 1 Interface']: <10} "
          f"{entry['Router 2']: <9} {entry['Router 2 Interface']: <10} "
          f"{entry['Router 1 IP']: <15} {entry['Router 2 IP']}")

def create_ssh_config(devices: list, mac_ip: dict) -> list:
    ssh_config = []
    iosv_devices = []
    iosvl2_devices = []

    for device in devices:
        device_type = "iosv" if device.startswith('r') else "iosvl2" if device.startswith('sw') else None
        management_ip = mac_ip.get(device, "N/A")  # Burada management IP'yi alıyoruz

        # Debug output
        print(f"Device: {device}, Management IP: {management_ip}")

        if device_type == "iosv":
            iosv_devices.append((device, management_ip))
        elif device_type == "iosvl2":
            iosvl2_devices.append((device, management_ip))

    if iosv_devices:
        ssh_config.append("# Cisco IOSv")
        for device, management_ip in iosv_devices:
            ssh_config.append(f"Host {device}")
            ssh_config.append(f"  HostName {management_ip}\n")

    if iosvl2_devices:
        ssh_config.append("# Cisco IOSvL2")
        for device, management_ip in iosvl2_devices:
            ssh_config.append(f"Host {device}")
            ssh_config.append(f"  HostName {management_ip}\n")

    # Defaults
    ssh_config.append("# Defaults")
    ssh_config.append("Host r? r?? sw? sw??")
    ssh_config.append("  User vagrant")
    ssh_config.append("  UserKnownHostsFile /dev/null")
    ssh_config.append("  StrictHostKeyChecking no")
    ssh_config.append("  PasswordAuthentication no")
    ssh_config.append("  HostkeyAlgorithms +ssh-rsa")
    ssh_config.append("  PubkeyAcceptedAlgorithms +ssh-rsa")
    ssh_config.append("  KexAlgorithms +diffie-hellman-group-exchange-sha1")
    ssh_config.append("  IdentityFile ~/.vagrant.d/insecure_private_key")
    ssh_config.append("  IdentitiesOnly yes")
    ssh_config.append("  LogLevel FATAL\n")

    return ssh_config

def create_inventory(devices: list, mac_ip: dict):
    """Creates an inventory directory and host.yaml, defaults.yaml, and groups.yaml files."""
    inventory_dir = 'inventory'
    os.makedirs(inventory_dir, exist_ok=True)  # Create inventory directory if it doesn't exist

    # Create host.yaml content
    inventory_data = {}
    for device in devices:
        inventory_data[device] = {
            'hostname': mac_ip.get(device, "N/A"),  # Yönetim IP'si
            'groups': ['router'] if device.startswith('r') else ['switch']  # Cihaz grubunu belirle
        }

    # YAML dosyasını oluştur
    yaml_file_path = os.path.join(inventory_dir, 'hosts.yaml')
    with open(yaml_file_path, 'w') as yaml_file:
        yaml_file.write('---\n')  # YAML dosyasının başına '---' ekle
        yaml.dump(inventory_data, yaml_file)

    # defaults.yaml dosyasını oluştur
    defaults_file_path = os.path.join(inventory_dir, 'defaults.yaml')
    defaults_content = """\
---
# Defaults for connection options
connection_options:
  scrapli:
    platform: cisco_iosxe
    username: vagrant
    extras:
      auth_private_key: "~/.vagrant.d/insecure_private_key"
      auth_strict_key: false
      # transport: ssh2
      transport_options:
        open_cmd:
          - "-o"
          - "HostkeyAlgorithms=+ssh-rsa"
          - "-o"
          - "PubkeyAcceptedAlgorithms=+ssh-rsa"
          - "-o"
          - "KexAlgorithms=+diffie-hellman-group-exchange-sha1"
"""
    with open(defaults_file_path, 'w') as defaults_file:
        defaults_file.write(defaults_content)  # Dosyayı doğrudan yaz

    # groups.yaml dosyasını oluştur
    groups_file_path = os.path.join(inventory_dir, 'groups.yaml')
    groups_content = """\
---
# Group definitions
router:
  data:
    type: iosv
    version: 15.9
    lldp: true
switch:
  data:
    type: iosvl2
    version: 15.2
    lldp: true
"""
    with open(groups_file_path, 'w') as groups_file:
        groups_file.write(groups_content)  # Dosyayı doğrudan yaz

    # host_vars dizinini oluştur
    host_vars_dir = os.path.join(inventory_dir, 'host_vars')
    os.makedirs(host_vars_dir, exist_ok=True)

    # Her cihaz için Loopback0, Loopback1 ve Loopback10 ayarlarını oluştur
    for device in devices:
        if device.startswith('r'):
            # IP adreslerini ayarla
            id_num = device[1:]  # 'r1' için '1', 'r2' için '2' vb.
            loopback0_addr = f"1.1.{id_num}.1"
            loopback1_addr = f"11.11.{id_num}.1"
            loopback10_addr = f"172.16.{id_num}.1"

            # Loopback0, Loopback1 ve Loopback10 ayarlarını yaz
            host_vars_content = f"""\
---
# {device} Loopback configurations
interfaces:
  Loopback0:
    ipv4:
      addr: {loopback0_addr}
      mask: 255.255.255.255
  Loopback1:
    ipv4:
      addr: {loopback1_addr}
      mask: 255.255.255.0
  Loopback10:
    ipv4:
      addr: {loopback10_addr}
      mask: 255.255.255.0
"""
            # Dosyayı oluştur
            host_file_path = os.path.join(host_vars_dir, f"{device}.yaml")
            with open(host_file_path, 'w') as host_file:
                host_file.write(host_vars_content)  # Dosyayı yaz

    print(f"Inventory created at {yaml_file_path}")
    print(f"Defaults created at {defaults_file_path}")
    print(f"Groups created at {groups_file_path}")
    print(f"Host vars created in {host_vars_dir}")

    # config.yaml dosyasını oluştur
    config_file_path = 'config.yaml'
    config_content = """\
---
inventory:
  plugin: YAMLInventory
  options:
    host_file: 'inventory/hosts.yaml'
    group_file: 'inventory/groups.yaml'
    defaults_file: 'inventory/defaults.yaml'
runner:
  plugin: threaded
  options:
    num_workers: 20
logging:
  enabled: false
"""
    with open(config_file_path, 'w') as config_file:
        config_file.write(config_content)  # config.yaml içeriğini yaz

    print(f"Config created at {config_file_path}")


# Main execution flow
if __name__ == "__main__":
    data = read_input_file(INPUT_FILENAME)
    devices = extract_devices(data)
    mac_ip_data = load_mac_and_management_ips(MAC_IP_FILENAME)

    # Initialize port configurations
    port_configs = {}
    mac_ip_index = 0  # To track index in mac_ip_data

    # Generate configuration based on input data
    previous_device = None
    for device_row in data:
        device, port, remote_device, remote_port = device_row
        if device:
            previous_device = device
            device_number = int(device[1])
            interface_number = int(port.split('/')[1])
            local_ip = generate_ip_address(device_number, interface_number)

            port_configs.setdefault(device, []).append((port, local_ip, None))

        else:
            # Use the previous device if the current one is empty
            if previous_device:
                device = previous_device
                device_number = int(device[1])
                interface_number = int(port.split('/')[1])
                local_ip = generate_ip_address(device_number, interface_number)

                port_configs.setdefault(device, []).append((port, local_ip, None))

        if remote_device:
            remote_device_number = int(remote_device[1])
            remote_interface_number = int(remote_port.split('/')[1])
            remote_ip = generate_ip_address(remote_device_number, remote_interface_number)

            port_configs[device][-1] = (port, local_ip, remote_ip)

            port_configs.setdefault(remote_device, []).append((remote_port, remote_ip, local_ip))

    # Create Vagrantfile content
    vagrantfile_content = [
        "# -*- mode: ruby -*-",
        "# vi: set ft=ruby :",
        "",
        'Vagrant.configure("2") do |config|',
        "  config.vm.box_check_update = false",
        "  config.vm.provider :libvirt do |lv|",
        '    lv.suspend_mode = "managedsave"',
        '    lv.management_network_keep = true',
        "  end",
    ]

    # Add devices to the Vagrantfile content
    for device in sorted(port_configs.keys(), key=lambda x: int(x[1:])):
        ports = port_configs[device]
        management_ip = list(mac_ip_data.keys())[mac_ip_index]
        mac_address = mac_ip_data[management_ip]
        port_config = generate_router_config(device, ports, mac_address, management_ip)
        vagrantfile_content.extend(port_config)
        mac_ip_index += 1

    vagrantfile_content.append("end")

    # Create Vagrantfile
    create_config_file(VAGRANTFILE_NAME, vagrantfile_content)

    mac_ip = read_mac_ip(MAC_IP_FILENAME)  # MAC-IP sözlüğünü yükle
    ssh_config = create_ssh_config(devices, mac_ip)  # SSH yapılandırmasını oluştur
    SSH_CONFIG_FILENAME = os.path.join(files_dir, "sshconfig")
    create_config_file(SSH_CONFIG_FILENAME, ssh_config)
    create_inventory(devices, mac_ip)  # Envanter dosyasını oluştur

def load_yaml(file_path):
    # Load existing YAML data or create a new structure if the file doesn't exist
    if os.path.exists(file_path):
        with open(file_path, 'r') as file:
            return yaml.safe_load(file) or {}
    return {}

def save_yaml(file_path, data):
    # Save the data to a YAML file
    with open(file_path, 'w') as file:
        yaml.dump(data, file, default_flow_style=False)

def update_router_interfaces(ip_table, inventory_dir):
    for entry in ip_table:
        r1, r1_interface, r1_ip = entry["Router 1"], entry["Router 1 Interface"], entry["Router 1 IP"]
        r2, r2_interface, r2_ip = entry["Router 2"], entry["Router 2 Interface"], entry["Router 2 IP"]
        
        # Define paths for each router's YAML file
        r1_file = os.path.join(inventory_dir, 'host_vars', f"{r1}.yaml")
        r2_file = os.path.join(inventory_dir, 'host_vars', f"{r2}.yaml")

        # Load or initialize YAML data for each router
        r1_data = load_yaml(r1_file)
        r2_data = load_yaml(r2_file)

        # Initialize interfaces if not present
        r1_data.setdefault("interfaces", {})
        r2_data.setdefault("interfaces", {})

        # Format interface names
        formatted_r1_interface = f"GigabitEthernet{r1_interface[1:]}"  # e.g., "g0/1" -> "GigabitEthernet0/1"
        formatted_r2_interface = f"GigabitEthernet{r2_interface[1:]}"  # e.g., "g0/2" -> "GigabitEthernet0/2"

        # Add IP address under each router's corresponding interface
        r1_data["interfaces"][formatted_r1_interface] = {
            "ipv4": {
                "addr": r1_ip,
                "mask": "255.255.255.252"  # Replace with appropriate mask as needed
            }
        }
        r2_data["interfaces"][formatted_r2_interface] = {
            "ipv4": {
                "addr": r2_ip,
                "mask": "255.255.255.252"  # Replace with appropriate mask as needed
            }
        }

        # Save updated YAML files
        save_yaml(r1_file, r1_data)
        save_yaml(r2_file, r2_data)

    print("Router interface IPs updated successfully.")

update_router_interfaces(ip_table, 'inventory')
