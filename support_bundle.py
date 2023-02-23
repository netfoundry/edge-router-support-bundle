#!/usr/bin/env python
"""
NetFoundry support bundle script
This script gathers information about a deployed Edge Router
Creates a bundle & uploads the file to an S3 bucket.
"""

import re
import platform
from datetime import datetime
import time
import argparse
import sys
import os
import socket
import shutil
import subprocess
import tempfile
import zipfile
import logging
import json
import yaml
import boto3
import botocore
import psutil


def bytes2human(number_of_bytes):
    """
    Convert bytes to human readable
    """
    symbols = ('K', 'M', 'G', 'T', 'P', 'E', 'Z', 'Y')
    prefix = {}
    for i, symbol in enumerate(symbols):
        prefix[symbol] = 1 << (i + 1) * 10
    for symbol in reversed(symbols):
        if number_of_bytes >= prefix[symbol]:
            value = float(number_of_bytes) / prefix[symbol]
            return '%.1f%s' % (value, symbol)
    return "%sB" % number_of_bytes

def create_info_file(tmp_dir, email_address):
    """
    Creates an info file with information that can be used to identify the local machine
    """
    info_items = {"email_address": email_address}
    info_items["network_version"] = "7"
    node_type_map = {
        "/opt/netfoundry/ziti/ziti-controller/ziti-controller": "NC",
        "/opt/netfoundry/ziti/ziti-router/config.yml": "ER",
    }

    logging.debug("Attempting to identify system...")

    for file_path, node_type in node_type_map.items():
        if os.path.exists(file_path):
            info_items["node_type"] = node_type
            logging.debug("Node Type: %s", node_type)
            break

    if "node_type" not in info_items:
        logging.warning("Failed to identify node type")

    try:
        host_id = extract_minion_id('/etc/salt/minion.d/nf-minion.conf')
    except FileNotFoundError:
        host_id = None
        logging.debug("Minion file not found")

    if not host_id:
        try:
            host_id = extract_minion_id('/etc/salt/minion.d/nf_minion.conf')
        except FileNotFoundError:
            logging.debug("Minion file not found")

    if host_id:
        info_items["host_id"] = host_id

    try:
        controller_ip = extract_tunnel_controller_ip('/opt/netfoundry/ziti/ziti-tunnel/config.json')
    except FileNotFoundError:
        logging.debug("Tunnel Config not found")
    else:
        info_items["controller_ip"] = controller_ip

    try:
        controller_ip = extract_router_controller_ip('/opt/netfoundry/ziti/ziti-router/config.yml')
    except FileNotFoundError:
        logging.debug("Router Config not found")
    else:
        info_items["controller_ip"] = controller_ip

    try:
        controller_advertise_value = extract_controller_info('/opt/netfoundry/ziti/ziti-controller/conf/controller01.config.yml')
        if ip_check(controller_advertise_value):
            info_items["controller_dns"] = controller_advertise_value
        else:
            info_items["controller_ip"] = controller_advertise_value
    except FileNotFoundError:
        logging.debug("Controller Conf not found")

    info_file_path = os.path.join(tmp_dir, "info_file.json")
    with open(info_file_path, "w") as file:
        json_data = json.dumps(info_items)
        file.write(json_data)

    return [info_file_path], info_items.get("node_type")

def create_dump_file(tmp_dir, process_name, dump_type):
    """
    Create a dump file based on process_name and dump type, return a file path
    """
    logging.debug("Starting dump of %s", process_name)
    try:
        process_id = get_system_pid(process_name)
        logging.debug("Process Id for %s: %s",process_name, process_id)
    except OSError:
        print("Unable to find running process")
        return
    if process_id == 0:
        return

    agent_socket = '/tmp/gops-agent.' + str(process_id) + '.sock'
    if dump_type == 'stack':
        signal = '01'
    if dump_type == 'mem':
        signal = '02'
    if dump_type == 'heap':
        signal = '05'
    if dump_type == 'cpu':
        signal = '06'

    file_path = (tmp_dir +
                "/" +
                process_name +
                "-" +
                dump_type +
                "-" +
                time.strftime("%Y-%m-%d-%H%M%S") +
                ".dump")
    logging.debug("Dumping to file: %s", file_path)
    try:
        if dump_type in ["heap", "cpu"]:
            file =  open(file_path,'wb')
        else:
            file =  open(file_path,'w')
    except OSError:
        print("Unable to create dump file")

    logging.debug("Attempting to send command to: %s", agent_socket)
    if os.path.exists(agent_socket):
        try:
            magic = ['01', '0b', '0a', '0d', '0e', '0c', '0a', '0f', '0e', '0f', '00', '00', '0d']
            sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            sock.connect(agent_socket)
            for character in magic:
                sock.send(bytes.fromhex(character))
            sock.send(bytes.fromhex(signal))
            while True:
                data = sock.recv(512)
                if len(data) < 1:
                    file.close()
                    break
                if dump_type in ["heap", "cpu"]:
                    file.write(data)
                else:
                    file.write(data.decode())
        except socket.error:
            print("Unable to attach to process socket" )
    else:
        logging.debug("Unable to find socket: %s", agent_socket)
    return str(file_path)

def exit_gracefully(tmp_dir):
    """
    Exit gracefully on Keyboard Interrupt
    """
    print('\nDetected Ctrl+C..going to clean up first.')
    run_cleanup(tmp_dir)
    print('\nGood by.')
    sys.exit(0)

def extract_controller_info(config):
    """
    Get the controller info from the config
    """
    logging.debug("Trying to open yaml config")
    with open(config, "r") as file:
        try:
            yaml_content = yaml.load(file, Loader=yaml.FullLoader)
            if 'web' in yaml_content.keys():
                controller_info = yaml_content["edge"]["api"]["address"]
            else:
                controller_info = yaml_content["edge"]["api"]["advertise"]
        except yaml.YAMLError:
            logging.debug("Unable to read config format")
    logging.debug("Controller Info: %s", controller_info)
    return controller_info

def extract_minion_id(config):
    """
    Get id from yaml configuration
    """
    logging.debug("Trying to open yaml config")
    with open(config, "r") as file:
        try:
            yaml_content = yaml.load(file, Loader=yaml.FullLoader)
            minion_id = yaml_content["id"]
        except yaml.YAMLError:
            logging.debug("Unable to read config format")
    logging.debug("Found mininon id: %s", minion_id)

    return minion_id

def extract_router_controller_ip(config):
    """
    Get the controller ip from the config
    """
    logging.debug("Trying to open yaml config")
    with open(config, "r") as file:
        try:
            yaml_content = yaml.load(file, Loader=yaml.FullLoader)
            controller_info = yaml_content["ctrl"]["endpoint"]
        except yaml.YAMLError:
            logging.debug("Unable to read config format")
    controller_ip = controller_info.split(":")[1]
    logging.debug("Controller IP: %s", controller_ip)

    return controller_ip

def extract_tunnel_controller_ip(config):
    """
    Get the controller ip from the config
    """
    logging.debug("Trying to open yaml config")
    with open(config, "r") as file:
        try:
            json_content = json.loads(file.read())
            controller_info = json_content["ztAPI"]
        except json.JSONDecodeError:
            logging.debug("Unable to read config format")
    controller_ip = controller_info.split(":")[1].lstrip("/")
    logging.debug("Controller IP: %s", controller_ip)

    return controller_ip

def get_system_info(tmp_dir):
    """
    Gather all information/logs from local system and return a list of files
    """

    list_of_system_files = ['/var/log/messages',
                            '/var/log/dmesg',
                            '/var/log/lastlog',
                            '/var/log/auth.log',
                            '/etc/resolv.conf',
                            '/etc/systemd/resolved.conf']

    # run system info
    sysinfo_file = system_info(tmp_dir)
    list_of_system_files.append(sysinfo_file)

    # run system commands
    system_command_output_files = run_system_commands(tmp_dir)

    # compile a list of files to return
    list_of_system_files = list_of_system_files + system_command_output_files

    # return a list of files
    return list_of_system_files

def get_system_pid(command_argument):
    """
    Find the PID of a running process that contains the given command argument in its command line.
    """
    for proc in psutil.process_iter(['pid', 'name', 'cmdline']):
        cmdline = proc.info['cmdline']
        if cmdline and command_argument in ' '.join(cmdline):
            logging.debug("PID: %s, Name: %s", proc.info['pid'], proc.info['name'])
            return proc.info['pid']
    logging.debug("Unable to find process")
    return None

def get_ziti_dumps(tmp_dir,dump_count):
    """
    Gather ziti dump files for any all ziti processes
    """
    print("Creating ziti dump files...")
    ziti_proccess_list = ["controller", "router", "tunnel"]
    dump_files = []
    do_sleep = False
    if dump_count > 1:
        do_sleep = True
    dump_number = 0
    while dump_number < dump_count:
        dump_number += 1
        for process_name in ziti_proccess_list:
            stack_dump = create_dump_file(tmp_dir, process_name, "stack")
            if stack_dump is not None:
                dump_files.append(stack_dump)
            mem_dump = create_dump_file(tmp_dir, process_name, "mem")
            if mem_dump is not None:
                dump_files.append(mem_dump)
            heap_dump = create_dump_file(tmp_dir, process_name, "heap")
            if heap_dump is not None:
                dump_files.append(heap_dump)
            cpu_dump = create_dump_file(tmp_dir, process_name, "cpu")
            if cpu_dump is not None:
                dump_files.append(cpu_dump)
        if do_sleep:
            print("Dump: " + str(dump_number) + " complete")
            if dump_number < dump_count:
                print("Sleeping for 30sec, before creating another dump")
                time.sleep(30)
    return dump_files

def get_ziti_info(tmp_dir):
    """
    Gather all ziti information
    """
    print("Gathering ziti configuration...")

    ziti_files = []
    # gather journal for ziti-router/tunnel
    for program in ['ziti-router','ziti-tunnel','ziti-controller']:
        log_file = tmp_dir + "/" + program + ".log"
        open_file = open(log_file,'w')
        subprocess.call(["journalctl", "-u", program,
                "--since","3 days ago",
                "--no-pager"  ], stdout=open_file)
        open_file.close()
        ziti_files.append(log_file)

    other_ziti_files = ['/opt/netfoundry/ziti/ziti-router/config.yml',
                        '/etc/systemd/system/ziti-router.service',
                        '/opt/netfoundry/ziti/ziti-tunnel/config.json',
                        '/etc/systemd/system/ziti-tunnel.service',
                        '/opt/netfoundry/ziti/ziti-controller/conf/controller01.config.yml',
                        '/etc/systemd/system/ziti-controller.service',
                        '/usr/lib/systemd/resolved.conf.d/01-netfoundry.conf',
                        '/etc/salt/minion.d/nf-minion.conf'
                        ]
    for ziti_file in other_ziti_files:
        try:
            shutil.copy(ziti_file,tmp_dir)
        except FileNotFoundError:
            logging.debug("didn't find %s", ziti_file)


    return ziti_files + other_ziti_files

def ip_check(value):
    """
    Check if the value is an ip address, if not assume it's a name
    """
    if re.match(r"^(25[0-5]|2[0-4][0-9]|[0-1]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[0-1]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[0-1]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[0-1]?[0-9][0-9]?)$", value):
        return True
    return False

def prompt_for_email():
    """
    Promp user for email addresss
    """
    while True:
        try:
            email_address = input("Please enter your email address:\n")
            regex = r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'
            if re.match(regex, email_address):
                return email_address
            print("ERROR: That doesn't seem to be an email address, please Try again")
            continue
        except ValueError:
            print("ERROR: That doesn't seem to be an email address, please Try again")
            continue

def prompt_ticket_number():
    """
    Prompt user for ticket number
    """
    while True:
        try:
            ticket_number = int(input("Please enter ticket number:\n"))
        except ValueError:
            print("ERROR: That's not a number, please Try again")
            continue
        else:
            return str(ticket_number)

def run_cleanup(path):
    """
    Cleanup all files
    """
    print("Cleaning up...")
    try:
        logging.debug("Removing: %s", path)
        shutil.rmtree(path)
    except FileNotFoundError:
        print("no files to clean")

def root_check():
    """
    Check to see if this is running as root
    """
    if os.geteuid() >= 1:
        print("Error: This script must be run with root privileges, please use sudo or run as root")
        sys.exit(1)

def run_system_commands(output_dir):
    """
    Run a system command & output the file results into a file
    """
    command_list = ["ifconfig",
                    "uptime",
                    ["resolvectl", "status", "--no-pager"],
                    ["top", "-b", "-n", "1"],
                    ["ip", "link"],
                    ["ip", "route"],
                    ["ip", "route", "show", "table", "local"],
                    ["iptables", "-L"],
                    ["iptables", "-L", "-t", "mangle"],
                    ["systemctl", "status", "ziti-router"],
                    ["systemctl", "status", "ziti-tunnel"],
                    ["systemctl", "status", "ziti-controller"],
                    ["systemctl", "status","salt-minion"],
                    ["systemctl", "status","ziti-router-upgrade"],
                    ["curl", "https://localhost/version", "--insecure"],
                    ["curl", "https://localhost/health-checks", "--insecure"]
                    ]

    output_file_list = []
    for command in command_list:
        if isinstance(command,list):
            primary_command = command[0]
        else:
            primary_command = command

        output_file = output_dir + "/" + primary_command + ".log"
        if shutil.which(primary_command):
            with open(output_file, "a+") as open_file:
                open_file.write("="*80 + "\n")
                open_file.write("CommandRun:" + str(command) + "\n")
                subprocess.call(command, stdout=open_file, stderr=open_file)
                open_file.write("\n"*5)
            if output_file not in output_file_list:
                output_file_list.append(output_file)
        else:
            logging.debug("Command not found: %s", primary_command)
    return output_file_list

def system_info(base_path):
    """
    Gather local system information
    """
    print("Gathering system information...")

    sysinfo_tmp_file = base_path + "/netfoundry_sysinfo.txt"
    # Open a file to print this information
    sysinfo_file = open(sysinfo_tmp_file, 'w')

    # uname information
    try:
        uname = platform.uname()
        sysinfo_file.write("="*40 + "System Information" + "="*31 + '\n')
        sysinfo_file.write("System: " + uname.system)
        sysinfo_file.write("Node Name: " + uname.node + "\n")
        sysinfo_file.write("Release: " + uname.release + "\n")
        sysinfo_file.write("Version: " + uname.version + "\n")
        sysinfo_file.write("Machine: " + uname.machine + "\n")
        sysinfo_file.write("Processor: " + uname.processor + "\n")
    except OSError:
        print("Unable to find uname")

    # Boot Time
    try:
        boot_time_timestamp = psutil.boot_time()
        b_time = datetime.fromtimestamp(boot_time_timestamp)
        sysinfo_file.write("="*40 + "Boot Time" + "="*40 + '\n')
        sysinfo_file.write("Boot Time: " +
                           str(b_time.year) + "/" +
                           str(b_time.month) + "/" +
                           str(b_time.day) + " " +
                           str(b_time.hour) + ":"  +
                           str(b_time.minute) + ":"  +
                           str(b_time.second) + "\n")
    except OSError:
        print("unable to find boot time")

    # let's print CPU information
    sysinfo_file.write("="*40 + "CPU Info" + "="*41 + '\n')
    # number of cores
    sysinfo_file.write("Physical cores: " + str(psutil.cpu_count(logical=False)) + "\n")
    sysinfo_file.write("Total cores: " + str(psutil.cpu_count(logical=True)) + "\n")
    # CPU frequencies
    # CPU usage
    sysinfo_file.write("CPU Usage Per Core:\n")
    for i, percentage in enumerate(psutil.cpu_percent(percpu=True, interval=1)):
        sysinfo_file.write("Core" +  str(i) + ":" + str(percentage) + "%\n")
    sysinfo_file.write("Total CPU Usage: " + str(psutil.cpu_percent()) + "%\n")

    # Memory Information
    sysinfo_file.write("="*40 + "Memory Information" + "="*31 + '\n')
    # get the memory details
    svmem = psutil.virtual_memory()
    sysinfo_file.write("Total: " + bytes2human(svmem.total) + "\n")
    sysinfo_file.write("Available: " + bytes2human(svmem.available) + "\n")
    sysinfo_file.write("Used: " + bytes2human(svmem.used) + "\n")
    sysinfo_file.write("Percentage: " + str(svmem.percent) + "%\n")

    # Disk Information
    sysinfo_file.write("="*40 + "Disk Information" + "="*33 + '\n')
    sysinfo_file.write("Partitions and Usage:\n")
    # get all disk partitions
    partitions = psutil.disk_partitions()
    for partition in partitions:
        if not re.search('/snap', partition.mountpoint):
            sysinfo_file.write("=== Device: " + partition.device + "===\n")
            sysinfo_file.write("  Mountpoint: " + partition.mountpoint + "\n")
            sysinfo_file.write("  File system type: " + partition.fstype + "\n")
            try:
                partition_usage = psutil.disk_usage(partition.mountpoint)
            except PermissionError:
            # this can be catched due to the disk that
            # isn't ready
                continue
            sysinfo_file.write("  Total Size: " + bytes2human(partition_usage.total) + "\n")
            sysinfo_file.write("  Used: " + bytes2human(partition_usage.used) + "\n")
            sysinfo_file.write("  Free: " + bytes2human(partition_usage.free) + "\n")
            sysinfo_file.write("  Percentage: " + str(partition_usage.percent) + "%\n")

    # Network information
    sysinfo_file.write("="*40 + "Network Information" + "="*30 + '\n')
    # get all network interfaces (virtual and physical)
    if_addrs = psutil.net_if_addrs()
    for interface_name, interface_addresses in if_addrs.items():
        for address in interface_addresses:
            sysinfo_file.write("=== Interface: " + interface_name + "===\n")
            if str(address.family) == 'AddressFamily.AF_INET':
                sysinfo_file.write("  IP Address: " + address.address + "\n")
                sysinfo_file.write("  Netmask: " + address.netmask + "\n")
                #sysinfo_file.write("  Broadcast IP: " + address.broadcast + "\n")
            elif str(address.family) == 'AddressFamily.AF_PACKET':
                sysinfo_file.write("  MAC Address: " + address.address + "\n")
                #sysinfo_file.write("  Netmask: " + address.netmask + "\n")
                #sysinfo_file.write("  Broadcast MAC: " + address.broadcast + "\n")
    # get IO statistics since boot
    net_io = psutil.net_io_counters()
    sysinfo_file.write("Total Bytes Sent: " + bytes2human(net_io.bytes_sent) + "\n")
    sysinfo_file.write("Total Bytes Received: " + bytes2human(net_io.bytes_recv) + "\n")
    sysinfo_file.close()
    return sysinfo_tmp_file

def upload_zip(aws_object_path, file_name):
    """
    Upload zip file to s3
    """
    print("Starting Upload to: https://nf-vm-support-bundle.s3.amazonaws.com/...")

    bucket_name = os.environ['AWS_BUCKET_NAME']
    aws_access_key_id = os.environ['AWS_ACCESS_KEY_ID']
    aws_secret_access_key = os.environ['AWS_SECRET_ACCESS_KEY']
    base_name_of_file = os.path.basename(file_name)
    aws_object = aws_object_path + "/" + base_name_of_file

    try:
        # Upload the file
        s3_client = boto3.client('s3', 'us-east-1',
                                aws_access_key_id=aws_access_key_id,
                             aws_secret_access_key=aws_secret_access_key)

        s3_client.upload_file(file_name, bucket_name, aws_object)
        print("Sucessfully uploaded file")
    except FileNotFoundError:
        print("The file was not found")
        return False
    except botocore.exceptions.NoCredentialsError:
        print("Credentials not available")
        return False
    except botocore.exceptions.ClientError:
        print("Timed out trying to upload")
        return False

    return True

def query_yes_no(question, default="yes"):
    """This function handles the yes/no questions"""
    valid = {"yes": True, "y": True,
             "no": False, "n": False}
    if default is None:
        prompt = " [y/n] "
    elif default == "yes":
        prompt = " [Y/n] "
    elif default == "no":
        prompt = " [y/N] "
    else:
        raise ValueError("invalid default answer: '%s'" % default)

    while True:
        sys.stdout.write(question + prompt)
        choice = input().lower()
        if default is not None and choice == '':
            return valid[default]
        if choice in valid:
            return valid[choice]
        sys.stdout.write("Please respond with 'yes' or 'no' "
                         "(or 'y' or 'n').\n")

def zip_files(temp_dir, ticket_number, node_type,file_list):
    """
    Create a zip file with all support info
    """
    print("Creating Zip File...")
    logging.debug("File list: %s", file_list)

    # get current date
    current_date_time = time.strftime("%Y-%m-%d-%H%M%S")

    # build zip file name
    zip_file_name = (temp_dir +
                    "/" +
                    ticket_number +
                    "_" +
                    node_type +
                    "_" +
                    current_date_time +
                    ".zip")

    # zip up all files
    with zipfile.ZipFile(zip_file_name, 'w', zipfile.ZIP_DEFLATED) as myzip:
        for file in file_list:
            try:
                myzip.write(file)
            except FileNotFoundError:
                logging.debug("file was not found %s", file)
            except KeyboardInterrupt:
                exit_gracefully(temp_dir)

    return zip_file_name

def main():
    """
    Main logic
    """

    # enable debug if requested
    if args.debug:
        log_level = logging.DEBUG
    else:
        log_level = logging.INFO

    # define logging information
    logging.basicConfig(format='%(asctime)s-%(levelname)s-%(message)s',
                        datefmt='%Y-%m-%d-%H:%M:%S',
                        level=log_level
                        )


    print("Starting Support Bundle Creation")

    # prompt for info if one was not provided
    if not args.ticket_number:
        ticket_number = prompt_ticket_number()
    else:
        try:
            if int(args.ticket_number):
                ticket_number = args.ticket_number
        except ValueError:
            print("ERROR: That's not a number, please Try again")
            sys.exit(1)

    # prompt for email address if one was not provided
    if not args.email_address:
        email_address = prompt_for_email()
    else:
        email_address = args.email_address

    # create a info file
    info_file_path, node_type = create_info_file(tmp_dir_path, email_address)

    # get system info
    system_files = get_system_info(tmp_dir_path)

    # get ziti info
    ziti_files = get_ziti_info(tmp_dir_path)

    ziti_dump_files = get_ziti_dumps(tmp_dir_path,args.dump_count)

    # zip all files
    zip_file_name = zip_files(tmp_dir_path,
                              ticket_number,
                              node_type,
                              system_files + ziti_files + info_file_path + ziti_dump_files)

    # prompt for upload
    if not args.upload:
        upload = query_yes_no("Would you like to upload this?")
    else:
        upload = True

    # upload files to s3 or just place vile
    if upload:
        upload_zip(ticket_number, zip_file_name)
    else:
        if "SUDO_USER" in os.environ:
            username = os.environ['SUDO_USER']
        else:
            username = ""
        home = os.path.expanduser("~" + username)
        new_file = shutil.move(zip_file_name, home)
        print("Output file: " + str(new_file))

    # cleanup
    run_cleanup(tmp_dir_path)

    print("Complete")

# main
if __name__ == '__main__':
    try:
        __version__ = '1.2.0'
        # change log
        # 1.0.0 - initial release
        # 1.1.0 - add cpu dump
        # 1.2.0 - change process lookup; clean up info file function

        # argument parser
        parser = argparse.ArgumentParser()
        # arguments
        parser.add_argument('-t', '--ticket_number',
                            help='support ticket number')
        parser.add_argument('-e', '--email_address',
                            help='email address')
        parser.add_argument('-n','--dump_count',
                            help='number of times to perform dumps',
                            default=1, type=int)
        parser.add_argument('-u', '--upload',
                            action='store_true',
                            help='auto upload')
        parser.add_argument('-d', '--debug',
                            action='store_true',
                            help='enable debug log in log file output')
        parser.add_argument('-v', '--version',
                            action='version',
                            version=__version__)

        # get arguments passed
        args = parser.parse_args()

        # root check
        root_check()

        # create temp dir to gather all logs
        tmp_dir_path = tempfile.mkdtemp(prefix="/root/")
        main()
    except KeyboardInterrupt:
        exit_gracefully(tmp_dir_path)
