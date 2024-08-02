from datetime import datetime
import concurrent.futures
import socket
import os
import json
import sys

#firebase
from firebase_config import *
authe, database = getFirebaseAPP()
user = authenticate_user(authe)
# firebase 1st code block ends

def addToWhitelist(new_data):
    global wl_df, wl_domains
    wl_df = wl_df._append(new_data, ignore_index=True) # Add the resolved domain to whitelist DataFrame
    wl_df.to_csv(os.path.join(script_dir_root, "whitelist.csv"), index=False)  # Save the updated whitelist to CSV
    wl_domains = wl_domains._append(pd.Series([new_data['domain']]), ignore_index=True)
    wl_df= pd.read_csv(os.path.join(script_dir_root, "whitelist.csv"),usecols=['domain'])
    wl_domains = wl_df['domain'].apply(extract_domain)


def handle_dns_request(request, client_address):
    # global user, database
    start_time = datetime.now()
    query_name = str(request.question[0].name)
    print("Query Name: ",query_name)
    query_type = request.question[0].rdtype 
    is_reverse_lookup = query_name.endswith(".in-addr.arpa.")
    is_malicious = False
    is_blacklist = False
    is_whitelist = False
    new_data = {'s': 1, 'domain': query_name, 'ip_address': '0.0.0.0'}

    if is_reverse_lookup:
        # Handle reverse DNS lookup
        print("Reverse DNS lookup request received.")
        # Extract the IP address from the reverse query name
        ip_address = query_name.split('.')[0]
        
        # Perform reverse DNS resolution to get the domain name
        try:
            domain_name = socket.gethostbyaddr(ip_address)[0]
        except socket.gaierror as e:
            print(f"Reverse DNS lookup failed: {e}")
            domain_name = None
        
        # Construct DNS response
        response = dns.message.make_response(request)
        response.question = request.question

        if domain_name:
            # If domain name is resolved, add PTR record to response
            try:
                RRset = dns.rrset.from_text(query_name, 300, dns.rdataclass.IN, dns.rdatatype.PTR, domain_name)
                response.answer.append(RRset)
            except Exception as e:
                print(f"Error adding PTR record to response: {e}")
        else:
            # If reverse DNS lookup failed, respond with NXDOMAIN
             print("Reverse DNS lookup failed or no PTR record found.")
             response.set_rcode(dns.rcode.NXDOMAIN)
    else:
        received_domain = extract_domain(query_name)
        received_domain =  received_domain[:-1] 
        received_domain = extract_domain(query_name)
        response = dns.message.make_response(request)
        response.question = request.question
        if received_domain in wl_domains.values:
            print(f"The domain {received_domain} is whitelisted. Proceed with DNS resolution.")
            is_whitelist = True
            # Resolve DNS
            response = handle_dns_record_type(response, query_name)
            try:
                temp_ip = "".join([i for i in str(response.answer[0]).split(" ")][4:])
            except IndexError:
                temp_ip = "".join([i for i in str(response.authority[0]).split(" ")][4:])
            new_data = {'s': 0, 'domain': query_name, 'ip_address': temp_ip}

        elif received_domain in bl_domains.values:
            print(f"The domain {received_domain} is present in the blacklist file.")
            print(f"Blocked {received_domain}")
            is_blacklist = True
            # Implement your response for blacklisted domains (e.g., return an error response)
            try:
                RRset = dns.rrset.from_text(query_name, 300, dns.rdataclass.IN, query_type, "0.0.0.0")
                response.answer.append(RRset)
            except:
                print("Not Resolved, dummy ip sent!")
        else:
            # Implement your DNS processing logic here
            # For demonstration, just print a success message
            print(f"The domain {received_domain} is not blacklisted. Proceed with DNS resolution.")

            # Implement code for ML model

            # Connect to the ML server's address and port
            try:
                received_t = dns_ml_model_predict(query_name)
                if(received_t[0] == 1 and received_t[1] >=70):
                    # Block only if probability is greater than 70%
                    print(f"ML Model predicted malicious with probability {received_t[1]}%")
                    print(f"Blocked {query_name}")
                    # Implement code for dummy response
                    try:
                        RRset = dns.rrset.from_text(query_name, 300, dns.rdataclass.IN, query_type, "0.0.0.0")
                        response.answer.append(RRset)
                    except:
                        print("Not Resolved, dummy ip sent!")
                        is_malicious = received_t[1]
                else:          
                    response = handle_dns_record_type(response, query_name)
                    if response.answer:
                        a_response = [i for i in str(response.answer[0]).split(" ")][4:]
                        new_data = {'s': 0, 'domain': query_name, 'ip_address': a_response[0]}
                    if response.authority:
                        soa_response = [i for i in str(response.authority[0]).split(" ")][4:]
                        soa_response = " ".join(soa_response)[1:]
                        new_data = {'s': 0, 'domain': query_name, 'ip_address': soa_response}
                    
                    # Update whitelist if resolution successful
                    if(new_data['ip_address'] != "0.0.0.0"):
                        addToWhitelist(new_data)
                        
                print("...ML Detection finished.")
            except Exception as e:
                print("ML Model ran into a problem so blocking all requests.")
                print(str(e))
                RRset = dns.rrset.from_text(query_name, 300, dns.rdataclass.IN, query_type, "0.0.0.0")
                response.answer.append(RRset)
                
    # Set the query ID of the response message
    response.id = request.id
    print(f"Request of {query_name} is sent back to {client_address} at time {datetime.now()}")
    server_socket.sendto(response.to_wire(), client_address)
    
    # Calculate elapsed time
    end_time = datetime.now()
    elapsed_time = end_time - start_time
    # Insert data into Firebase
    curr_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    final_data = create_data_object(query_name, list(client_address), new_data['ip_address'], str(curr_time), is_malicious, is_blacklist, is_whitelist, str(elapsed_time))
    try:
        input_data(database, user, final_data)
        print("Data sent successfully!\n\n")
    except Exception as e:
        error_data = json.loads(e.args[1])
        print("\nData cannot be sent to server:", error_data['error'])

def handle_dns_request_parallel(request, client_address):
    with concurrent.futures.ThreadPoolExecutor() as executor:
        future = executor.submit(handle_dns_request, request, client_address)
        return_value = future.result()


def start_dns_server():
    
    while True:
        try:
            data, client_address = server_socket.recvfrom(1024)
            request = dns.message.from_wire(data)
            
            handle_dns_request_parallel(request, client_address)
        except ConnectionResetError:
            pass
        except KeyboardInterrupt:
            break

def get_host_ip():
    try:
        # Get the IP address by connecting to a remote server
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))  # Connect to Google's public DNS server
        ip_address = s.getsockname()[0]
        s.close()
        return ip_address
    except Exception as e:
        print("Error:", e)
        return None

# data reading
import pandas as pd
from ml_model_server.dns_tunnelling_model import *
from dns_resolver_server.paralleldns import *
# importing blacklist data domains
# Get the directory of the current script
script_dir_root = os.path.dirname(__file__)
# Construct the full path to the CSV file
# Read the CSV file using pandas
bl_df = pd.read_csv(os.path.join(script_dir_root, "blacklist.csv"), usecols=['domain'])
wl_df= pd.read_csv(os.path.join(script_dir_root, "whitelist.csv"),usecols=['domain'])

bl_domains = bl_df['domain'].apply(extract_domain)
wl_domains = wl_df['domain'].apply(extract_domain)

if __name__ == "__main__":
    ipv4_addresses = None
    if sys.platform == "win32":
        # Call the function to extract and print IPv4 addresses
        ipv4_addresses = get_host_ip()
        if ipv4_addresses:
            print("IPv4 addresses found in ifconfig of machine:", ipv4_addresses)
        else:
            print("No IPv4 addresses found in ifconfig output.")

    server_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    # Call the function to extract and print IPv4 addresses from ifconfig output
    server_address = (str(ipv4_addresses if ipv4_addresses else '0.0.0.0'), 53)
    server_socket.bind(server_address)

    if(user) :
        print("\nServer listening at{}:{}..\n".format(*server_address))
        start_dns_server()