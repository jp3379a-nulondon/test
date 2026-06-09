import ipaddress # Importing IP address module

def validate_ip(ip_address):
    try:
        # Checks if the input is a valid IPv4 or IPv6 address
        ipaddress.ip_address(ip_address)
        return True
    except ValueError:
        return False


user_ip = input("Enter an IP address: ")

if validate_ip(user_ip):
    print(f"Valid IP address entered: {user_ip}")
else:
    print("Invalid IP address. Please enter a correctly formatted IP address.")
    
    # Test 3