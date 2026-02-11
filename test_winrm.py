import winrm

TARGET_IP = "192.168.0.154" # Check if your VM IP changed!
USERNAME = "SecOps"
PASSWORD = "PfeProject2026!"

print(f"🛡️ Connecting to {TARGET_IP} using Secure NTLM...")

try:
    # PRODUCTION CONFIGURATION:
    # 1. transport='ntlm': Encrypts authentication (Pass is never sent)
    # 2. message_encryption='auto': Encrypts the command output
    session = winrm.Session(
        f'http://{TARGET_IP}:5985/wsman', 
        auth=(USERNAME, PASSWORD),
        transport='ntlm' 
    )
    
    result = session.run_cmd('powershell -Command "hostname; Get-Date"')
    
    if result.status_code == 0:
        print("✅ SUCCESS! Connected securely.")
        print(result.std_out.decode())
    else:
        print("❌ FAILED.")
        print(result.std_err.decode())

except Exception as e:
    print(f"❌ ERROR: {e}")