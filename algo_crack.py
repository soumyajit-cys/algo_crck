import argparse
import hashlib
import os
import sys
import time
from colorama import init, Fore

# Initialize colorama for colored console output
init(autoreset=True)

# Supported hash algorithms
HASH_ALGORITHMS = {
    'md5': {
        'length': 32,
        'function': lambda p: hashlib.md5(p.encode('utf-8')).hexdigest()
    },
    'sha1': {
        'length': 40,
        'function': lambda p: hashlib.sha1(p.encode('utf-8')).hexdigest()
    },
    'sha256': {
        'length': 64,
        'function': lambda p: hashlib.sha256(p.encode('utf-8')).hexdigest()
    },
    'sha512': {
        'length': 128,
        'function': lambda p: hashlib.sha512(p.encode('utf-8')).hexdigest()
    },
    'ntlm': {
        'length': 32,
        'function': lambda p: hashlib.new('md4', p.encode('utf-16le')).hexdigest()
    }
}

def validate_hash(hash_str):
    """Check if hash has valid hexadecimal format."""
    try:
        int(hash_str, 16)
        return True
    except ValueError:
        return False

def validate_wordlist_path(wordlist_path):
    """Validate wordlist path and permissions."""
    if not os.path.exists(wordlist_path):
        print(Fore.RED + f"Error: Wordlist file not found at '{wordlist_path}'")
        return False
    
    if os.path.isdir(wordlist_path):
        print(Fore.RED + f"Error: The path '{wordlist_path}' is a directory, not a file")
        
        # List text files in the directory to help user
        print(Fore.YELLOW + "Text files in this directory:")
        try:
            files = os.listdir(wordlist_path)
            text_files = [f for f in files if f.endswith(('.txt', '.lst', '.wordlist'))]
            for file in text_files[:5]:  # Show first 5 files
                print(Fore.CYAN + f"  - {file}")
            if len(text_files) > 5:
                print(Fore.CYAN + f"  ... and {len(text_files) - 5} more")
        except:
            print(Fore.RED + "  Cannot list directory contents")
        
        return False
    
    try:
        # Try to open the file to check permissions
        with open(wordlist_path, 'r', encoding='utf-8', errors='ignore') as test_file:
            test_file.readline()
        return True
    except PermissionError:
        print(Fore.RED + f"Error: Permission denied to read '{wordlist_path}'")
        print(Fore.YELLOW + "Try running the script as administrator or check file permissions")
        return False
    except Exception as e:
        print(Fore.RED + f"Error: Cannot read file '{wordlist_path}': {str(e)}")
        return False

def crack_password(target_hash, wordlist_path, algorithm=None):
    target_hash = target_hash.strip().lower()
    
    # Validate hash format
    if not validate_hash(target_hash):
        print(Fore.RED + "Error: Invalid hash format. Must be hexadecimal.")
        return None
    
    # Validate wordlist path and permissions
    if not validate_wordlist_path(wordlist_path):
        return None
    
    # Detect algorithm if not specified
    if algorithm is None:
        possible_algos = []
        hash_length = len(target_hash)
        for algo, props in HASH_ALGORITHMS.items():
            if props['length'] == hash_length:
                possible_algos.append(algo)
        
        if not possible_algos:
            print(Fore.YELLOW + f"Warning: Hash length ({hash_length}) doesn't match known algorithms.")
            print(Fore.CYAN + "Supported algorithms: " + ", ".join(HASH_ALGORITHMS.keys()))
            return None
    else:
        algorithm = algorithm.lower()
        if algorithm not in HASH_ALGORITHMS:
            print(Fore.RED + f"Error: Unsupported algorithm '{algorithm}'.")
            print(Fore.CYAN + "Supported algorithms: " + ", ".join(HASH_ALGORITHMS.keys()))
            return None
        if HASH_ALGORITHMS[algorithm]['length'] != len(target_hash):
            print(Fore.YELLOW + f"Warning: Hash length doesn't match typical {algorithm.upper()} length.")
        possible_algos = [algorithm]

    # Process wordlist
    try:
        start_time = time.time()
        count = 0  # Initialize count here to avoid reference errors
        file_size = os.path.getsize(wordlist_path)
        print(Fore.CYAN + f"\nStarting cracking process...")
        print(Fore.CYAN + f"Wordlist size: {file_size/1048576:.2f} MB")
        print(Fore.CYAN + f"Target hash: {target_hash}")
        print(Fore.CYAN + f"Testing algorithms: {', '.join(possible_algos)}\n")
        
        with open(wordlist_path, 'r', encoding='utf-8', errors='ignore') as file:
            for count, password in enumerate(file, 1):
                password = password.strip()
                for algo in possible_algos:
                    hash_func = HASH_ALGORITHMS[algo]['function']
                    try:
                        if hash_func(password) == target_hash:
                            return (password, count, time.time() - start_time)
                    except UnicodeEncodeError:
                        continue
                
                # Progress updates
                if count % 250000 == 0:
                    elapsed = time.time() - start_time
                    rate = count / elapsed if elapsed > 0 else 0
                    print(Fore.MAGENTA + f"Checked {count:,} passwords ({rate:,.0f} p/sec)", end='\r')
        
        elapsed = time.time() - start_time
        return (None, count, elapsed)
        
    except Exception as e:
        print(Fore.RED + f"\nError during processing: {str(e)}")
        # Return a tuple with count=0 since we didn't process any passwords
        elapsed = time.time() - start_time if 'start_time' in locals() else 0
        return (None, 0, elapsed)

def main():
    print(Fore.GREEN + r"""
   ___                  __  ___          __            
  / _ \___  ___ ___ _  /  |/  /__  ___  / /_____ ____ _
 / // / _ \/ -_) _ `/ / /|_/ / _ \/ _ \/  '_/ -_) __ `/
/____/_//_/\__/\_, / /_/  /_/\___/\___/_/\_\\__/_/ /_/ 
               /___/                                    
    """)
    
    parser = argparse.ArgumentParser(description='Hashed Password Cracker for Windows/VSCode')
    parser.add_argument('hash', nargs='?', help='Target hash to crack')
    parser.add_argument('wordlist', nargs='?', help='Path to password wordlist file')
    parser.add_argument('--algorithm', '-a', help='Specify hash algorithm (md5, sha1, sha256, sha512, ntlm)')
    
    args = parser.parse_args()
    
    # Interactive mode if arguments not provided
    if not args.hash or not args.wordlist:
        print(Fore.CYAN + "\nInteractive Mode (Ctrl+C to exit)")
        try:
            args.hash = input("Enter target hash: ").strip()
            
            # Get wordlist path with validation
            while True:
                wordlist_path = input("Enter wordlist path: ").strip()
                if wordlist_path.startswith('~'):
                    wordlist_path = os.path.expanduser(wordlist_path)
                
                if validate_wordlist_path(wordlist_path):
                    args.wordlist = wordlist_path
                    break
                else:
                    print(Fore.YELLOW + "Please enter a valid file path.")
            
            algo_input = input("Algorithm (optional, press Enter to auto-detect): ").strip()
            args.algorithm = algo_input if algo_input else None
        except KeyboardInterrupt:
            print(Fore.YELLOW + "\nOperation cancelled by user")
            sys.exit(0)
    
    # Run cracking process
    result = crack_password(args.hash, args.wordlist, args.algorithm)
    
    # Display results
    if result is None:
        print(Fore.RED + "\nCracking process aborted due to errors")
        return
    
    password, count, elapsed = result
    
    if password:
        print(Fore.GREEN + "\n\n" + "="*50)
        print(Fore.GREEN + f"CRACK SUCCESSFUL! Password found: '{password}'")
        print(Fore.GREEN + "="*50)
        print(Fore.CYAN + f"Passwords tested: {count:,}")
        print(Fore.CYAN + f"Time elapsed: {elapsed:.2f} seconds")
        print(Fore.CYAN + f"Speed: {count/elapsed:,.0f} passwords/sec" if elapsed > 0 else "Speed: N/A (instant)")
        print(Fore.GREEN + "="*50)
    else:
        print(Fore.RED + "\n\n" + "="*50)
        print(Fore.RED + "PASSWORD NOT FOUND")
        print(Fore.RED + "="*50)
        print(Fore.CYAN + f"Passwords tested: {count:,}")
        print(Fore.CYAN + f"Time elapsed: {elapsed:.2f} seconds")
        print(Fore.CYAN + f"Speed: {count/elapsed:,.0f} passwords/sec" if elapsed > 0 else "Speed: N/A (instant)")
        print(Fore.YELLOW + "\nTry a different wordlist or check hash/algorithm")
        print(Fore.RED + "="*50)

if __name__ == '__main__':
    main()