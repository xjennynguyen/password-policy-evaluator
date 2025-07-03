import time
import os
from password_strength import PasswordPolicy
from Crypto.Hash import SHA256, MD5

# The above are the libraries I utilized
# Example: The os module will interact with the operating system
# The time module will measure the time it takes to perform our operations
# The SHA256, MD5 are hash functions
# The password strength package will help us with the password strength rules

# this is the basic password policy (first policy)
policy_basic = PasswordPolicy.from_names(
    length=8,  # there is minimum length of 8 characters
    uppercase=1, # at least 1 uppercase letter
    numbers=1,  # at least 1 digit
    special=1,  # at least 1 special character
)
# this is a 10 character policy (second policy)
policy_10_characters = PasswordPolicy.from_names(
    length=10,  # min of 10 characters
    uppercase=1,  # at least 1 uppercase letter
    numbers=1,  # at least 1 digit
    special=1,  # at least 1 special character
)

#custom policy: checking for common names and sequences
#define a custom policy class to track results separately
class CustomPolicy:
    def test(self, password):
        return contains_personal_info(password) or contains_common_sequences(password)
    # Below we will have two lists demonstrating the common names and sequences

#intializing the custom password policy
policy_custom = CustomPolicy()

# here is a list of common names --> there are more but we are doing a subset of it (for custom policy)
common_names = ["John", "Jane", "Michael", "Sarah", "David", "Emily",
                "Stephen", "James", "Matthew", "Ashley", "Chris", "Jessica", "James", "Amanda", "Jenny", "Jordan",
                "Julian","Jason", "Andrew", "Maya", "Stephen", "Claire", "Julia", "Bella", "Isabella", "Jennifer"
               , "Ethan", "Sam", "Robert", "Christina", "Brittany", "Kevin", "Richard", "Joseph", "Mary", "Susan", "Lisa", "Emily", "Karen"
               , "Juan", "Luis", "Patricia"]

# Function to check if the password contains personal information
def contains_personal_info(password):
    for name in common_names:
        if name.lower() in password.lower():  #case insensitive check
            return True
    return False


#another list of common password sequences (for custom policy)
def contains_common_sequences(password):
    common_sequences = ['1234', 'abcd', 'qwerty', '123456', '54321', 'abc', '12345678', "qwerty123", "000000",
                        "111111", "password", "admin", "dragon", "monkey", "iloveyou", "welcome", "asdfgh", "zxcvbn",
                        "qwertyuiop", "222333", "welcome1", "master", "sunshine", "login123", "pokemon", "ninja",
                        "pokemon123"
                        ]
    for sequence in common_sequences:
        if sequence in password:
            return True
    return False

# function to generate a 16 byte salt
def generate_salt():
    return os.urandom(16)  # 16-byte salt

#these are the files to test
files_to_test = ['rockyou.txt']
#when testing you need to change. For example, to change to custom_password you simply put "custom_password"
# we have to files to test from dataset I VS dataset II

# counters and lists
weak_passwords = 0
strong_passwords = 0
salted_hashing_times_sha256 = []
salted_hashing_times_md5 = []
salted_hashing_times_salted_sha256 = []

#policy counters this will track each policy separately
policy_basic_pass = 0
policy_basic_fail = 0
policy_10_char_pass = 0
policy_10_char_fail = 0
policy_custom_pass = 0  #contains personal info or common sequences
policy_custom_fail = 0
total_passwords = 0

# process passwords from both files
for file_name in files_to_test:
    with open(file_name, 'r', encoding='utf-8') as file:
        with open(f'{file_name}_hashes.txt', 'w') as hash_file:
            for line in file:
                password = line.strip()
                if not password:
                    continue  #skip empty lines

                total_passwords += 1

                #tracking the source of the password (file name)
                source = file_name

                #test password strength based on policy 1
                if not policy_basic.test(password):
                    policy_basic_pass += 1
                else:
                    policy_basic_fail += 1

                #test password strength based on policy 2
                if not policy_10_characters.test(password):
                    policy_10_char_pass += 1
                else:
                    policy_10_char_fail += 1

                #test password against custom policy #3
                if not policy_custom.test(password):
                    policy_custom_pass += 1
                else:
                    policy_custom_fail += 1
                    #print details about why a password failed custom policy
                    if contains_personal_info(password):
                        print(f"  - Password contains personal information: {password}")
                    if contains_common_sequences(password):
                        print(f"  - Password contains common sequence: {password}")

                #determine if the password is weak or strong overall
                #A password is considered weak if it fails ANY policy
                if policy_basic.test(password) or policy_10_characters.test(password) or policy_custom.test(password):
                    weak_passwords += 1
                else:
                    strong_passwords += 1

                #MD5 Hashing (without salt) with multiple iterations to slow down
                start_time = time.perf_counter()
                for _ in range(10000):  # ran 10,000 to "exagerrate" the hash --> this made it easier to visualize the results
                    md5_hash_obj = MD5.new(data=password.encode())
                md5_hash_time = time.perf_counter() - start_time
                salted_hashing_times_md5.append(md5_hash_time)
                md5_hash = md5_hash_obj.hexdigest()

                #save the MD5 hash and source to the file
                hash_file.write(f"{md5_hash},{source}_md5\n")  # save MD5 hash
                print(f"MD5 Hashing time for '{password}': {md5_hash_time:.5f} seconds")

                # SHA-256 Hashing (without salt) with multiple iterations to slow down
                start_time = time.perf_counter()
                for _ in range(10000):  # ran 10,000 to "exagerrate" the hash
                    sha256_hash_obj = SHA256.new(data=password.encode())
                sha256_hash_time = time.perf_counter() - start_time
                salted_hashing_times_sha256.append(sha256_hash_time)
                sha256_hash = sha256_hash_obj.hexdigest()

                #save the SHA-256 hash and source to the file
                hash_file.write(f"{sha256_hash},{source}_sha256\n")  # save SHA-256 hash
                print(f"SHA-256 Hashing time for '{password}': {sha256_hash_time:.5f} seconds")

                #salted SHA-256 Hashing with multiple iterations to slow down
                salt = generate_salt()
                password_with_salt = password.encode() + salt

                start_time = time.perf_counter()
                for _ in range(10000):  #ran 10,000 to "exagerrate" the hash
                    salted_sha256_hash_obj = SHA256.new(data=password_with_salt)
                salted_sha256_hash_time = time.perf_counter() - start_time
                salted_hashing_times_salted_sha256.append(salted_sha256_hash_time)

                #save the Salted SHA-256 hash and source to the file
                salted_sha256_hash = salted_sha256_hash_obj.hexdigest()
                hash_file.write(f"{salted_sha256_hash},{source}_salted_sha256\n")  #save Salted SHA-256 hash
                print(f"Salted SHA-256 Hashing time for '{password}': {salted_sha256_hash_time:.5f} seconds")

#output the total counts and average times
print(f"\nTotal Weak passwords: {weak_passwords}")
print(f"Total Strong passwords: {strong_passwords}")
print(f"Average MD5 hashing time: {sum(salted_hashing_times_md5) / len(salted_hashing_times_md5):.5f} seconds")
print(
    f"Average SHA-256 hashing time: {sum(salted_hashing_times_sha256) / len(salted_hashing_times_sha256):.5f} seconds")
print(
    f"Average Salted SHA-256 hashing time: {sum(salted_hashing_times_salted_sha256) / len(salted_hashing_times_salted_sha256):.5f} seconds")
#The first outputs the averages of all hashing times
#new detailed policy analysis --> gives you more in depth of percentages of passwords passing each policy
print("\n Password Policy Analysis")
print(f"Total passwords analyzed: {total_passwords}") #this demonstrates how many unique passwords there are (technically how many are in the dataset)

#policy 1: Basic (8 char min, 1 uppercase, 1 number, 1 special)
basic_pass_percent = (policy_basic_pass / total_passwords * 100) if total_passwords > 0 else 0
print(f"\nPolicy 1 (Basic - 8 chars, uppercase, number, special char):")
print(f"  Passed: {policy_basic_pass} ({basic_pass_percent:.2f}%)")
print(f"  Failed: {policy_basic_fail} ({100 - basic_pass_percent:.2f}%)")

#policy 2: 10 Character Policy
ten_char_pass_percent = (policy_10_char_pass / total_passwords * 100) if total_passwords > 0 else 0
print(f"\nPolicy 2 (10+ chars, uppercase, number, special char):")
print(f"  Passed: {policy_10_char_pass} ({ten_char_pass_percent:.2f}%)")
print(f"  Failed: {policy_10_char_fail} ({100 - ten_char_pass_percent:.2f}%)")

#policy 3: Custom Policy (no common names/sequences)
custom_pass_percent = (policy_custom_pass / total_passwords * 100) if total_passwords > 0 else 0
print(f"\nPolicy 3 (Custom - No common names or sequences):")
print(f"  Passed: {policy_custom_pass} ({custom_pass_percent:.2f}%)")
print(f"  Failed: {policy_custom_fail} ({100 - custom_pass_percent:.2f}%)")