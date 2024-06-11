import hashlib

def compare_hashes(password, hash):
    hashed_password = hashlib.sha1(password.encode()).hexdigest()
    return (hashed_password == hash)

def crack_sha1_hash(hash, use_salts = False):
    # open file
    password_file = open('top-10000-passwords.txt', 'r')

    # check each password
    for password in password_file:
        # strip whitespace
        password = password.strip()

        # add salts if necessary
        if (use_salts):
            # open file
            salts_file = open('known-salts.txt', 'r')

            # check each salt
            for salt in salts_file:
                # strip whitespace
                salt = salt.strip()

                # prepend and try
                prepended_password = salt + password
                if (compare_hashes(prepended_password, hash)):
                    password_file.close()
                    salts_file.close()
                    return password

                # append and try
                appended_password = password + salt
                if (compare_hashes(appended_password, hash)):
                    password_file.close()
                    salts_file.close()
                    return password

            # close file if not found for next password
            salts_file.close()

        else:
            # just test the password if not
            if (compare_hashes(password, hash)):
                password_file.close()
                return password

    # close file and return string if not found
    password_file.close()
    return "PASSWORD NOT IN DATABASE"