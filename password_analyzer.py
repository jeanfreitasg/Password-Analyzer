from string import ascii_lowercase, digits, punctuation
from detectlanguage import configuration, detect
from math import pow, log
import mmap


class PasswordAnalyzer(object):
    """Analyzes a passwword to determine its strength
    +Heuristic check:
        - Min 10 characters;
        - Does not contain sequences - QWERT 123 ABC, mininum of 3 chars;
        - Have at least 1 uppercase, 1 lowercase, 1 digit and special character
        - Does not contain the same character in sequence, 3 or more - 111 AAA ===;
    +Entropy Calculation
    +Endures to a Dictionary Attack
    +Isn't a word, verify using the 'Language Detection API',
    supported languages: https://detectlanguage.com/languages
    """

    def __init__(self, password):
        super(PasswordAnalyzer, self).__init__()
        self.password = password
        configuration.api_key = "d6ed8c76914a9809b58c2e11904fbaa3"

    def has_sequence(self):
        sequences = [
            "qwertyuiop",  # QWERT sequence [Row 1]
            "asdfghjkl",  # QWERT sequence [Row 2]
            "zxcvbnm",  # QWERT sequence [Row 3]
            ascii_lowercase,
            digits + "0"    # Adding a 0 at the end so the search finds
                            # both sequences: 012 and 890,
                            # the natural and the keyboard order
        ]

        for sequence in sequences:
            for i in range(0, len(sequence) - 2):
                if sequence[i:i + 3] in self.password.lower() or \
                        sequence[i:i + 3][::-1] in self.password.lower():
                    return True
        else:
            return False

    def has_repetition(self):
        for alphanumeric_char in ascii_lowercase + digits + punctuation:
            if (alphanumeric_char * 3) in self.password.lower():
                return True
        else:
            return False

    @property
    def heuristic_errors(self):
        errors = {
            "Length": len(self.password) < 10,
            "Uppercase": not any(char.isupper() for char in self.password),
            "Lowercase": not any(char.islower() for char in self.password),
            "Digit": not any(char.isdigit() for char in self.password),
            "Special Char": all(char.isalnum() for char in self.password),
            "Sequence": self.has_sequence(),
            "Repetition": self.has_repetition()
        }
        return errors

    @property
    def entropy(self):
        entropy = log(
            pow(
                (not self.heuristic_errors["Uppercase"]) * 27 +
                (not self.heuristic_errors["Lowercase"]) * 27 +
                (not self.heuristic_errors["Digit"]) * 10 +
                (not self.heuristic_errors["Special Char"]) * 33,
                len(self.password)
            ), 2
        )

        return entropy

    def password_mutations(self):

        leet = {
            "0": 'o',
            "1": 'l',
            "2": 'z',
            "3": 'e',
            "4": 'a',
            "5": 's',
            "6": 'b',
            "7": 't',
            "8": 'x',
            "9": 'g',
            "!": 'i',
            "@": 'a',
            "$": 's',
            "%": 'x',
            "&": 'e',
            "£": 'e',
            "₤": 'e',
            "€": 'e',
            "§": 's'
        }

        mutations = [
            self.password,
            "".join([char for char in self.password if char.isalpha()]),
            "".join([leet.get(char, char) for char in self.password])
        ]

        # Removes any special characters after translated from leet
        mutations.append(
            "".join([char for char in mutations[2] if char.isalpha()]))

        return set(mutations)

    @property
    def is_word(self):
        passwords = self.password_mutations()
        for _password in passwords:
            if detect(_password)[0]['confidence'] == 10:
                return True
        else:
            return False

    def dictionary_attack(self):
        '''
        Return True if the password was found in the dictionary
        '''
        with open("password_dictionary.txt", mode='rb') as file, \
        mmap.mmap(file.fileno(), 0, access=mmap.ACCESS_READ) as content:
            for _password in self.password_mutations():
                if content.find(str.encode(_password)) != -1:
                    return True
            else:
                return False
