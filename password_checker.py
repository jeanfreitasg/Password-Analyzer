from password_analyzer import PasswordAnalyzer
from termcolor import colored
import getpass

_pass = getpass.getpass()
analyses = PasswordAnalyzer(_pass)

for k, v in analyses.heuristic_errors.items():
    print("{}: {}".format(k, colored("Approved", "green")
                          if not v else colored("Failed", "red")))

print("Entropy: {0:.2f}".format(analyses.entropy))
print("Endures dictionary attack: {}".format(not analyses.dictionary_attack()))
print("It's a single word: {}".format(analyses.is_word))
