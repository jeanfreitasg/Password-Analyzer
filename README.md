# Password-Analyzer
Analyzes a passwword to determine its strength

- Heuristic check:</br>
  - Min 10 characters;</br>
  - Does not contain sequences - QWERT 123 ABC, mininum of 3 chars;</br>
  - Have at least 1 uppercase, 1 lowercase, 1 digit and special character;</br>
  - Does not contain the same character in sequence, 3 or more - 111 AAA ===</br>
- Entropy Calculation</br>
- Endures to a Dictionary Attack</br>
- Isn't a word, verify using the ['Language Detection API'](https://detectlanguage.com/languages)

Usage Example:
```python
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
```
