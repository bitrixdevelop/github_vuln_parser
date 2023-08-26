""" Main file to run the program. """
from classes.Parser import Parser

if __name__ == "__main__":
    Parser(
        "https://github.com/advisories?query=type%3Areviewed+ecosystem%3Ago"
    ).convert_json_to_csv()
