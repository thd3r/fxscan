#!/usr/bin/env python3

import os
import sys
import time
import argparse
from concurrent.futures import ThreadPoolExecutor

# External library
from selenium import webdriver
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
from selenium.common.exceptions import TimeoutException, NoAlertPresentException, UnexpectedAlertPresentException

class Fxss:

    def __init__(self, args):
        self.args = args

    @property
    def _target(self):
        if not self.args.input:
            return sys.stdin.read().strip().split()
        else:
            return self.args.input.split() if not os.path.isfile(self.args.input) else open(self.args.input, "r").read().strip().split()
    
    @property
    def _timeout(self):
        if self.args.timeout:
                WebDriverWait(self.driver(option_driver=self.options), self.args.timeout).until(EC.alert_is_present(), message="timeout until xss is triggered.")
        else: pass
    
    @property
    def options(self):
        if self.args.mode == "gui":
            return None
        if self.args.mode == "cli":
            options = webdriver.ChromeOptions() or webdriver.FirefoxOptions()
            options.add_argument("--headless")
            options.add_argument("--no-sandbox")
            options.add_argument("--disable-gpu")

            return options

    def driver(self, option_driver):
        if self.args.browser.lower() == "chrome":
            return webdriver.Chrome(options=option_driver)
        if self.args.browser.lower() == "firefox":
            return webdriver.Firefox(options=option_driver)
        
    def run(self):
        driver = self.driver(option_driver=self.options)
        for url in self._target:
            try:
                driver.get(url)
                self._timeout
                driver.switch_to.alert.accept()
                print("\033[32mPossible xss appears on the page:", url, "\033[0m")
                continue
            except TimeoutException:
                print("\033[31mTimeout:", url, "\033[0m")
                continue
            except NoAlertPresentException:
                if self.args.only_poc:
                    pass
                else:
                    print("\033[90mNo xss appears on the page:", url, "\033[0m")
                    continue
            except UnexpectedAlertPresentException:
                print("\033[33mAn unexpected xss appeared on the page:", url, "\033[0m")
                continue
            except Exception:
                continue
            except KeyboardInterrupt:
                time.sleep(1)
                driver.quit()
                print("")
                break

        driver.quit()

def main():
    parser = argparse.ArgumentParser(prog="fxscan", usage="%(prog)s [mode] [flags]")
    parser._optionals.title = "flags"
    parser.add_argument(
        "-v",
        "--version",
        action="version",
        version="%(prog)s v0.1"
    )

    subparser = parser.add_subparsers(title="available modes", metavar="gui,cli", dest="mode", required=True, help="list of available modes (choose gui or cli)")

    guiparser = subparser.add_parser(name="gui", prog="fxscan", help="run programs with a graphical interface", usage="%(prog)s gui [flags]")
    guiparser._optionals.title = "flags"
    guiparser.add_argument(
        "-i",
        "--input",
        action="store",
        help="the target input includes its payload"
    )
    guiparser.add_argument(
        "-c",
        "--threads",
        type=int,
        default=50,
        help="number of concurrent threads (default: 50)"
    )
    guiparser.add_argument(
        "-t",
        "--timeout",
        type=float,
        help="timeout until xss is triggered"
    )
    guiparser.add_argument(
        "-b",
        "--browser",
        type=str,
        default="chrome",        
        help="browser you want to use (default: chrome)"
    )
    guiparser.add_argument(
        "-op",
        "--only-poc",
        action="store_true",
        help="show only potentially vulnerable urls"
    )

    cliparser = subparser.add_parser(name="cli", prog="fxscan", help="run programs without a graphical interface", usage="%(prog)s cli [flags]")
    cliparser._optionals.title = "flags"
    cliparser.add_argument(
        "-i",
        "--input",
        action="store",
        help="the target input includes its payload"
    )
    cliparser.add_argument(
        "-c",
        "--threads",
        type=int,
        default=50,
        help="number of concurrent threads (default: 50)"
    )
    cliparser.add_argument(
        "-t",
        "--timeout",
        type=float,
        help="timeout until xss is triggered"
    )
    cliparser.add_argument(
        "-b",
        "--browser",
        type=str,
        default="chrome",        
        help="browser you want to use (default: chrome)"
    )
    cliparser.add_argument(
        "-op",
        "--only-poc",
        action="store_true",
        help="show only potentially vulnerable urls"
    )

    print(open("static/fxscan_banner.txt", "r").read())
    args = parser.parse_args()

    fxss = Fxss(args=args)
    
    with ThreadPoolExecutor(max_workers=args.threads) as executor:
        try:
            executor.submit(fxss.run())
        finally:
            executor.shutdown()

if __name__ == '__main__':
    try:
        main()
    except AttributeError:
        pass